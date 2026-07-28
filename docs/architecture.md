# Architecture

## Overview

UGOW sits between user applications and Windows drives mounted in WSL2, intercepting write-class VFS operations and checking them against a centralized permission store. Three enforcement backends are available, all sharing the same grant database and CLI.

```
 ┌──────────────────────────────────────────────────────────┐
 │                    User Applications                     │
 │              (Docker, scripts, editors, ...)             │
 └────────────────────────┬─────────────────────────────────┘
                          │
                    VFS operations
                          │
              ┌───────────┼───────────┐
              │           │           │
         ┌────▼───┐  ┌────▼───┐  ┌───▼────┐
         │  FUSE  │  │  BPF   │  │  kmod  │
         │  shim  │  │  LSM   │  │  LSM   │
         └────┬───┘  └────┬───┘  └───┬────┘
              │           │          │
              └───────────┼──────────┘
                          │
                   ┌──────▼──────┐
                   │  PermStore  │
                   │  (SQLite)   │
                   └──────┬──────┘
                          │
                   ┌──────▼──────┐
                   │  ugow CLI   │
                   └─────────────┘
```

## Enforcement Modes

### FUSE mode

Each drive gets its own isolated FUSE instance via a systemd template unit:

```
 /mnt/.<letter>-backing   <-- raw DrvFs, metadata,umask=077,nosuid,nodev
          |
      FUSE shim            <-- UGOWShim (permission checks, W-bit enforcement)
          |
     /mnt/<letter>          <-- what users and tools see (transparent)
```

WSL automount is disabled. UGOW takes over drive mounting, placing the raw DrvFs under a hidden root-only backing directory and presenting a permission-gated view to users.

**Trade-offs:**

- Easiest to deploy (no kernel requirements)
- Root operations are remapped to the launching user's UID -- root doesn't bypass enforcement
- Moderate performance overhead (user/kernel boundary crossed twice per VFS op)
- Bypass-resistant at the mountpoint level only
- Both mounts are `nosuid,nodev`, and the shim masks `setuid`/`setgid` out of every `chmod`, so a granted user cannot plant a privileged binary on the drive
- FUSE attribute, entry and negative-entry caching are all disabled: `getattr` answers per calling UID, and a per-inode cache would let one user's answer decide another user's permission check

### BPF mode

BPF LSM hooks enforce directly on the real DrvFs mount:

```
     /mnt/<letter>          <-- real DrvFs (WSL automount)
          |
    BPF LSM hooks           <-- ugow_file_open, ugow_inode_permission, etc.
          |
     grants map             <-- (inode, dev, uid) -> allow/deny
```

WSL automount stays enabled. BPF hooks run inline in the kernel on every relevant syscall.

**Trade-offs:**

- Near-zero performance overhead
- Cannot be bypassed from userspace -- every syscall path passes through LSM hooks
- Root (uid 0) is always exempt to prevent system lockout
- Requires stock WSL2 kernel 6.6+ with BPF LSM enabled

### kmod mode

Compiled-in LSM hooks enforce on the devices userspace has registered:

```
     /mnt/<letter>          <-- real DrvFs (WSL automount)
          |
    LSM hooks               <-- ugow_inode_permission, ugow_file_open, etc.
          |
   in-kernel hash table     <-- (device, superblock-relative path, uid) grants
                                via securityfs
```

**Trade-offs:**

- Same kernel-level enforcement as BPF mode
- Requires a custom WSL2 kernel build, and is **experimental and unverified** -- see [kmod](kmod.md)
- RCU-based hash table for lock-free reads on the hot path
- Enforcement is opt-in per device: nothing is gated until a device is registered via securityfs, so enabling the LSM cannot by itself make a filesystem read-only
- Root exemption is a build-time choice (`CONFIG_SECURITY_UGOW_ROOT_EXEMPT`, default `y`)

### Mode comparison

|  | FUSE | BPF | kmod |
|---|---|---|---|
| **Install** | `sudo ./setup.sh` | `sudo ./setup.sh --mode bpf` | Custom kernel build |
| **Where it runs** | Userspace (FUSE) | Kernel (eBPF LSM) | Kernel (compiled-in LSM) |
| **Needs custom kernel?** | No | No (stock WSL2 6.6+) | Yes (`CONFIG_SECURITY_UGOW=y`) |
| **Performance overhead** | Moderate (user/kernel bounce) | Near zero | Near zero |
| **WSL automount** | Disabled (UGOW mounts drives) | Left enabled | Left enabled |
| **Root bypasses enforcement?** | No (remapped to launching user) | Yes (uid 0 exempt) | Build-time choice: `CONFIG_SECURITY_UGOW_ROOT_EXEMPT` (default `y`) |
| **Multi-drive** | `ugow mount d` | `ugow mount d` | Per-device opt-in via securityfs `devices` |
| **Grant interface** | SQLite | SQLite + BPF map | SQLite + securityfs |

!!! warning "FUSE and BPF are mutually exclusive"
    The FUSE shim's own I/O to the backing filesystem would be blocked by BPF hooks, and BPF cannot see through the FUSE device. The installer detects conflicts and refuses to install if the other mode is active.

## Permission Store

All backends share a single SQLite database at `/var/lib/ugow/wperm.db`.

### Grant model

- Grants are `(path, uid)` pairs stored in a `wperms` table
- **Inheritance**: a grant on `/mnt/c/data` covers `/mnt/c/data/sub/file.txt` -- the permission check walks up the directory tree from the target path
- **Per-user**: each UID's grants are independent
- **Idempotent**: granting the same path twice is a no-op
- **Normalized**: paths are canonicalized before being stored or looked up, so trailing slashes and redundant separators resolve to the same grant. The ancestor walk never produces a trailing slash, so an unnormalized key would be a row that could never match

A second table, `dac_modes`, records the original Unix mode of any path whose permissions BPF mode had to widen, so `ugow deny` can restore it rather than leaving the path world-writable after the hooks stop applying.

### Caching

The permission store keeps an in-memory LRU cache of `(path, uid)` answers with a 2-second TTL, hard-bounded at 8192 entries (`_WBIT_CACHE_MAX`); the oldest entries are evicted once it is full. The cache is invalidated for a path and its descendants on `grant()` and `revoke()`.

That covers same-process invalidation only. The FUSE daemon is long-lived and holds a cache the `ugow` CLI -- a separate process -- cannot reach, so consumers that pass `watch_db=True` also run a background thread that polls SQLite's `PRAGMA data_version` every 0.5 s and clears the whole cache when it moves. `data_version` changes only on commits by *other* connections and is a header read rather than a table scan, so the watcher stays off the `has_wbit()` hot path entirely. This is why `allow` and `deny` take effect promptly without restarting the shim.

### Thread safety

SQLite connections are per-thread (stored in `threading.local()`). WAL mode is enabled for concurrent read/write access across threads.

### ACL mirroring

When enabled (`--mirror-acl`), grant and revoke operations are queued to a background worker thread that:

1. Creates a Windows local user `wsl_<UID>` if it doesn't exist, with a random password, and immediately disables it -- the account exists only as an ACL principal, nothing ever authenticates as it, and a disabled account's SID still resolves in ACLs
2. Runs `icacls` via PowerShell to apply or remove NTFS ACLs on the Windows path
3. Times out after 30 seconds per operation to prevent hangs

Grants are applied inheritably (`(OI)(CI)F`) and recursively (`/T`). Revoke uses `/remove:g` on the exact path *without* `/T`: dropping the explicit inheritable ACE also drops the inherited copies from descendants, whereas recursing would delete explicit ACEs belonging to still-valid grants on subdirectories.

Requesting `--mirror-acl` without Windows Administrator privileges raises `AclMirrorUnavailable`, which the CLI turns into an error message. The library never calls `sys.exit()` on its caller's behalf -- the FUSE daemon imports the same module and would otherwise die at startup with no explanation. Flushing pending ACL work is bounded (60 s) and returns a success flag rather than blocking forever if the worker thread has died.

ACL mirroring is best-effort -- if it fails, the SQLite grant still succeeds and the W-bit enforcement layer works independently. `ugow acl-cleanup` removes mirrored `wsl_*` accounts whose UID no longer holds any grant.

### Path conversion

Linux paths under `/mnt/<drive>/...` are translated to Windows paths (`C:\...`) for ACL mirroring commands. Only a *single alphabetic* component is treated as a drive letter, because `/mnt` also holds real WSL mounts -- `/mnt/wsl`, `/mnt/wslg`, `/mnt/data` -- which are returned unchanged.

## Backend Detection

The CLI auto-detects active backends on every `allow`/`deny` operation:

- **SQLite**: always active
- **BPF**: detected via `/sys/fs/bpf/ugow/grants`
- **kmod**: detected via `/sys/kernel/security/ugow/grant`

`allow` pushes the grant to every active kernel backend *first* and only commits to SQLite once they all accept; if any refuses, nothing is recorded and the command exits non-zero, so `ugow check` can never claim a permission the kernel will deny. `deny` reverses the order -- SQLite first, then the backends -- so a partial failure errs toward denying.

Because BPF grants are inode-keyed, this makes `ugow allow` on a nonexistent path a hard failure in BPF mode. See [BPF caveats](bpf.md#caveats-inode-keyed-grants).

## Boot-Time Replay

Grants in the BPF map and the kmod's hash table live in kernel memory and are lost on every `wsl --shutdown`. `ugow-sync.service` is installed and enabled by default, is conditional on either backend's control file existing, and runs `ugow sync` to replay the SQLite store at boot.

BPF mode needs one more step: pins live in a tmpfs and device numbers are reassigned on each restart, so managed drive letters are recorded in `/var/lib/ugow/drives` and `ugow-bpf.service` runs `ugow_manage.py restore-devices` before syncing grants. Without it, drives other than C: would come back unenforced while still carrying the permissions `ugow allow` widened for them.

## Project Layout

```
cli.py                CLI entry point (installed as /usr/local/bin/ugow)
permstore.py          SQLite-backed permission store
setup.sh              Installer / uninstaller
fuse/
  shim.py              FUSE overlay daemon
  mount-backing.sh     DrvFs backing mount helper with retry logic
  wait-mount.sh        ExecStartPost guard: blocks until /mnt/<letter> is mounted
bpf/
  ugow.bpf.c          eBPF LSM program
  ugow.h               Shared types (grant_key struct)
  ugow_manage.py       BPF loader and map manager
  Makefile              Builds ugow.bpf.o from kernel BTF
kmod/
  ugow_lsm.c           Compiled-in LSM module (custom kernel)
  Kconfig               Kernel config entry
  Makefile              Kbuild makefile
tests/
  conftest.py           Shared pytest fixtures
  test_permstore.py     Permission store unit tests
  test_shim_ops.py      FUSE shim operation tests
  test_cli.py           CLI and integration tests
  test_path_conversion.py  Path conversion tests
  test_security.py      Denial and privilege-bit regression tests
```
