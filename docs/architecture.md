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
 /mnt/.<letter>-backing   <-- raw DrvFs, umask=077, root-only
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

Compiled-in LSM hooks enforce on all 9P superblocks:

```
     /mnt/<letter>          <-- real DrvFs (WSL automount)
          |
    LSM hooks               <-- ugow_inode_permission, ugow_file_open, etc.
          |
   in-kernel hash table     <-- path-based grants via securityfs
```

**Trade-offs:**

- Same kernel-level enforcement as BPF mode
- Requires a custom WSL2 kernel build
- RCU-based hash table for lock-free reads on the hot path
- Automatic enforcement on all 9P mounts (no per-drive registration needed)

### Mode comparison

|  | FUSE | BPF | kmod |
|---|---|---|---|
| **Install** | `sudo ./setup.sh` | `sudo ./setup.sh --mode bpf` | Custom kernel build |
| **Where it runs** | Userspace (FUSE) | Kernel (eBPF LSM) | Kernel (compiled-in LSM) |
| **Needs custom kernel?** | No | No (stock WSL2 6.6+) | Yes (`CONFIG_SECURITY_UGOW=y`) |
| **Performance overhead** | Moderate (user/kernel bounce) | Near zero | Near zero |
| **WSL automount** | Disabled (UGOW mounts drives) | Left enabled | Left enabled |
| **Root bypasses enforcement?** | No (remapped to launching user) | Yes (uid 0 exempt) | Configurable |
| **Multi-drive** | `ugow mount d` | `ugow mount d` | Automatic (all 9P mounts) |
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

### Caching

The permission store maintains a TTL-based in-memory cache (2 seconds) keyed by `(path, uid)` to reduce SQLite lookups on hot paths. The cache is invalidated on `grant()` and `revoke()`.

### Thread safety

SQLite connections are per-thread (stored in `threading.local()`). WAL mode is enabled for concurrent read/write access across threads.

### ACL mirroring

When enabled (`--mirror-acl`), grant and revoke operations are queued to a background worker thread that:

1. Creates a Windows local user `wsl_<UID>` if it doesn't exist
2. Runs `icacls` via PowerShell to apply or remove NTFS ACLs on the Windows path
3. Times out after 30 seconds per operation to prevent hangs

ACL mirroring is best-effort -- if it fails, the SQLite grant still succeeds and the W-bit enforcement layer works independently.

### Path conversion

Linux paths under `/mnt/<drive>/...` are translated to Windows paths (`C:\...`) for ACL mirroring commands.

## Backend Detection

The CLI auto-detects active backends on every `allow`/`deny` operation:

- **SQLite**: always active
- **BPF**: detected via `/sys/fs/bpf/ugow/grants`
- **kmod**: detected via `/sys/kernel/security/ugow/grant`

Grants are synced to all active backends automatically.

## Project Layout

```
cli.py                CLI entry point (installed as /usr/local/bin/ugow)
permstore.py          SQLite-backed permission store
setup.sh              Installer / uninstaller
fuse/
  shim.py              FUSE overlay daemon
  mount-backing.sh     DrvFs backing mount helper with retry logic
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
```
