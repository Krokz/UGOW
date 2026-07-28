# BPF LSM

Kernel-level W-bit enforcement using eBPF LSM hooks on the **stock WSL2 kernel** -- no kernel rebuild required.

## How It Works

```
                     ┌────────────────────────────────┐
                     │          WSL2 Kernel            │
                     │                                 │
   open("/mnt/c/x") │  VFS -> LSM hooks -> BPF progs  │
   ──────────────────┤       |                         │
                     │  grants map: (ino,dev,uid)?     │
                     │       |                         │
                     │  ALLOW or -EACCES               │
                     └────────────────────────────────┘
                                 ^
                     ┌───────────┴───────────┐
                     │   ugow_manage.py      │
                     │   resolves paths ->   │
                     │   (ino, dev) via stat  │
                     │   updates BPF maps    │
                     │   persists in SQLite  │
                     └───────────────────────┘
```

The BPF programs hook into the kernel's LSM framework and check every write-class VFS operation against a hash map keyed by `(inode, device, uid)`. The userspace manager resolves human-readable paths to inode numbers and keeps the BPF maps in sync with the SQLite grant database.

Key advantage over the FUSE shim: **cannot be bypassed from userspace**. Every syscall path to the filesystem passes through the LSM hooks.

!!! info "Root exemption"
    Root (uid 0) is always exempt from enforcement to prevent system lockout.

## Prerequisites

The stock WSL2 kernel (6.6+) ships with `CONFIG_BPF_LSM=y`, but BPF LSM is not activated by default. You need to add `bpf` to the LSM boot list.

### 1. Enable BPF LSM

Edit `%USERPROFILE%\.wslconfig` on the Windows side:

```ini
[wsl2]
kernelCommandLine = lsm=landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo,bpf
```

Then restart WSL:

```powershell
wsl --shutdown
```

Verify it worked:

```bash
cat /sys/kernel/security/lsm
# Should include "bpf" in the comma-separated list
```

### 2. Install build dependencies

`clang` and `libbpf-dev` are hard requirements -- `ugow.bpf.c` includes `<bpf/bpf_helpers.h>`, and the installer checks for both before building. The rest of this list is what building `bpftool` needs:

```bash
sudo apt install -y clang llvm libbpf-dev build-essential libelf-dev libssl-dev
```

!!! note "bpftool on WSL2"
    `bpftool` is required and there is no `linux-tools` package that matches the custom Microsoft WSL2 kernel. Build it from source:

    ```bash
    git clone --depth 1 https://github.com/libbpf/bpftool.git
    cd bpftool
    git submodule update --init --depth 1
    cd src && make && sudo make install
    hash -r
    bpftool version   # should show v7.x.x
    ```

### 3. Install via setup.sh

```bash
sudo ./setup.sh --mode bpf
```

This builds the BPF program, installs all components, creates a systemd service, and enables enforcement on `/mnt/c` by default.

## Multi-Drive Management

The `ugow` CLI auto-detects BPF mode -- the same commands work for both FUSE and BPF:

```bash
sudo ugow mount d         # enable UGOW enforcement on D:
sudo ugow drives          # list enforced drives
sudo ugow unmount d       # stop enforcing on D:
```

Only devices registered this way are subject to W-bit checks. Other filesystems (ext4, tmpfs, etc.) are completely unaffected.

## Architecture Notes

### No string operations in kernel

The BPF program uses `(inode, device, uid)` integer keys, avoiding BPF's string limitations entirely. The userspace loader resolves paths via `stat()`.

### Inheritance

The BPF program walks up the dentry tree (bounded to 64 levels, `MAX_PATH_DEPTH` in `bpf/ugow.h`) checking each ancestor, so a grant on `/mnt/c/data` covers `/mnt/c/data/sub/file.txt`.

### Filesystem UID, not real UID

The hooks read `cred->fsuid` from the current task rather than the real UID returned by `bpf_get_current_uid_gid()`. Those diverge whenever a task has called `setfsuid()` -- file servers and some container runtimes do -- and `fsuid` is the identity the kernel's own DAC check uses, so the two decisions agree.

### Device filtering

Only mounts registered via `ugow mount` trigger enforcement. This prevents accidental lockouts on system filesystems.

Registered drive letters are recorded in `/var/lib/ugow/drives`. BPF pins live in a tmpfs and device numbers are reassigned on every `wsl --shutdown`, so `ugow-bpf.service` runs `ugow_manage.py restore-devices` at boot to re-register every recorded drive -- not just C:. A drive that came back unregistered would be unenforced while still carrying the widened permissions `ugow allow` gave it, so `restore-devices` fails loudly if a recorded drive cannot be re-registered.

### Cross-device rename protection

The rename hook checks both the source and destination directories against `target_devs`, preventing files from being renamed into a protected directory from an unprotected one.

### Hard links are checked on both ends

`inode_link` requires the W-bit on the destination's parent *and* on the existing file. Without the second check, linking a protected file into a granted directory would make it writable through its new name, since the ancestor walk starts from whichever path is used.

### Shared database

Grants live in the same SQLite DB as the FUSE shim (`/var/lib/ugow/wperm.db`), so you can switch between enforcement layers without re-creating grants.

## Caveats (inode-keyed grants)

Because BPF keys grants on `(inode, device, uid)` rather than path strings, it
behaves slightly differently from the SQLite-backed FUSE shim and the kmod
backend (both of which match on the path). These are **inherent to the design**
-- fixing them would require in-kernel path resolution, which would defeat the
near-zero overhead that is BPF mode's whole reason to exist. Know them rather
than work around them:

- **Delete + recreate orphans a grant.** Recreating a granted directory (or a
  tool that does atomic replace-by-rename) gives it a new inode. The BPF map
  still holds the old inode, so enforcement silently stops applying. Re-run
  `ugow allow` (or `ugow sync`) after such an operation. Path-based backends are
  unaffected.
- **Inheritance is capped at 64 levels** (`MAX_PATH_DEPTH` in `bpf/ugow.h`). A
  grant more than 64 directories above a deeply nested file will not be found,
  producing a false denial. The FUSE/SQLite ancestor walk is unbounded.
- **You can't pre-grant a non-existent path.** `ugow allow` resolves the path to
  an inode via `stat()`, so in BPF mode granting a path that doesn't exist yet
  **fails the whole command** with a non-zero exit and nothing is recorded --
  the alternative would be an SQLite grant the kernel refuses to honour. Create
  the path first, then grant. A SQLite-only install stores the string and does
  not need the path to exist; the kmod stores a string too, but the CLI still
  has to `stat()` the path to resolve its device.

If any of these matter for your workflow, use **FUSE mode** -- it matches on the
path string and has none of these caveats (at the cost of a userspace round-trip
per op). The kmod backend is also path-based but is experimental and unverified;
see [kmod](kmod.md).

## Manual Usage

If you prefer to manage the BPF program directly (without the installer):

```bash
cd bpf/
make                                              # build ugow.bpf.o
sudo python3 ugow_manage.py load                  # load and attach LSM hooks
sudo python3 ugow_manage.py add-device /mnt/c     # register a drive
sudo python3 ugow_manage.py restore-devices       # re-register all recorded drives
sudo python3 ugow_manage.py grant 9500 /mnt/c/data
sudo python3 ugow_manage.py revoke 9500 /mnt/c/data
sudo python3 ugow_manage.py remove-device /mnt/d  # stop enforcing a drive
sudo python3 ugow_manage.py sync                  # sync SQLite -> BPF map
sudo python3 ugow_manage.py list                  # show BPF map entries
sudo python3 ugow_manage.py unload                # detach and unpin
```

## Systemd Service

```bash
# Check status
sudo systemctl status ugow-bpf.service

# View logs
sudo journalctl -u ugow-bpf.service -f
```
