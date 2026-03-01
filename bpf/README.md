# UGOW BPF LSM

Kernel-level W-bit enforcement using eBPF LSM hooks on the **stock WSL2
kernel** -- no kernel rebuild required.

## How it works

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

The BPF programs hook into the kernel's LSM framework and check every
write-class VFS operation against a hash map keyed by `(inode, device, uid)`.
The userspace manager resolves human-readable paths to inode numbers and
keeps the BPF maps in sync with the SQLite grant database (shared with the
FUSE shim).

Key advantage over the FUSE shim: **cannot be bypassed from userspace**.
Every syscall path to the filesystem passes through the LSM hooks.

**Root (uid 0) is always exempt** from enforcement to prevent system lockout.

---

## Prerequisites

The stock WSL2 kernel (6.6+) ships with `CONFIG_BPF_LSM=y`, but BPF LSM
is not activated by default. You need to add `bpf` to the LSM boot list.

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

```bash
sudo apt install -y clang llvm libbpf-dev linux-tools-common bpftool
```

### 3. Install via setup.sh

```bash
sudo ./setup.sh --mode bpf
```

This builds the BPF program, installs all components, creates a systemd
service, and enables enforcement on `/mnt/c` by default.

---

## Manual usage

If you prefer to manage the BPF program directly (without the installer):

### Build

```bash
cd bpf/
make
```

This generates `vmlinux.h` from your running kernel's BTF data and compiles
`ugow.bpf.o`.

### Load

```bash
sudo python3 ugow_manage.py load
```

### Register a drive for enforcement

```bash
sudo python3 ugow_manage.py add-device /mnt/c
```

Only devices registered this way are subject to W-bit checks. Other
filesystems (ext4, tmpfs, etc.) are completely unaffected.

### Grant / revoke write access

The recommended way is through the unified CLI:

```bash
sudo ugow allow 9500 /mnt/c/data
sudo ugow deny  9500 /mnt/c/data
```

The CLI automatically syncs grants to both SQLite and the BPF map when
BPF is active. You can also use the manager directly:

```bash
sudo python3 ugow_manage.py grant 9500 /mnt/c/data
sudo python3 ugow_manage.py revoke 9500 /mnt/c/data
```

### Sync existing grants into BPF

If you already have grants in SQLite (e.g. from prior FUSE usage):

```bash
sudo python3 ugow_manage.py sync
```

### List / unload

```bash
sudo python3 ugow_manage.py list      # show BPF map entries
sudo python3 ugow_manage.py unload    # detach hooks and unpin programs
```

---

## Architecture notes

- **No string operations in kernel** -- the BPF program uses `(inode, device,
  uid)` integer keys, avoiding BPF's string limitations entirely. The
  userspace loader resolves paths via `stat()`.

- **Inheritance** -- the BPF program walks up the dentry tree (bounded to 32
  levels) checking each ancestor, so a grant on `/mnt/c/data` covers
  `/mnt/c/data/sub/file.txt`.

- **Device filtering** -- only mounts registered via `add-device` trigger
  enforcement. This prevents accidental lockouts on system filesystems.

- **Root exemption** -- uid 0 is always allowed through all hooks, preventing
  root lockout if the BPF maps are empty or misconfigured.

- **Cross-device rename protection** -- the rename hook checks both the source
  and destination directories against `target_devs`, preventing files from
  being renamed into a protected directory from an unprotected one.

- **Shared database** -- grants live in the same SQLite DB as the FUSE shim
  (`/var/lib/ugow/wperm.db`), so you can switch between enforcement layers
  without re-creating grants.

---

## Deployment tiers

| Tier | Setup | Bypass resistance | Overhead |
|------|-------|-------------------|----------|
| FUSE shim only | `sudo ./setup.sh` | Mountpoint only | Userspace context switch |
| BPF LSM only | `.wslconfig` + `sudo ./setup.sh --mode bpf` | Full (kernel-level) | Near-zero (inline BPF) |
