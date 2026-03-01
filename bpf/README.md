# UGOW BPF LSM

Kernel-level W-bit enforcement using eBPF LSM hooks on the **stock WSL2
kernel** -- no kernel rebuild required.

## How it works

```
                     ┌────────────────────────────────┐
                     │          WSL2 Kernel            │
                     │                                │
   open("/mnt/c/x") │  VFS → LSM hooks → BPF progs   │
   ──────────────────┤       ↓                        │
                     │  grants map: (ino,dev,uid)?    │
                     │       ↓                        │
                     │  ALLOW or -EACCES              │
                     └────────────────────────────────┘
                                 ▲
                     ┌───────────┴───────────┐
                     │  ugow_manage.py       │
                     │  resolves paths →     │
                     │  (ino, dev) via stat() │
                     │  updates BPF maps     │
                     │  persists in SQLite   │
                     └───────────────────────┘
```

The BPF programs hook into the kernel's LSM framework and check every
write-class VFS operation against a hash map keyed by `(inode, device, uid)`.
The userspace manager resolves human-readable paths to inode numbers and
keeps the BPF maps in sync with the SQLite grant database (shared with the
FUSE shim).

Key advantage over the FUSE shim: **cannot be bypassed from userspace**.
Every syscall path to the filesystem passes through the LSM hooks.

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

### 3. Build the BPF program

```bash
cd bpf/
make
```

This generates `vmlinux.h` from your running kernel's BTF data and compiles
`ugow.bpf.o`.

## Usage

All commands require root (`sudo`).

### Load the BPF program

```bash
sudo python3 ugow_manage.py load
```

### Register a Windows drive mount for enforcement

```bash
sudo python3 ugow_manage.py add-device /mnt/c
```

Only devices registered this way are subject to W-bit checks. Other
filesystems (ext4, tmpfs, etc.) are completely unaffected.

### Grant / revoke write access

```bash
# Grant UID 9500 write access to /mnt/c/data
sudo python3 ugow_manage.py grant 9500 /mnt/c/data

# Revoke it
sudo python3 ugow_manage.py revoke 9500 /mnt/c/data
```

Grants are persisted in the same SQLite database as the FUSE shim
(`/var/lib/wsl-fuse-shim/wperm.db`), so both enforcement layers share a
single source of truth.

### Sync existing grants into BPF

If you already have grants from the FUSE shim:

```bash
sudo python3 ugow_manage.py sync
```

### List active BPF map entries

```bash
sudo python3 ugow_manage.py list
```

### Unload

```bash
sudo python3 ugow_manage.py unload
```

## Architecture notes

- **No string operations in kernel**: the BPF program uses `(inode, device,
  uid)` integer keys, avoiding BPF's string limitations entirely. The
  userspace loader resolves paths via `stat()`.

- **Inheritance**: the BPF program walks up the dentry tree (bounded to 64
  levels) checking each ancestor, so a grant on `/mnt/c/data` covers
  `/mnt/c/data/sub/file.txt`.

- **Device filtering**: only mounts registered via `add-device` trigger
  enforcement. This prevents accidental lockouts on system filesystems.

- **Shared database**: grants live in the same SQLite DB as the FUSE shim,
  so you can use either or both enforcement layers with a single grant
  management interface.

## Deployment tiers

| Tier | Setup | Bypass resistance | Overhead |
|------|-------|-------------------|----------|
| FUSE shim only | `pip install fusepy`, run script | Mountpoint only | Userspace context switch |
| BPF LSM only | `.wslconfig` + `apt install clang` | Full (kernel-level) | Near-zero (inline BPF) |
| Both | All of the above | Full + defense-in-depth | Both |
