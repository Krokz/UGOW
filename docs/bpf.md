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

```bash
sudo apt install -y clang llvm libbpf-dev build-essential libelf-dev libssl-dev
```

!!! note "bpftool on WSL2"
    The WSL2 kernel is custom-built by Microsoft, so there's no matching `linux-tools` package. Build bpftool from source:

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

The BPF program walks up the dentry tree (bounded to 32 levels) checking each ancestor, so a grant on `/mnt/c/data` covers `/mnt/c/data/sub/file.txt`.

### Device filtering

Only mounts registered via `ugow mount` trigger enforcement. This prevents accidental lockouts on system filesystems.

### Cross-device rename protection

The rename hook checks both the source and destination directories against `target_devs`, preventing files from being renamed into a protected directory from an unprotected one.

### Shared database

Grants live in the same SQLite DB as the FUSE shim (`/var/lib/ugow/wperm.db`), so you can switch between enforcement layers without re-creating grants.

## Manual Usage

If you prefer to manage the BPF program directly (without the installer):

```bash
cd bpf/
make                                              # build ugow.bpf.o
sudo python3 ugow_manage.py load                  # load and attach LSM hooks
sudo python3 ugow_manage.py add-device /mnt/c     # register a drive
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
