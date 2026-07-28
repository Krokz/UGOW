# FUSE Shim

Userspace W-bit enforcement using a **FUSE overlay filesystem** -- the easiest backend to deploy, works on any stock WSL2 kernel.

## How It Works

```
                     ┌────────────────────────────────┐
                     │       WSL2 Userspace            │
                     │                                 │
   open("/mnt/c/x") │  FUSE daemon (UGOWShim)         │
   ──────────────────┤       |                         │
                     │  PermStore: has_wbit(path,uid)? │
                     │       |                         │
                     │  ALLOW  ->  pass to backing     │
                     │  DENY   ->  -EACCES             │
                     └────────────────────────────────┘
                                 ^
                     ┌───────────┴───────────┐
                     │   /mnt/.<letter>-      │
                     │     backing            │
                     │   (raw DrvFs,          │
                     │    umask=077,          │
                     │    nosuid, nodev)      │
                     └───────────────────────┘
```

Each Windows drive gets its own isolated FUSE instance managed by a systemd template unit (`wsl-fuse-shim@<letter>.service`). The raw DrvFs is remounted under a hidden backing directory (`/mnt/.<letter>-backing`) with `metadata,umask=077,nosuid,nodev` -- `umask=077` makes it root-only, and `nosuid,nodev` mean it can never carry privilege bits or device nodes, since any granted user can write there through the shim. The FUSE shim presents the user-visible mount at `/mnt/<letter>`.

Write-class VFS operations -- `access` (for `W_OK`), `open`, `create`, `truncate`, `mkdir`, `unlink`, `rmdir`, `rename`, `symlink`, `link`, `chmod`, and `utimens` -- are gated by the SQLite-backed permission store. Read operations pass through unmodified.

`chmod` and `utimens` are metadata writes and gated like any other write: the shim runs as root, so an ungated `chmod` would let any caller re-mode every file on the drive. `chmod` additionally masks off the `setuid` and `setgid` bits, which buy nothing on a Windows drive and would be a privilege-escalation primitive. `link` requires the W-bit on the source file as well as the destination parent, so a second name can never confer rights the first one lacked. `chown` remains root-only, tested against the real caller UID rather than the root-remapped one.

## Prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv fuse libfuse2
```

No custom kernel or kernel modules required.

## Install

```bash
sudo ./setup.sh
```

This installs the FUSE shim daemon, CLI, permission store, Python venv, systemd template units, and configures `wsl.conf`. Drive C: is enabled by default.

## Multi-Drive Management

```bash
sudo ugow mount d        # enable UGOW on D:
sudo ugow drives         # list all FUSE-managed drives
sudo ugow unmount d      # disable UGOW on D: (re-mounts as standard DrvFs)
```

## Query W-bit via xattr

The shim exposes a virtual extended attribute for quick permission checks:

```bash
getfattr -n user.ugow.wbit /mnt/c/data    # "1" = granted, "0" = denied
```

## Architecture Notes

### Root remapping

When the FUSE daemon runs as root (which it must for `allow_other`), root operations are remapped to the UID that launched the shim (`SUDO_UID` or `--launcher-uid`). This means root inherits the launching user's W-bit rights rather than bypassing enforcement entirely.

### Permission inheritance

A grant on a directory applies to all files and subdirectories beneath it. The permission store walks up the path tree checking each ancestor.

### W-bit in stat

`getattr` dynamically injects or strips the write bits (`0o222`) from the reported `st_mode` based on the calling user's grants. This gives correct `ls -l` output without modifying the underlying filesystem.

### No attribute caching

The mount runs with `attr_timeout=0`, `entry_timeout=0`, and `negative_timeout=0`. `getattr` reports the W-bit for the *calling* UID, but the kernel's attribute cache is per-inode -- caching would let one user's mode answer decide `default_permissions` checks for another. The mount is also `nosuid,nodev`.

### Audited denials

Every denial is logged as a warning by the `ugow` logger with the operation, the calling UID, and the mount-visible path:

```bash
sudo journalctl -u wsl-fuse-shim@c.service -f
```

### Path-escape protection

All path operations are resolved against the backing root and rejected if they escape it via `..` or symlinks.

### Backing mount retries

`mount-backing.sh` handles transient DrvFs mount failures (common immediately after WSL boot) by retrying up to 5 times with a 2-second delay.

### Start-up ordering

The shim runs in the foreground, so `Type=simple` would report the unit started as soon as the process forks -- before libfuse has mounted anything. `wait-mount.sh` runs as `ExecStartPost` and blocks (up to 20 s) until `/mnt/<letter>` is really a mount point, so units ordered `After=` it do not race an unmounted drive.

## Limitations

- **Bypass resistance** -- enforcement is at the mountpoint level. A process with raw block device access or `CAP_SYS_ADMIN` could theoretically access the backing mount directly. For kernel-level enforcement, use [BPF mode](bpf.md).
- **Performance** -- each VFS operation crosses the user/kernel boundary twice (into FUSE, then back to DrvFs). For I/O-heavy workloads, [BPF mode](bpf.md) has near-zero overhead.

## Systemd Service

The FUSE shim runs as a systemd template unit:

```bash
# Check status
sudo systemctl status wsl-fuse-shim@c.service

# Restart
sudo systemctl restart wsl-fuse-shim@c.service

# View logs
sudo journalctl -u wsl-fuse-shim@c.service -f
```
