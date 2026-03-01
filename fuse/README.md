# UGOW FUSE Shim

Userspace W-bit enforcement using a **FUSE overlay filesystem** -- the easiest
backend to deploy, works on any stock WSL2 kernel.

## How it works

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
                     │   (raw DrvFs, 0700,    │
                     │    root-only)          │
                     └───────────────────────┘
```

Each Windows drive gets its own isolated FUSE instance managed by a systemd
template unit (`wsl-fuse-shim@<letter>.service`). The raw DrvFs is remounted
under a hidden backing directory (`/mnt/.<letter>-backing`) and the FUSE shim
presents the user-visible mount at `/mnt/<letter>`.

Write-class VFS operations -- `open`, `create`, `truncate`, `mkdir`, `unlink`,
`rmdir`, `rename`, `symlink`, and `link` -- are gated by the SQLite-backed
permission store. Read operations pass through unmodified.

---

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

This installs the FUSE shim daemon, CLI, permission store, Python venv, systemd
template units, and configures `wsl.conf`. Drive C: is enabled by default.

## Uninstall

```bash
sudo ./setup.sh --uninstall
```

---

## Multi-drive management

```bash
sudo ugow mount d        # enable UGOW on D:
sudo ugow drives         # list all FUSE-managed drives
sudo ugow unmount d      # disable UGOW on D: (re-mounts as standard DrvFs)
```

## Grant / revoke write access

```bash
sudo ugow allow ubuntu /mnt/c/docker
sudo ugow deny  ubuntu /mnt/c/docker
```

## Query W-bit via xattr

The shim exposes a virtual extended attribute for quick permission checks:

```bash
getfattr -n user.ugow.wbit /mnt/c/data    # "1" = granted, "0" = denied
```

---

## Architecture notes

- **Root remapping** -- when the FUSE daemon runs as root (which it must for
  `allow_other`), root operations are remapped to the UID that launched the
  shim (`SUDO_UID` or `--launcher-uid`). This means root inherits the
  launching user's W-bit rights rather than bypassing enforcement entirely.

- **Permission inheritance** -- a grant on a directory applies to all files and
  subdirectories beneath it. The permission store walks up the path tree
  checking each ancestor.

- **W-bit in stat** -- `getattr` dynamically injects or strips the write bits
  (`0o222`) from the reported `st_mode` based on the calling user's grants.
  This gives correct `ls -l` output without modifying the underlying filesystem.

- **Path-escape protection** -- all path operations are resolved against the
  backing root and rejected if they escape it via `..` or symlinks.

- **Backing mount retries** -- `mount-backing.sh` handles transient DrvFs mount
  failures (common immediately after WSL boot) by retrying up to 5 times with a
  2-second delay.

- **Shared database** -- grants live in the same SQLite DB as all other backends
  (`/var/lib/ugow/wperm.db`), so you can switch between enforcement layers
  without re-creating grants.

---

## Files

```
shim.py              FUSE overlay daemon (UGOWShim + entry point)
mount-backing.sh     DrvFs backing mount helper with retry logic
```

---

## Deployment tiers

| Tier | Setup | Bypass resistance | Overhead |
|------|-------|-------------------|----------|
| FUSE shim | `sudo ./setup.sh` | Mountpoint only | Userspace context switch |
| BPF LSM | `.wslconfig` + `sudo ./setup.sh --mode bpf` | Full (kernel-level) | Near-zero (inline BPF) |
