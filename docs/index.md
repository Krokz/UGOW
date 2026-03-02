---
hide:
  - navigation
---

<div style="text-align: center; margin: 2rem 0 1rem;" markdown>

<pre style="display: inline-block; text-align: left; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; line-height: 1.3; border: none; background: none; padding: 0;">
  _   _    ____    ___   __        __
 | | | |  / ___|  / _ \  \ \      / /
 | | | | | |  _  | | | |  \ \ /\ / /
 | |_| | | |_| | | |_| |   \ V  V /
  \___/   \____|  \___/     \_/\_/
</pre>

# UGOW

**Unix Grant Overlay for Windows drives in WSL2**

Fine-grained, per-user write control for `/mnt/c`, `/mnt/d`, and beyond.

[Get Started](quickstart.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/Krokz/UGOW){ .md-button }

</div>

---

## The Problem

WSL2 mounts Windows drives via `/mnt/c` with effectively wide-open Unix permissions (often `777`), but the actual NTFS ACLs underneath don't know or care about Linux UIDs. Linux thinks everything is permitted, Windows disagrees, and there's no unified control plane.

It started with a QA engineer running a Docker container in WSL2, mounting a Windows-native path (`C:\Docker`) as a volume. The container ran as UID 9500 -- not the default Ubuntu UID 1000. Everything broke. The errors were cryptic. Every fix required changes on the Windows side.

I couldn't find a clean solution, so I built one.

## Features

- :material-shield-lock: **Three enforcement backends** -- choose FUSE (easiest), BPF LSM (fastest), or a compiled-in kernel module.
- :material-harddisk: **Multi-drive support** -- manage any Windows drive (C:, D:, E:, ...) with a single command.
- :material-file-lock: **W-bit enforcement** -- gates `open`, `create`, `truncate`, `mkdir`, `unlink`, `rmdir`, `rename`, `symlink`, and `link`.
- :material-family-tree: **Permission inheritance** -- a grant on a directory applies to all descendants automatically.
- :material-microsoft-windows: **ACL mirroring** -- optionally creates matching NTFS ACL grants via PowerShell/`icacls`.
- :material-console: **Unified CLI** -- `ugow allow`, `deny`, `check`, `status`, `list` -- works the same across all backends.

## Quick Example

```bash
# Install (one command)
sudo ./setup.sh

# Grant a user write access
sudo ugow allow ubuntu /mnt/c/docker

# Check access
sudo ugow check /mnt/c/docker

# Use with Docker -- no special paths needed
docker run --user 9500 -v /mnt/c/userdata:/data my-image
```

## Choose Your Backend

|  | FUSE | BPF | kmod |
|---|---|---|---|
| **Install** | `sudo ./setup.sh` | `sudo ./setup.sh --mode bpf` | Custom kernel build |
| **Where it runs** | Userspace | Kernel (eBPF) | Kernel (compiled-in) |
| **Custom kernel?** | No | No (stock WSL2 6.6+) | Yes |
| **Overhead** | Moderate | Near zero | Near zero |
| **Bypass resistance** | Mountpoint only | Full | Full |

:material-arrow-right: [Compare backends in detail](architecture.md#enforcement-modes)

---

<div style="text-align: center; margin-top: 2rem; opacity: 0.6;" markdown>

*Originally: **U**ser **G**roup **O**ther **W**indows -- because that's the Unix permission model this extends. Rebranded to something that sounds like it belongs on a resume.*

</div>
