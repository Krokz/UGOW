```
  _   _    ____    ___   __        __
 | | | |  / ___|  / _ \  \ \      / /
 | | | | | |  _  | | | |  \ \ /\ / /
 | |_| | | |_| | | |_| |   \ V  V /
  \___/   \____|  \___/     \_/\_/
```

# UGOW

[![Tests](https://github.com/Krokz/UGOW/actions/workflows/tests.yml/badge.svg)](https://github.com/Krokz/UGOW/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**U**nix **G**rant **O**verlay for **W**indows drives in WSL2.

UGOW adds fine-grained, per-user write control to Windows drives mounted in WSL2. Write operations on `/mnt/c`, `/mnt/d`, etc. are gated by a SQLite-backed permission store and optionally mirrored to NTFS ACLs on the Windows host.

---

## Why

It started with a QA engineer on our team. He was running a Docker container in WSL2, mounting a Windows-native path (`C:\Docker`) as a volume. The container ran as UID 9500 -- not the default Ubuntu UID 1000.

Everything broke. The container couldn't write to its own mounted volume. The errors were cryptic. And every fix we found required changes on the Windows side -- NTFS ACL tweaks, `icacls` commands, folder permission dialogs. Nothing could be done from within WSL itself.

That's the gap: WSL2 mounts Windows drives via `/mnt/c` with effectively wide-open Unix permissions (often `777`), but the actual NTFS ACLs underneath don't know or care about Linux UIDs. So you get the worst of both worlds -- Linux thinks everything is permitted, Windows disagrees, and there's no unified control plane.

I couldn't find a clean solution, so I built one.

---

## Features

- **Three enforcement backends** -- choose between a FUSE overlay shim (easiest), BPF LSM hooks (fastest, kernel-level), or a compiled-in kernel LSM module (custom kernel builds).
- **Multi-drive support** -- manages any Windows drive (C:, D:, E:, ...) via systemd template units (FUSE mode) or device registration (BPF mode).
- **W-bit enforcement** -- gates `access`, `open`, `create`, `truncate`, `mkdir`, `unlink`, `rmdir`, `rename`, `symlink`, `link`, `chmod`, and `utimens` based on the permission store. A hard link needs the W-bit on both the source file and the destination directory, and the shim never lets `setuid`/`setgid` bits be set.
- **Permission inheritance** -- a grant on a directory applies to all descendants.
- **Root exemption** (BPF mode) -- root is always allowed through. In FUSE mode, root is remapped to the user who launched the shim, inheriting their W-bit rights. The kmod makes this a build-time choice (`CONFIG_SECURITY_UGOW_ROOT_EXEMPT`, default `y`).
- **Audited denials** -- every refused operation is logged with the operation, UID, and mount-visible path (`journalctl -u wsl-fuse-shim@c.service`).
- **ACL mirroring** -- best-effort creation of corresponding Windows local users (`wsl_<UID>`) and NTFS ACL grants via PowerShell/`icacls`.
- **Unified CLI** -- `ugow allow`, `ugow deny`, `ugow check`, `ugow status`, `ugow list`, `ugow sync`, `ugow acl-cleanup` -- works identically across all backends.

---

## Quick Start

```bash
# Install (FUSE mode, default)
sudo ./setup.sh

# Grant a user write access to a path
sudo ugow allow ubuntu /mnt/c/docker

# Check your own access
sudo ugow check /mnt/c/docker

# Check a specific user
sudo ugow check --user 9500 /mnt/c/docker

# See who can write somewhere
sudo ugow status /mnt/c/docker

# List all grants
sudo ugow list

# Revoke access
sudo ugow deny ubuntu /mnt/c/docker
```

---

## Installation

### Prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv fuse libfuse2
```

For BPF mode, also install `clang` and the libbpf headers:

```bash
sudo apt install -y clang libbpf-dev
```

`bpftool` is required too, but the WSL2 kernel is custom-built by Microsoft and has no matching `linux-tools` package -- build it from source instead:

```bash
sudo apt install -y build-essential libelf-dev libssl-dev llvm clang
git clone --depth 1 https://github.com/libbpf/bpftool.git
cd bpftool
git submodule update --init --depth 1
cd src && make && sudo make install
hash -r
```

### Install

```bash
# FUSE mode (default) -- easiest, no kernel requirements
sudo ./setup.sh

# BPF mode -- faster, kernel-level enforcement
sudo ./setup.sh --mode bpf
```

The installer handles everything: CLI, permission store, Python venv, systemd units, and `wsl.conf` configuration. Drive C: is enabled by default.

### Uninstall

```bash
sudo ./setup.sh --uninstall
```

This stops all services, removes installed files and BPF pins, and reloads systemd. The permission database (`/var/lib/ugow/wperm.db`) is preserved -- delete it manually with `sudo rm -rf /var/lib/ugow` if desired. Run `wsl --shutdown` from Windows afterwards to apply `wsl.conf` changes.

---

## Enforcement Modes

|  | FUSE | BPF | kmod |
|---|---|---|---|
| **Install** | `sudo ./setup.sh` | `sudo ./setup.sh --mode bpf` | Custom kernel build |
| **Where it runs** | Userspace (FUSE) | Kernel (eBPF LSM) | Kernel (compiled-in LSM) |
| **Needs custom kernel?** | No | No (stock WSL2 6.6+) | Yes (`CONFIG_SECURITY_UGOW=y`) |
| **Performance overhead** | Moderate (user/kernel bounce) | Near zero | Near zero |
| **WSL automount** | Disabled (UGOW mounts drives) | Left enabled (BPF enforces on real mount) | Left enabled |
| **Root bypasses enforcement?** | No (remapped to launching user) | Yes (uid 0 is always allowed) | Build-time choice: `CONFIG_SECURITY_UGOW_ROOT_EXEMPT` (default `y`) |
| **Multi-drive** | `ugow mount d` | `ugow mount d` | Per-device opt-in via securityfs `devices` |
| **Grant interface** | SQLite | SQLite + BPF map | SQLite + securityfs |

**FUSE and BPF are mutually exclusive.** The FUSE shim's own I/O to the backing filesystem would be blocked by BPF hooks, and BPF cannot see through the FUSE device. The installer detects conflicts and refuses to install if the other mode is active.

The **kmod** (`kmod/ugow_lsm.c`) is a standalone option for custom WSL2 kernel builds. It is **experimental and unverified** -- it is not covered by the installer and has not been compiled or booted against a real kernel. See [docs/kmod.md](docs/kmod.md) for the build steps and the securityfs interface. The CLI auto-detects it via `/sys/kernel/security/ugow/`, registers the drive's device, and syncs grants to securityfs on `allow`/`deny`.

---

## Usage

### Grant and revoke permissions

```bash
sudo ugow allow ubuntu /mnt/c/docker     # grant write access
sudo ugow deny  ubuntu /mnt/c/docker     # revoke write access
sudo ugow check /mnt/c/docker            # can I write here?
sudo ugow check --user 9500 /mnt/c/data  # can UID 9500 write here?
sudo ugow status /mnt/c/docker           # who can write here?
sudo ugow list                           # show all grants
sudo ugow sync                           # replay SQLite into kernel backends
sudo ugow acl-cleanup                    # drop mirrored wsl_* users with no grants
```

Users can be specified by name or numeric UID. All commands require root (`sudo`). The `check` command uses `SUDO_UID` to test the *calling* user's permissions, not root's.

`allow` and `deny` are the only commands that write to a kernel backend on their own; `sync` replays the whole store into whichever kernel backend is active, which is what `ugow-sync.service` runs at boot.

### Multi-drive management

Works the same regardless of whether FUSE or BPF mode is installed:

```bash
sudo ugow mount d        # enable UGOW on D:
sudo ugow mount e        # enable UGOW on E:
sudo ugow drives         # list all active drives
sudo ugow unmount d      # disable UGOW on D:
```

### Query W-bit via xattr (FUSE mode)

```bash
getfattr -n user.ugow.wbit /mnt/c/data    # "1" = granted, "0" = denied
```

### Using with Docker

No special paths needed -- Docker bind-mounts use `/mnt/c` as usual:

```bash
# Grant the container's UID write access first
sudo ugow allow 9500 /mnt/c/userdata

# Then run the container
docker run --user 9500 \
  -v /mnt/c/userdata:/data \
  my-image
```

The container (UID 9500) will be able to write under `/data` only if you granted its W-bit.

---

## Architecture

### FUSE mode

Each drive gets its own isolated FUSE instance via a systemd template unit (`wsl-fuse-shim@<letter>.service`):

```
 /mnt/.<letter>-backing   <-- raw DrvFs, mounted metadata,umask=077,nosuid,nodev
          |
      FUSE shim            <-- UGOWShim (permission checks, W-bit enforcement)
          |
     /mnt/<letter>          <-- what users and tools see (transparent)
```

The FUSE mount itself is also `nosuid,nodev`, and attribute, entry and negative-entry caching are disabled so one user's W-bit answer can never satisfy a kernel permission check for another.

### BPF mode

BPF LSM hooks enforce directly on the real DrvFs mount. Root (uid 0) is exempt.

```
     /mnt/<letter>          <-- real DrvFs (WSL automount)
          |
    BPF LSM hooks           <-- ugow_file_open, ugow_inode_permission, etc.
          |
     grants map             <-- (inode, dev, uid) -> allow/deny
```

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

### Shared components

```
  permstore.py    <-- SQLite-backed grant store (shared by all backends)
  cli.py          <-- ugow CLI (always installed)
```

---

## Internals

- **Metadata** -- stored in `/var/lib/ugow/wperm.db` (SQLite, WAL mode, thread-safe with per-thread connections).
- **W-bit cache** -- the permission store maintains an LRU cache of `(path, uid)` answers, hard-bounded at 8192 entries with a 2 s TTL, to reduce SQLite lookups on hot paths. The long-lived FUSE daemon also runs a background poll on SQLite's `data_version` and flushes its cache when another process (the CLI) commits a grant, so `allow`/`deny` take effect promptly without restarting the shim.
- **Path conversion** -- Linux paths under `/mnt/<drive>/...` are translated to Windows paths (e.g. `C:\...`) for ACL mirroring commands. Only a single-letter component counts as a drive, so real WSL mounts such as `/mnt/wsl` and `/mnt/wslg` are left alone.
- **Backend detection** -- the CLI auto-detects active backends (BPF via `/sys/fs/bpf/ugow/grants`, kmod via `/sys/kernel/security/ugow/grant`) and syncs grants to all active backends on `allow`/`deny`.
- **Atomic grants** -- `ugow allow` pushes to the active kernel backends *before* committing to SQLite and aborts with a non-zero exit if any of them refuses, so `ugow check` can never report a permission the kernel will deny. `ugow deny` runs in the opposite order (SQLite first), erring toward denial if a backend fails.
- **DAC restoration** (BPF mode) -- `ugow allow` widens a path's Unix mode when it would block writes before the LSM hooks even run, records the original mode, and `ugow deny` restores it once no UID holds a grant on that path.
- **Boot-time replay** -- kernel grants live in kernel memory, so `ugow-sync.service` is installed and enabled by default and replays SQLite into the active kernel backend at boot. In BPF mode the managed drive letters are recorded in `/var/lib/ugow/drives` and re-registered by `ugow_manage.py restore-devices`, since device numbers are reassigned on every WSL restart.

---

## Development

### Running tests

The FUSE shim tests import `fuse`, so both requirement files are needed:

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest tests/ -v
```

### Project layout

```
cli.py                CLI entry point (installed as /usr/local/bin/ugow)
permstore.py          SQLite-backed permission store
setup.sh              Installer / uninstaller
fuse/
  shim.py              FUSE overlay daemon
  mount-backing.sh     DrvFs backing mount helper with retry logic
  wait-mount.sh        ExecStartPost guard: blocks until /mnt/<letter> is mounted
  README.md            FUSE-specific documentation
bpf/
  ugow.bpf.c          eBPF LSM program
  ugow.h               Shared types (grant_key struct)
  ugow_manage.py       BPF loader and map manager
  Makefile              Builds ugow.bpf.o from kernel BTF
  README.md            BPF-specific documentation
kmod/
  ugow_lsm.c           Compiled-in LSM module (custom kernel)
  Kconfig               Kernel config entry
  Makefile              Kbuild makefile
  README.md            kmod-specific documentation
tests/
  conftest.py           Shared pytest fixtures
  test_permstore.py     Permission store unit tests
  test_shim_ops.py      FUSE shim operation tests
  test_cli.py           CLI and integration tests
  test_path_conversion.py  Path conversion tests
  test_security.py      Denial and privilege-bit regression tests
```

---

## Name

*Originally: **U**ser **G**roup **O**ther **W**indows -- because that's the Unix permission model this extends. Rebranded to something that sounds like it belongs on a resume.*

## License

MIT
