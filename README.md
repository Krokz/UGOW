# UGOWShim

`UGOWShim` is a FUSE-based shim for Windows Subsystem for Linux (WSL) that extends the standard Unix permission model (User/Group/Other) with an additional **W-bit** controlling Windows-side write permissions per Linux UID. When a Linux user is granted the W-bit on a path, all write operations under that path are enforced by the shim and mirrored to NTFS ACLs on the Windows host.

---

## Features

* **Transparent overlay**: mounts over an existing Windows-Drived filesystem (e.g. `/mnt/c`) so all processes—including Docker containers—go through the shim.
* **W-bit enforcement**: allows or denies `open`, `create`, `truncate`, `mkdir`, `unlink`, `rmdir`, and `rename` calls based on a JSON-backed permission map.
* **Permission inheritance**: a grant on a directory applies to all descendants.
* **Root remapping**: root in WSL is remapped to the user who launched the shim, so root inherits the same W-bit rights.
* **ACL mirroring**: best-effort creation of corresponding Windows local users (`wsl_<UID>`) and NTFS ACL grants via PowerShell/`icacls`.
* **CLI manager**: root can explicitly grant or revoke W-bit for any UID on any path using `--grant` and `--revoke` flags.

---

## Installation

1. **Install dependencies**:

   ```bash
   sudo apt update
   sudo apt install -y fuse libfuse2 python3-pip
   sudo pip3 install fusepy xattr
   ```

2. **Copy `shim.py`** into a system location:

   ```bash
   sudo install -m 755 shim.py /usr/local/bin/ugowshim
   ```

3. **Enable FUSE**:

   * Uncomment `user_allow_other` in `/etc/fuse.conf`.
   * Add your WSL user to the `fuse` group:

     ```bash
     sudo usermod -aG fuse $USER
     ```

4. **Prepare metadata store**:

   ```bash
   sudo mkdir -p /var/lib/wsl-fuse-shim
   sudo chown $USER /var/lib/wsl-fuse-shim
   ```

---

## Usage

### 1. Mount a drive

```bash
ugowshim /mnt/c /mnt/c-shim \
  -- foreground --allow_other --default_permissions
```

This mounts the shim over `/mnt/c`, exposing it at `/mnt/c-shim`. All operations under `/mnt/c-shim` are now gated by the W-bit logic.

### 2. Grant/Revoke W-bit via `chmod`

As your WSL user:

```bash
# Grant W-bit on /mnt/c-shim/data
chmod +t /mnt/c-shim/data

# Revoke W-bit
chmod -t /mnt/c-shim/data
```

### 3. Explicit CLI grants (root only)

```bash
# Grant UID 9500 write rights on a specific path
sudo ugowshim --grant 9500 /mnt/c-shim/userdata

# Revoke
sudo ugowshim --revoke 9500 /mnt/c-shim/userdata
```

### 4. Using with Docker

When launching containers that mount Windows paths, point them at the shim mountpoint:

```bash
docker run --user 9500 \
  -v /mnt/c-shim/userdata:/data \
  my-image
```

The container (UID 9500) will be able to write under `/data` only if you granted its W-bit.

---

## Internals

* **Metadata**: stored in `/var/lib/wsl-fuse-shim/wperm.json` as a map of paths → list of UIDs.
* **Path conversion**: Linux paths under `/mnt/<drive>/…` are translated to Windows paths (e.g. `C:\…`) for ACL commands.
* **Sticky-bit**: `chmod +t`/`-t` toggles grant/revoke behavior in the FUSE `chmod()` handler.

---

## Future Work

* Migrate JSON store to SQLite for scalability and ACID guarantees.
* Support dynamic discovery and auto-mount of all `/mnt/<letter>` volumes via systemd templates.
* Refine ACL mirroring to handle edge cases and user-management policies.

---

## License

MIT © Your Name
