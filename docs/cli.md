# CLI Reference

All commands require root (`sudo`). The CLI auto-detects the active backend and syncs grants to all active stores.

## `ugow allow`

Grant write permission to a user on a path.

```bash
sudo ugow allow <user> <path>
```

| Argument | Description |
|----------|-------------|
| `user` | Username or numeric UID |
| `path` | Absolute path to grant write access on |

Grants are inherited -- granting a directory covers all files and subdirectories beneath it.

```bash
sudo ugow allow ubuntu /mnt/c/docker
sudo ugow allow 9500 /mnt/c/data
```

??? info "ACL mirroring"
    Pass `--mirror-acl` to also create a corresponding NTFS ACL grant on the Windows side via PowerShell. Requires an elevated (Administrator) Windows Terminal session.

    ```bash
    sudo ugow allow --mirror-acl ubuntu /mnt/c/docker
    ```

    This creates a Windows local user `wsl_<UID>` and grants it full control on the Windows path via `icacls`.

---

## `ugow deny`

Revoke write permission from a user on a path.

```bash
sudo ugow deny <user> <path>
```

| Argument | Description |
|----------|-------------|
| `user` | Username or numeric UID |
| `path` | Absolute path to revoke write access from |

```bash
sudo ugow deny ubuntu /mnt/c/docker
```

---

## `ugow check`

Check if a user can write to a path.

```bash
sudo ugow check [--user <user>] <path>
```

| Argument | Description |
|----------|-------------|
| `path` | Path to check |
| `--user` | Optional. Check a specific user instead of yourself |

Without `--user`, checks the calling user's permissions (via `SUDO_UID`), not root's.

```bash
sudo ugow check /mnt/c/docker
sudo ugow check --user 9500 /mnt/c/data
```

---

## `ugow status`

Show which users have write access to a path.

```bash
sudo ugow status <path>
```

Displays all grants that cover the given path (direct grants and inherited grants from parent directories).

```bash
sudo ugow status /mnt/c/docker
```

---

## `ugow list`

List all grants in the permission store.

```bash
sudo ugow list
```

Shows a table of all user/path grants and the active backends (sqlite, bpf, kmod).

---

## `ugow mount`

Enable UGOW enforcement on a Windows drive.

```bash
sudo ugow mount <drive>
```

| Argument | Description |
|----------|-------------|
| `drive` | Drive letter (e.g. `d`, `e`, `f`) |

In FUSE mode, this starts a systemd unit for the drive. In BPF mode, this registers the device in the BPF target map.

```bash
sudo ugow mount d
```

---

## `ugow unmount`

Disable UGOW enforcement on a Windows drive.

```bash
sudo ugow unmount <drive>
```

| Argument | Description |
|----------|-------------|
| `drive` | Drive letter (e.g. `d`, `e`, `f`) |

In FUSE mode, this stops the systemd unit and re-mounts the drive as standard DrvFs. In BPF mode, this removes the device from the BPF target map.

```bash
sudo ugow unmount d
```

---

## `ugow drives`

List all drives currently managed by UGOW.

```bash
sudo ugow drives
```

Shows active FUSE units or BPF-registered devices, depending on the installed mode.

---

## Hidden Flags

These flags are available but hidden from `--help`:

| Flag | Description |
|------|-------------|
| `--db <path>` | Override the SQLite database path (default: `/var/lib/ugow/wperm.db`) |
| `--mirror-acl` | Enable NTFS ACL mirroring on `allow`/`deny` operations |
