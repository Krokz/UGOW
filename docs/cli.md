# CLI Reference

All commands require root (`sudo`). The CLI auto-detects the active backend, but only `allow`, `deny`, and `sync` write to a kernel backend -- `check`, `status`, and `list` read the SQLite store alone, and `mount`/`unmount`/`drives` operate on drive registration rather than grants.

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

The grant is pushed to every active kernel backend *before* it is committed to SQLite. If a backend refuses it, nothing is recorded and the command exits `1` -- so `ugow check` can never report a permission the kernel will deny.

!!! warning "BPF mode requires the path to exist"
    BPF grants are keyed by inode, so `ugow allow` on a path that does not exist yet fails the whole command. Create the path first, then grant it. See [BPF caveats](bpf.md#caveats-inode-keyed-grants).

In BPF mode, `allow` also widens the path's Unix mode if it would block writes at the DAC layer before the LSM hooks run, recording the original mode so `deny` can put it back.

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

The revoke order is the reverse of `allow`: SQLite first, then the kernel backends, so a partial failure errs toward denying rather than leaving a stale permission. If a backend reports an error the command still revokes but exits `1` with a warning.

In BPF mode, once no UID holds a grant on the path, `deny` also restores the Unix mode that `allow` widened.

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

## `ugow sync`

Replay every SQLite grant into the active kernel backends.

```bash
sudo ugow sync
```

The BPF map and the kmod's grant table live in kernel memory and are lost on every `wsl --shutdown`, so they have to be repopulated from the authoritative SQLite store. `ugow-sync.service` is installed and enabled by default and runs this at boot; you only need to invoke it by hand after editing the database directly or after a backend was restarted independently.

If no kernel backend is active the command reports that there is nothing to sync and exits `0`. In BPF mode it delegates to `ugow_manage.py sync`, which flushes stale map entries first. In kmod mode, grants whose path no longer exists are skipped (the device cannot be resolved without it) and reported as such; the SQLite grant stands and applies the next time `sync` runs. Any other backend error makes the command exit `1`.

---

## `ugow acl-cleanup`

Remove mirrored Windows `wsl_<UID>` users that no longer hold any grant.

```bash
sudo ugow acl-cleanup
```

ACL mirroring creates a Windows local user per granted UID. Revoking the last grant for a UID drops its NTFS ACEs but leaves the account behind; this command lists the host's `wsl_*` users and deletes the ones whose UID has zero grants in the store. It has no effect if you have never used `--mirror-acl`.

---

## `ugow mount`

Enable UGOW enforcement on a Windows drive.

```bash
sudo ugow mount <drive>
```

| Argument | Description |
|----------|-------------|
| `drive` | Drive letter (e.g. `d`, `e`, `f`) |

In FUSE mode, this starts a systemd unit for the drive. In BPF mode, this registers the device in the BPF target map and records the drive letter in `/var/lib/ugow/drives`, so it is re-registered at the next boot -- device numbers are reassigned on every WSL restart, and a drive left out would come back unenforced.

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

In FUSE mode, this stops the systemd unit and re-mounts the drive as standard DrvFs. In BPF mode, this removes the device from the BPF target map and drops the drive letter from `/var/lib/ugow/drives`.

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
