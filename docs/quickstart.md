# Quick Start

## Prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv fuse libfuse2
```

For BPF mode, also install:

```bash
sudo apt install -y clang linux-tools-generic
```

## Install

=== "FUSE mode (default)"

    The easiest option -- works on any stock WSL2 kernel.

    ```bash
    sudo ./setup.sh
    ```

=== "BPF mode"

    Faster, kernel-level enforcement. Requires stock WSL2 kernel 6.6+ and BPF LSM enabled.

    ```bash
    sudo ./setup.sh --mode bpf
    ```

    !!! note "BPF LSM must be enabled first"
        See the [BPF mode prerequisites](bpf.md#prerequisites) for the one-time `.wslconfig` setup.

The installer handles everything: CLI, permission store, Python venv, systemd units, and `wsl.conf` configuration. Drive C: is enabled by default.

## Grant Write Access

```bash
# Grant a user by name
sudo ugow allow ubuntu /mnt/c/docker

# Or by UID
sudo ugow allow 9500 /mnt/c/data
```

Grants are inherited -- granting `/mnt/c/docker` covers everything underneath it.

## Check Permissions

```bash
# Check your own access (uses SUDO_UID)
sudo ugow check /mnt/c/docker

# Check a specific user
sudo ugow check --user 9500 /mnt/c/data

# See who can write to a path
sudo ugow status /mnt/c/docker

# List all grants
sudo ugow list
```

## Manage Drives

```bash
# Enable UGOW on another drive
sudo ugow mount d

# List active drives
sudo ugow drives

# Disable UGOW on a drive
sudo ugow unmount d
```

These commands work the same regardless of whether FUSE or BPF mode is installed.

## Use with Docker

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

## Revoke Access

```bash
sudo ugow deny ubuntu /mnt/c/docker
```

## Uninstall

```bash
sudo ./setup.sh --uninstall
```

This stops all services, removes installed files and BPF pins, and reloads systemd. The permission database (`/var/lib/ugow/wperm.db`) is preserved -- delete it manually with `sudo rm -rf /var/lib/ugow` if desired.

Run `wsl --shutdown` from Windows afterwards to apply `wsl.conf` changes.
