# Kernel Module

A Linux Security Module that enforces W-bit permissions directly in the kernel VFS layer for 9P (DrvFs) mounts in WSL2.

!!! warning "Requires a custom WSL2 kernel build"
    For stock kernels, use [BPF mode](bpf.md) instead -- it provides the same kernel-level enforcement without a custom build.

## Building

### 1. Clone the WSL2 kernel

```bash
git clone https://github.com/microsoft/WSL2-Linux-Kernel.git
cd WSL2-Linux-Kernel
git checkout linux-msft-wsl-6.6.y   # or latest stable branch
```

### 2. Copy the UGOW LSM source

```bash
cp -r /path/to/UGOW/kmod/ security/ugow/
```

### 3. Wire it into the kernel build

Add to `security/Makefile`:

```makefile
subdir-$(CONFIG_SECURITY_UGOW) += ugow
obj-$(CONFIG_SECURITY_UGOW) += ugow/
```

Add to `security/Kconfig`:

```kconfig
source "security/ugow/Kconfig"
```

### 4. Enable in kernel config

```bash
# Start from the WSL2 default config
cp Microsoft/config-wsl .config

# Enable the LSM
scripts/config --enable CONFIG_SECURITY_UGOW

# Add "ugow" to the LSM order
scripts/config --set-str CONFIG_LSM "landlock,lockdown,yama,loadpin,safesetid,integrity,ugow"

make -j$(nproc)
```

### 5. Install the custom kernel

Copy the built kernel to Windows and point WSL at it:

```powershell
# From PowerShell
Copy-Item \\wsl$\Ubuntu\path\to\WSL2-Linux-Kernel\vmlinux C:\Users\you\wsl-kernel\vmlinux
```

Create or edit `%USERPROFILE%\.wslconfig`:

```ini
[wsl2]
kernel=C:\\Users\\you\\wsl-kernel\\vmlinux
```

Restart WSL:

```powershell
wsl --shutdown
```

## Usage

Once booted with the custom kernel, grants are managed via securityfs:

```bash
# Grant UID 9500 write access to /mnt/c/data
echo "9500 /mnt/c/data" | sudo tee /sys/kernel/security/ugow/grant

# Revoke it
echo "9500 /mnt/c/data" | sudo tee /sys/kernel/security/ugow/revoke

# List all grants
cat /sys/kernel/security/ugow/grants
```

The `ugow` CLI auto-detects the kmod backend and syncs grants to securityfs automatically:

```bash
sudo ugow allow 9500 /mnt/c/data
sudo ugow deny  9500 /mnt/c/data
```

## How It Works

The LSM hooks into the kernel's VFS layer at these points:

| Hook | Enforces |
|------|----------|
| `inode_permission` | W-bit on any write-access permission check |
| `file_open` | W-bit when opening a file for writing |
| `inode_create` | Parent W-bit for file creation |
| `inode_link` | Parent W-bit for hard link creation |
| `inode_unlink` | W-bit for file deletion |
| `inode_symlink` | Parent W-bit for symlink creation |
| `inode_mkdir` | Parent W-bit for directory creation |
| `inode_rmdir` | W-bit for directory removal |
| `inode_rename` | Source W-bit + destination parent W-bit |

Enforcement only activates on superblocks with filesystem type `9p` (how WSL2 mounts Windows drives). All other filesystems are unaffected.

Grants are stored in a kernel hash table with RCU-based read access for lock-free lookups on the hot path. Grant inheritance walks up the directory tree, so a grant on `/mnt/c/data` covers `/mnt/c/data/sub/file.txt`.
