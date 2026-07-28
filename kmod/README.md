# UGOW Kernel LSM

A Linux Security Module that enforces W-bit permissions directly in the kernel
VFS layer, on the mounted filesystems userspace has registered for enforcement
-- in practice the Windows drives WSL2 mounts under `/mnt`. Unlike the FUSE
shim, this cannot be bypassed from userspace.

> **Experimental and unverified:** this backend is not covered by `setup.sh` and
> has never been compiled or booted against a real WSL2 kernel. The source has
> been substantially rewritten and reviewed, but nothing below has been
> validated on hardware -- treat it as intent rather than observed behaviour.

> **Note:** This requires a custom WSL2 kernel build. For stock kernels, use
> the [BPF mode](../bpf/README.md) instead -- it provides the same kernel-level
> enforcement without a custom build.

---

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

# Enable the LSM (depends on SECURITY and SECURITYFS)
scripts/config --enable CONFIG_SECURITY_UGOW

# Optional: gate root as well. CONFIG_SECURITY_UGOW_ROOT_EXEMPT defaults to y,
# which exempts uid 0 exactly as the BPF backend does.
# scripts/config --disable CONFIG_SECURITY_UGOW_ROOT_EXEMPT

# Add "ugow" to the LSM order so it loads at boot, keeping the WSL2 defaults
scripts/config --set-str CONFIG_LSM "landlock,lockdown,yama,loadpin,safesetid,integrity,apparmor,bpf,ugow"

make -j$(nproc)
```

**`CONFIG_LSM` is ignored if the kernel command line sets `lsm=`.** A
`kernelCommandLine = lsm=...` entry in `%USERPROFILE%\.wslconfig` -- which the
BPF setup instructions tell you to add -- supersedes `CONFIG_LSM` completely,
so `ugow` is silently skipped and nothing is enforced. Either drop that line or
append `,ugow` to it, keeping `apparmor` (snapd and Docker confinement need it)
and `bpf`. Verify with `cat /sys/kernel/security/lsm`.

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

---

## Usage

Once booted with the custom kernel, everything is driven through four files
under `/sys/kernel/security/ugow/`. All writes require `CAP_SYS_ADMIN`.

| File | Mode | Purpose |
|------|------|---------|
| `devices` | `0600` | Write `+major:minor` to enforce a device, `-major:minor` to stop. Read to list enforced devices |
| `grant` | `0200` | Write `uid major:minor path` to add a grant |
| `revoke` | `0200` | Write `uid major:minor path` to remove one |
| `grants` | `0400` | Read to list all current grants |

Two properties of the format matter:

- **Enforcement is opt-in per device.** Nothing is gated until a device is
  registered via `devices`, so enabling the LSM cannot by itself make a
  filesystem read-only. This mirrors the BPF backend's `target_devs` map and
  avoids guessing at filesystem type names, which have changed across WSL
  releases (`9p`, `drvfs`, `virtiofs`).
- **Paths are superblock-relative, not absolute.** `dentry_path_raw()` stops at
  the filesystem root, so the file a user calls `/mnt/c/docker/f` is `/docker/f`
  here. Pairing it with the superblock's device keeps `/docker` on C: distinct
  from `/docker` on D:. Userspace does the mountpoint arithmetic and sends both
  halves.

Assuming `/mnt/c` is device `0:45`:

```bash
# Enforce the device backing /mnt/c
echo "+0:45" | sudo tee /sys/kernel/security/ugow/devices

# Grant UID 9500 write access to /mnt/c/data
echo "9500 0:45 /data" | sudo tee /sys/kernel/security/ugow/grant

# Revoke it
echo "9500 0:45 /data" | sudo tee /sys/kernel/security/ugow/revoke

# List all grants and enforced devices
cat /sys/kernel/security/ugow/grants
cat /sys/kernel/security/ugow/devices
```

The `ugow` CLI auto-detects the kmod backend, resolves the mountpoint and
device for you, registers the device on the first grant, and writes the
relative path -- so you can also use:

```bash
sudo ugow allow 9500 /mnt/c/data
sudo ugow deny  9500 /mnt/c/data
```

Because the device is resolved with `stat()`, grants and revokes through the CLI
need the path to exist even though the grant itself is stored as a string.

---

## Persistence across reboots

The kmod's grant table lives in kernel memory and is lost on every
`wsl --shutdown` or reboot. The `ugow` CLI stores all grants in SQLite
(`/var/lib/ugow/wperm.db`), so they survive reboots -- but the kernel
needs to be re-populated on startup.

### Option A: systemd service (default)

`setup.sh` installs and enables `ugow-sync.service` in both modes, so this is
already in place after a normal install. To wire it up by hand:

```bash
sudo cp /path/to/UGOW/kmod/ugow-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ugow-sync.service
```

This runs `ugow sync` on every boot, replaying all SQLite grants into whichever
kernel backend is present -- it activates when either the kmod's or the BPF
backend's control file exists
(`ConditionPathExists=|/sys/kernel/security/ugow/grant`,
`ConditionPathExists=|/sys/fs/bpf/ugow/grants`). Device registration happens
implicitly, since the CLI registers a grant's device before writing the grant.
Grants whose path no longer exists are skipped and reported; they apply the next
time `sync` runs.

### Option B: manual sync

After any reboot, run:

```bash
sudo ugow sync
```

---

## How it works

The LSM hooks into the kernel's VFS layer at these points:

| Hook | Enforces |
|------|----------|
| `inode_permission` | W-bit on any write-access permission check |
| `file_open` | W-bit when opening a file for writing |
| `inode_create` | Parent W-bit for file creation |
| `inode_link` | Destination parent W-bit **and** W-bit on the existing file |
| `inode_unlink` | Parent W-bit for file deletion |
| `inode_symlink` | Parent W-bit for symlink creation |
| `inode_mkdir` | Parent W-bit for directory creation |
| `inode_rmdir` | Parent W-bit for directory removal |
| `inode_rename` | Source parent W-bit + destination parent W-bit |
| `inode_setattr` | W-bit for `chmod`, `chown`, `truncate`, and explicit timestamp changes |

`inode_link` checks both ends because the ancestor walk starts from whichever
name is used: without the source check, linking a protected file into a granted
directory would make it writable through its second name.

Enforcement only activates on devices registered through the `devices` file. All
other filesystems are unaffected, and a freshly booted system is fully writable
until grants have been replayed.

Grants are stored in a kernel hash table with RCU-based read access for
lock-free lookups on the hot path. Inheritance walks up the superblock-relative
path, so a grant on `/data` covers `/data/sub/file.txt`, and a grant on `/`
covers the whole device.

The hooks are armed only *after* securityfs is set up successfully. LSM hooks
cannot be unregistered, so arming first and then failing to create the control
interface would leave enforcement active with no way to add a grant.
