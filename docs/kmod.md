# Kernel Module

!!! danger "Experimental and unverified"
    The kernel module backend is **not covered by the installer** and has **never been compiled or booted** against a real WSL2 kernel. The source has been substantially rewritten and reviewed, but nothing here has been validated on hardware -- treat every claim below as intent rather than observed behaviour. For kernel-level enforcement today, use [BPF mode](bpf.md).

A Linux Security Module that enforces W-bit permissions directly in the kernel VFS layer, on the mounted filesystems userspace has registered for enforcement -- in practice the Windows drives WSL2 mounts under `/mnt`.

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

# Enable the LSM (depends on SECURITY and SECURITYFS)
scripts/config --enable CONFIG_SECURITY_UGOW

# Optional: gate root as well. Default is y (root exempt).
# scripts/config --disable CONFIG_SECURITY_UGOW_ROOT_EXEMPT

# Add "ugow" to the LSM order, keeping the WSL2 defaults intact
scripts/config --set-str CONFIG_LSM "landlock,lockdown,yama,loadpin,safesetid,integrity,apparmor,bpf,ugow"

make -j$(nproc)
```

!!! warning "`lsm=` on the kernel command line overrides `CONFIG_LSM` entirely"

    If `%USERPROFILE%\.wslconfig` sets `kernelCommandLine = lsm=...`, the kernel
    ignores `CONFIG_LSM` and enables only the modules named there -- so `ugow`
    is silently skipped and nothing is enforced, no matter how the kernel was
    configured. The BPF setup instructions tell you to add exactly such a line,
    so this is easy to hit if you have used both backends.

    Either remove the `lsm=` line, or append `,ugow` to it. Keep `apparmor` in
    the list (snapd and Docker confinement depend on it), and keep `bpf` if you
    may go back to the BPF backend.

    Check what actually loaded:

    ```bash
    cat /sys/kernel/security/lsm
    ```

| Kconfig option | Default | Effect |
|----------------|---------|--------|
| `CONFIG_SECURITY_UGOW` | `n` | Builds the LSM in. Depends on `SECURITY` and `SECURITYFS` -- securityfs is the only control interface, so without it the module has no way to receive grants |
| `CONFIG_SECURITY_UGOW_ROOT_EXEMPT` | `y` | Processes whose filesystem UID is 0 bypass W-bit checks, matching the BPF backend. Say `n` only if you intend root itself to be gated -- system services, package managers and container runtimes routinely write to mounted Windows drives as root and will start receiving `EACCES` unless uid 0 is granted explicitly |

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

## securityfs Interface

Once booted with the custom kernel, everything is driven through four files under `/sys/kernel/security/ugow/`. All writes require `CAP_SYS_ADMIN`.

| File | Mode | Purpose |
|------|------|---------|
| `devices` | `0600` | Write `+major:minor` to enforce a device, `-major:minor` to stop. Read to list enforced devices |
| `grant` | `0200` | Write `uid major:minor path` to add a grant |
| `revoke` | `0200` | Write `uid major:minor path` to remove one |
| `grants` | `0400` | Read to list all current grants as `uid<TAB>major:minor<TAB>path` |

Two properties of the format matter:

- **Enforcement is opt-in per device.** Nothing is gated until a device is registered via `devices`, so enabling the LSM cannot by itself make a filesystem read-only. This mirrors the BPF backend's `target_devs` map and avoids guessing at filesystem type names, which have changed across WSL releases (`9p`, `drvfs`, `virtiofs`).
- **Paths are superblock-relative, not absolute.** The kernel derives a dentry's path with `dentry_path_raw()`, which stops at the filesystem root -- so the file a user calls `/mnt/c/docker/f` is `/docker/f` here. Pairing the relative path with the superblock's device keeps grants unambiguous when several drives are mounted, since `/docker` on C: and `/docker` on D: differ in device. Userspace does the mountpoint arithmetic and sends both halves.

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

The `ugow` CLI auto-detects the kmod backend, resolves the mountpoint and device for you, registers the device on the first grant, and writes the relative path:

```bash
sudo ugow allow 9500 /mnt/c/data
sudo ugow deny  9500 /mnt/c/data
```

Because the device has to be resolved with `stat()`, kmod grants and revokes through the CLI need the path to exist even though the grant itself is stored as a string. `ugow sync` skips and reports grants whose path is currently missing; they apply the next time it runs.

## How It Works

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

`inode_link` checks both ends because the ancestor walk starts from whichever name is used: without the source check, linking a protected file into a granted directory would make it writable through its second name. `inode_setattr` exists for the same reason `chmod` is gated in the FUSE shim -- ungated, it would let any caller re-mode files they hold no grant on.

Every gated operation first checks that the superblock's device is registered and that the caller is not exempt, both of which are cheap and happen before any allocation. Grants live in a kernel hash table with RCU-based read access for lock-free lookups on the hot path. Inheritance walks up the relative path component by component, so a grant on `/data` covers `/data/sub/file.txt`, and a grant on `/` covers the whole device.

The hooks are armed only *after* securityfs is set up successfully. LSM hooks cannot be unregistered, so arming first and then failing to create the control interface would leave enforcement active with no way to add a grant.

## Persistence Across Reboots

The grant table lives in kernel memory and is lost on every `wsl --shutdown`. `ugow-sync.service` -- installed and enabled by default by `setup.sh`, and conditional on `/sys/kernel/security/ugow/grant` existing -- runs `ugow sync` at boot to replay the SQLite store. Device registration happens implicitly, since the CLI registers a grant's device before writing the grant.

## Overhead and correctness vs BPF

The kmod matches on the **path string**, whereas BPF mode keys on
`(inode, device, uid)`. That difference cuts both ways:

- **Per-operation cost is higher than BPF.** Each gated op allocates a 4 KB
  buffer, reconstructs the superblock-relative path with `dentry_path_raw()`,
  then hashes and `strcmp`s the path at each ancestor level. BPF does
  allocation-free integer map lookups instead. Both remain *kernel-resident* --
  so both are far cheaper than the FUSE shim's userspace round-trip, and both
  are "near zero" relative to it -- but kmod does strictly more work per op
  than BPF.
- **In exchange, it avoids BPF's inode-keying caveats.** Path matching survives
  delete-and-recreate, has no fixed inheritance-depth cap, and the stored grant
  does not depend on an inode remaining valid. See the
  [BPF caveats](bpf.md#caveats-inode-keyed-grants).
