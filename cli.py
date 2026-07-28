#!/usr/bin/env python3
"""
ugow -- unified CLI for UGOW W-bit permission management.

Usage:
    ugow allow <user> <path>     Grant write permission
    ugow deny  <user> <path>     Revoke write permission
    ugow check <path>            Check if you can write to a path
    ugow status <path>           Show who can write to a path
    ugow list                    List all grants
    ugow sync                    Sync SQLite grants into kernel backends
    ugow acl-cleanup             Drop mirrored Windows users with no grants
    ugow mount <drive>           Enable UGOW on a Windows drive
    ugow unmount <drive>         Disable UGOW on a Windows drive
    ugow drives                  List active UGOW-managed drives
"""

import os
import sys
import pwd
import struct
import subprocess
import argparse

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in [_HERE, "/opt/ugow/lib"]:
    if os.path.isfile(os.path.join(_p, "permstore.py")):
        sys.path.insert(0, _p)
        break
from permstore import (  # noqa: E402
    AclMirrorUnavailable,
    DEFAULT_DB_PATH,
    PermStore,
    _path_ancestors,
    kernel_dev,
)

BPF_PIN = "/sys/fs/bpf/ugow"
KMOD_SECURITYFS = "/sys/kernel/security/ugow"
UGOW_MANAGE = "/opt/ugow/lib/ugow_manage.py"
UGOW_PYTHON = "/opt/ugow/venv/bin/python"


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

def _bpf_active():
    return os.path.exists(f"{BPF_PIN}/grants")


def _kmod_active():
    return os.path.exists(f"{KMOD_SECURITYFS}/grant")


def _active_backends():
    found = ["sqlite"]
    if _bpf_active():
        found.append("bpf")
    if _kmod_active():
        found.append("kmod")
    return found


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def require_root(action):
    """Exit with an error if the current user is not root."""
    if os.getuid() != 0:
        print(
            f"Error: 'ugow {action}' requires root privileges.\n"
            f"  Run with: sudo ugow {action} ...",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# User resolution -- accept "ubuntu" or "1000"
# ---------------------------------------------------------------------------

def resolve_user(name_or_uid):
    """Return (uid, display_name) from a username or numeric UID string."""
    try:
        uid = int(name_or_uid)
        try:
            return uid, pwd.getpwuid(uid).pw_name
        except KeyError:
            return uid, str(uid)
    except ValueError:
        pass
    try:
        pw = pwd.getpwnam(name_or_uid)
        return pw.pw_uid, pw.pw_name
    except KeyError:
        print(f"Error: unknown user '{name_or_uid}'", file=sys.stderr)
        sys.exit(1)


def uid_to_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


# ---------------------------------------------------------------------------
# BPF map helpers (only called when BPF backend is active)
# ---------------------------------------------------------------------------

def _run(cmd):
    """Run a helper binary, turning a missing binary into a readable error."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return subprocess.CompletedProcess(
            cmd, 127, "", f"{cmd[0]} not found on PATH"
        )


def _bpf_key_hex(uid, path):
    """Encode the (ino, dev, uid) grant key, or None if the path is missing."""
    try:
        st = os.stat(path)
    except OSError as e:
        return None, str(e)
    raw = struct.pack("=QII", st.st_ino, kernel_dev(st.st_dev), uid)
    return " ".join(f"0x{b:02x}" for b in raw), None


def _bpf_grant(uid, path):
    """Add a BPF map entry. Returns None on success or an error string."""
    key_hex, err = _bpf_key_hex(uid, path)
    if key_hex is None:
        return (f"BPF grants are keyed by inode, so the path must exist: {err}")
    result = _run(
        ["bpftool", "map", "update", "pinned", f"{BPF_PIN}/grants",
         "key", "hex"] + key_hex.split() + ["value", "hex", "0x01"]
    )
    if result.returncode != 0:
        return f"BPF grant failed: {result.stderr.strip()}"
    return None


def _bpf_revoke(uid, path):
    """Delete a BPF map entry. Returns None on success or an error string."""
    key_hex, err = _bpf_key_hex(uid, path)
    if key_hex is None:
        # Nothing to remove: an entry can only exist for a path that resolved.
        return None
    result = _run(
        ["bpftool", "map", "delete", "pinned", f"{BPF_PIN}/grants",
         "key", "hex"] + key_hex.split()
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "No such file or directory" in stderr or "ENOENT" in stderr:
            return None
        return f"BPF revoke failed: {stderr}"
    return None


# ---------------------------------------------------------------------------
# kmod securityfs helpers
# ---------------------------------------------------------------------------

def _mount_point(path):
    """Innermost mount point containing *path*."""
    path = os.path.abspath(path)
    while True:
        if os.path.ismount(path):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return path
        path = parent


def _kmod_key(path):
    """Return (dev, superblock-relative path) for *path*.

    The kmod derives a dentry's path with dentry_path_raw(), which stops at the
    filesystem root -- so /mnt/c/docker is /docker there. Grants must be
    expressed the same way, paired with the device so identical relative paths
    on different drives stay distinct.
    """
    st = os.stat(path)
    dev = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    mount = _mount_point(path)
    rel = path if mount == "/" else path[len(mount):]
    if not rel.startswith("/"):
        rel = "/" + rel
    return dev, os.path.normpath(rel)


def _kmod_securityfs_write(name, payload):
    """Write one line to a kmod securityfs file. Returns an error or None."""
    try:
        with open(f"{KMOD_SECURITYFS}/{name}", "w") as f:
            f.write(payload + "\n")
    except PermissionError:
        return f"kmod {name} failed: permission denied (need root?)"
    except FileNotFoundError:
        return f"kmod {name} failed: securityfs interface not found"
    except OSError as e:
        return f"kmod {name} failed: {e}"
    return None


def _kmod_register_device(path):
    """Register the device backing *path* for enforcement."""
    try:
        dev, _ = _kmod_key(path)
    except OSError as e:
        return f"kmod device registration failed: {e}"
    return _kmod_securityfs_write("devices", f"+{dev}")


def _kmod_write(action, uid, path):
    """Push a grant/revoke to the kmod. Returns an error string or None."""
    try:
        dev, rel = _kmod_key(path)
    except OSError as e:
        return f"kmod {action} needs the path to exist to resolve its device: {e}"
    # A grant is meaningless unless the device is enforced.
    if action == "grant":
        err = _kmod_register_device(path)
        if err:
            return err
    return _kmod_securityfs_write(action, f"{uid} {dev} {rel}")


# ---------------------------------------------------------------------------
# DAC helpers for BPF mode
# ---------------------------------------------------------------------------

def _relax_dac_for_bpf(store, path):
    """Ensure DAC allows writes on *path* so the BPF LSM is the sole gate.

    On DrvFs, default permissions are rwxrwxrwx.  Paths that were manually
    restricted (chmod / chown) block writes at the DAC layer before BPF even
    runs.  The original mode is recorded first so `ugow deny` can put it back:
    a widened mode left behind after the hooks detach would be an open door.
    """
    try:
        st = os.stat(path)
        if st.st_mode & 0o222 == 0o222:
            return
        store.remember_dac_mode(path, st.st_mode)
        os.chmod(path, st.st_mode | 0o222)
    except OSError as e:
        print(f"  warning: could not relax DAC permissions on {path}: {e}",
              file=sys.stderr)


def _restore_dac_after_bpf(store, path):
    """Undo _relax_dac_for_bpf once no uid holds a grant on *path*."""
    if store.has_any_grant(path):
        return
    mode = store.forget_dac_mode(path)
    if mode is None:
        return
    try:
        os.chmod(path, mode & 0o7777)
    except OSError as e:
        print(f"  warning: could not restore permissions on {path}: {e}",
              file=sys.stderr)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_allow(args):
    require_root("allow")
    uid, username = resolve_user(args.user)
    path = os.path.abspath(args.path)

    store = PermStore(db_path=args.db, mirror_acl=args.mirror_acl)

    # Kernel backends first: committing to SQLite before they accept the grant
    # would leave `ugow check` reporting a permission the kernel will refuse.
    errors = []
    if _bpf_active():
        err = _bpf_grant(uid, path)
        if err:
            errors.append(err)
    if _kmod_active():
        err = _kmod_write("grant", uid, path)
        if err:
            errors.append(err)

    if errors:
        print(f"Error: grant not applied for {username} (uid={uid}) on {path}",
              file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        sys.exit(1)

    store.grant(path, uid)
    if _bpf_active():
        _relax_dac_for_bpf(store, path)

    backends = _active_backends()
    print(f"Allowed: {username} (uid={uid}) can write to {path}")
    if len(backends) > 1:
        print(f"  backends: {', '.join(backends)}")
    store.flush_acl()


def cmd_deny(args):
    require_root("deny")
    uid, username = resolve_user(args.user)
    path = os.path.abspath(args.path)

    store = PermStore(db_path=args.db, mirror_acl=args.mirror_acl)

    # Revoke is the reverse: drop the authoritative record first so a partial
    # failure errs toward denying rather than keeping a stale permission.
    store.revoke(path, uid)

    errors = []
    if _bpf_active():
        err = _bpf_revoke(uid, path)
        if err:
            errors.append(err)
        _restore_dac_after_bpf(store, path)
    if _kmod_active():
        err = _kmod_write("revoke", uid, path)
        if err:
            errors.append(err)

    backends = _active_backends()
    print(f"Denied: {username} (uid={uid}) can no longer write to {path}")
    if len(backends) > 1:
        print(f"  backends: {', '.join(backends)}")
    store.flush_acl()

    if errors:
        print("Warning: revoked in the permission store, but a backend "
              "reported an error:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        sys.exit(1)


def cmd_check(args):
    require_root("check")
    path = os.path.abspath(args.path)

    if hasattr(args, "user") and args.user:
        uid, username = resolve_user(args.user)
    else:
        uid = int(os.environ.get("SUDO_UID", os.getuid()))
        username = uid_to_name(uid)

    store = PermStore(db_path=args.db, mirror_acl=False)
    has = store.has_wbit(path, uid)

    if has:
        print(f"  {username} (uid={uid}) CAN write to {path}")
    else:
        print(f"  {username} (uid={uid}) CANNOT write to {path}")
    sys.exit(0 if has else 1)


def cmd_status(args):
    require_root("status")
    path = os.path.abspath(args.path)
    ancestors = set(_path_ancestors(path))

    store = PermStore(db_path=args.db, mirror_acl=False)
    all_grants = store.list_grants()

    covering = []
    for gpath, guid in all_grants:
        if gpath in ancestors:
            scope = "exact" if gpath == path else f"via {gpath}"
            covering.append((uid_to_name(guid), guid, scope))

    if not covering:
        print(f"No write grants cover {path}")
        return

    print(f"Users who can write to {path}:\n")
    for username, uid, scope in covering:
        print(f"  {username:<16} uid={uid:<6}  ({scope})")
    print()
    backends = _active_backends()
    print(f"Active backends: {', '.join(backends)}")


def cmd_sync(args):
    require_root("sync")
    store = PermStore(db_path=args.db, mirror_acl=False)
    grants = store.list_grants()

    backends = _active_backends()
    has_kmod = _kmod_active()
    has_bpf = _bpf_active()

    if not has_kmod and not has_bpf:
        print("No kernel backend active (kmod or BPF). Nothing to sync.")
        return

    synced = {"kmod": 0, "bpf": 0}
    failed = False

    if has_bpf:
        result = subprocess.run(
            [UGOW_PYTHON, UGOW_MANAGE, "--db", args.db, "sync"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            for line in result.stderr.splitlines():
                if "Synced" in line:
                    try:
                        synced["bpf"] = int(line.split("Synced")[1].split()[0])
                    except (IndexError, ValueError):
                        pass
            print(f"  BPF: synced {synced['bpf']} grants")
        else:
            err = (result.stderr or result.stdout or "").strip()
            print(f"  BPF sync failed: {err}", file=sys.stderr)
            failed = True

    if has_kmod:
        skipped = 0
        for path, uid in grants:
            err = _kmod_write("grant", uid, path)
            if err is None:
                synced["kmod"] += 1
            elif not os.path.exists(path):
                # Nothing to resolve a device from; the SQLite grant stands and
                # will apply once the path exists and sync runs again.
                skipped += 1
            else:
                print(f"  {err}", file=sys.stderr)
                failed = True
        print(f"  kmod: synced {synced['kmod']} grants"
              + (f" ({skipped} skipped -- path missing)" if skipped else ""))

    if failed:
        print(f"\nSync finished with errors. Active backends: {', '.join(backends)}")
        sys.exit(1)
    print(f"\nSync complete. Active backends: {', '.join(backends)}")


def cmd_acl_cleanup(args):
    require_root("acl-cleanup")
    store = PermStore(db_path=args.db, mirror_acl=False)
    store.cleanup_acl()
    print("ACL cleanup complete.")


def cmd_list(args):
    require_root("list")
    store = PermStore(db_path=args.db, mirror_acl=False)
    grants = store.list_grants()

    if not grants:
        print("No grants.")
        return

    print(f"{'User':<16} {'UID':>6}  Path")
    print(f"{chr(0x2500) * 16} {chr(0x2500) * 6}  {chr(0x2500) * 40}")
    for gpath, guid in grants:
        print(f"{uid_to_name(guid):<16} {guid:>6}  {gpath}")

    backends = _active_backends()
    print(f"\nActive backends: {', '.join(backends)}")


# ---------------------------------------------------------------------------
# Drive management (adapts to FUSE or BPF backend)
# ---------------------------------------------------------------------------

UNIT_TEMPLATE = "wsl-fuse-shim@{}.service"
FUSE_TEMPLATE_PATH = "/etc/systemd/system/wsl-fuse-shim@.service"


def _fuse_installed():
    return os.path.exists(FUSE_TEMPLATE_PATH)


def _detect_mode():
    """Return 'fuse', 'bpf', or None."""
    if _fuse_installed():
        return "fuse"
    if _bpf_active():
        return "bpf"
    return None


def _validate_drive(letter):
    letter = letter.lower().rstrip(":")
    if len(letter) != 1 or not letter.isalpha():
        print(f"Error: '{letter}' is not a valid drive letter", file=sys.stderr)
        sys.exit(1)
    return letter


def _require_mode(action):
    mode = _detect_mode()
    if mode is None:
        print(
            f"Error: no UGOW enforcement mode is installed.\n"
            f"  Run 'sudo ./setup.sh' (FUSE) or 'sudo ./setup.sh --mode bpf' first.",
            file=sys.stderr,
        )
        sys.exit(1)
    return mode


def cmd_mount(args):
    require_root("mount")
    mode = _require_mode("mount")
    letter = _validate_drive(args.drive)

    if mode == "fuse":
        service = UNIT_TEMPLATE.format(letter)
        result = subprocess.run(
            ["systemctl", "enable", "--now", service],
        )
        if result.returncode == 0:
            print(f"\nDrive {letter.upper()}: is now managed by UGOW at /mnt/{letter}")
        else:
            sys.exit(result.returncode)

    elif mode == "bpf":
        mount_path = f"/mnt/{letter}"
        if not os.path.isdir(mount_path):
            print(f"Error: {mount_path} does not exist or is not mounted.",
                  file=sys.stderr)
            sys.exit(1)
        result = _run([UGOW_PYTHON, UGOW_MANAGE, "add-device", mount_path])
        if result.returncode == 0:
            print(f"\nDrive {letter.upper()}: is now enforced by UGOW BPF at {mount_path}")
        else:
            print(f"Error: {result.stderr.strip()}", file=sys.stderr)
            sys.exit(result.returncode)


def cmd_unmount(args):
    require_root("unmount")
    mode = _require_mode("unmount")
    letter = _validate_drive(args.drive)

    if mode == "fuse":
        service = UNIT_TEMPLATE.format(letter)
        result = subprocess.run(
            ["systemctl", "disable", "--now", service],
        )
        if result.returncode == 0:
            subprocess.run(
                ["umount", f"/mnt/.{letter}-backing"],
                capture_output=True,
            )
            subprocess.run(
                ["mount", "-t", "drvfs", f"{letter.upper()}:",
                 f"/mnt/{letter}", "-o", "metadata"],
                capture_output=True,
            )
            print(f"\nDrive {letter.upper()}: is no longer managed by UGOW")
            print(f"  Re-mounted as standard DrvFs at /mnt/{letter}")
        else:
            sys.exit(result.returncode)

    elif mode == "bpf":
        mount_path = f"/mnt/{letter}"
        result = _run([UGOW_PYTHON, UGOW_MANAGE, "remove-device", mount_path])
        if result.returncode == 0:
            print(f"\nDrive {letter.upper()}: is no longer enforced by UGOW BPF")
        else:
            print(f"Error: {result.stderr.strip()}", file=sys.stderr)
            sys.exit(result.returncode)


def cmd_drives(args):
    require_root("drives")
    mode = _require_mode("drives")

    if mode == "fuse":
        result = subprocess.run(
            ["systemctl", "list-units", "wsl-fuse-shim@*.service",
             "--plain", "--no-legend", "--all"],
            capture_output=True, text=True,
        )
        lines = [l for l in result.stdout.strip().splitlines() if l.strip()]
        if not lines:
            print("No UGOW-managed drives.")
            return

        print(f"{'Drive':<8} {'Mount':<16} {'Backing':<24} {'Status'}")
        print(f"{'─' * 7} {'─' * 15} {'─' * 23} {'─' * 16}")
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            unit = parts[0]
            active, sub = parts[2], parts[3]
            letter = unit.split("@")[1].split(".")[0]
            status = f"{active} ({sub})"
            print(f"{letter.upper()}:      /mnt/{letter:<12} /mnt/.{letter}-backing       {status}")

    elif mode == "bpf":
        enforced = []
        for letter in "abcdefghijklmnopqrstuvwxyz":
            mount_path = f"/mnt/{letter}"
            if not os.path.isdir(mount_path):
                continue
            try:
                st = os.stat(mount_path)
            except OSError:
                continue
            dev_key = struct.pack("=I", kernel_dev(st.st_dev))
            key_hex = " ".join(f"0x{b:02x}" for b in dev_key)
            result = _run(
                ["bpftool", "map", "lookup", "pinned",
                 f"{BPF_PIN}/target_devs", "key", "hex"] + key_hex.split()
            )
            if result.returncode == 0:
                enforced.append(letter)

        if not enforced:
            print("No UGOW-managed drives (BPF mode).")
            return

        print(f"{'Drive':<8} {'Mount':<16} {'Mode'}")
        print(f"{'─' * 7} {'─' * 15} {'─' * 10}")
        for letter in enforced:
            print(f"{letter.upper()}:      /mnt/{letter:<12} BPF")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="ugow",
        description="UGOW -- W-bit permission manager for WSL2",
        epilog="Examples:\n"
               "  ugow allow ubuntu /mnt/c/docker\n"
               "  ugow deny  ubuntu /mnt/c/docker\n"
               "  ugow check /mnt/c/docker\n"
               "  ugow status /mnt/c/docker\n"
               "  ugow list\n"
               "  ugow sync\n"
               "  ugow mount d\n"
               "  ugow unmount d\n"
               "  ugow drives\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help=argparse.SUPPRESS)
    parser.add_argument("--mirror-acl", action="store_true", help=argparse.SUPPRESS)

    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("allow", help="Grant write permission")
    p.add_argument("user", help="Username or UID")
    p.add_argument("path", help="Path to grant write access on")

    p = sub.add_parser("deny", help="Revoke write permission")
    p.add_argument("user", help="Username or UID")
    p.add_argument("path", help="Path to revoke write access from")

    p = sub.add_parser("check", help="Check if you can write to a path")
    p.add_argument("path", help="Path to check")
    p.add_argument("--user", default=None, help="Check a specific user (requires root)")

    p = sub.add_parser("status", help="Show who can write to a path")
    p.add_argument("path", help="Path to inspect")

    sub.add_parser("list", help="List all grants")
    sub.add_parser("sync", help="Replay SQLite grants into kernel backends (kmod/BPF)")
    sub.add_parser("acl-cleanup",
                   help="Remove mirrored Windows wsl_* users with no grants")

    p = sub.add_parser("mount", help="Enable UGOW on a Windows drive")
    p.add_argument("drive", help="Drive letter (e.g. d, e, f)")

    p = sub.add_parser("unmount", help="Disable UGOW on a Windows drive")
    p.add_argument("drive", help="Drive letter (e.g. d, e, f)")

    sub.add_parser("drives", help="List active UGOW-managed drives")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    handler = {
        "allow": cmd_allow,
        "deny": cmd_deny,
        "check": cmd_check,
        "status": cmd_status,
        "list": cmd_list,
        "sync": cmd_sync,
        "acl-cleanup": cmd_acl_cleanup,
        "mount": cmd_mount,
        "unmount": cmd_unmount,
        "drives": cmd_drives,
    }
    try:
        handler[args.command](args)
    except AclMirrorUnavailable as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
