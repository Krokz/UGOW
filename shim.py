#!/usr/bin/env python3
import os
import sys
import errno
import json
import atexit
import subprocess
import argparse
from fuse import FUSE, Operations, fuse_get_context

# Capture the user who launched the shim (to remap root)
LAUNCHER_UID = os.getuid()

# JSON metadata file storing W-permission map
META_FILE = "/var/lib/wsl-fuse-shim/wperm.json"

# Load or initialize W_MAP
try:
    with open(META_FILE, "r") as f:
        W_MAP = json.load(f)
except FileNotFoundError:
    W_MAP = {}

# Ensure metadata directory exists
os.makedirs(os.path.dirname(META_FILE), exist_ok=True)

# Save W_MAP on exit
def _save_wmap():
    try:
        with open(META_FILE, "w") as f:
            json.dump(W_MAP, f)
    except Exception as e:
        print(f"Warning: could not save W_MAP: {e}")
atexit.register(_save_wmap)

# Helpers for path conversion

def path_to_win(path):
    parts = path.split(os.sep)
    if len(parts) > 2 and parts[1].lower() == 'mnt':
        drive = parts[2].upper()
        rest = parts[3:]
        return drive + ':\\' + '\\'.join(rest)
    return path

# Permission logic

def has_wbit(path, uid):
    ustr = str(uid)
    current = path
    while True:
        if ustr in W_MAP.get(current, []):
            return True
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return False

# Grant and revoke functions (JSON + Windows ACL)

def grant_wbit(path, uid):
    ustr = str(uid)
    W_MAP.setdefault(path, [])
    if ustr not in W_MAP[path]:
        W_MAP[path].append(ustr)
    # Mirror to Windows (best-effort)
    win_user = f"wsl_{uid}"
    win_path = path_to_win(path)
    ps = (
        f"if (-Not (Get-LocalUser -Name '{win_user}' -ErrorAction SilentlyContinue)) {{ "
        f"New-LocalUser -Name '{win_user}' -NoPassword -ErrorAction SilentlyContinue }}; "
        f"icacls '{win_path}' /grant '{win_user}:(OI)(CI)F' /T -ErrorAction SilentlyContinue"
    )
    subprocess.run(["powershell.exe", "-Command", ps], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def revoke_wbit(path, uid):
    ustr = str(uid)
    if path in W_MAP and ustr in W_MAP[path]:
        W_MAP[path].remove(ustr)
        if not W_MAP[path]:
            del W_MAP[path]
    win_user = f"wsl_{uid}"
    win_path = path_to_win(path)
    ps = f"icacls '{win_path}' /remove '{win_user}' /T -ErrorAction SilentlyContinue"
    subprocess.run(["powershell.exe", "-Command", ps], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# FUSE filesystem implementation

class UGOWShim(Operations):
    def __init__(self, root):
        self.root = root

    def _effective_uid(self):
        real_uid, _, _ = fuse_get_context()
        return LAUNCHER_UID if real_uid == 0 else real_uid

    def _full_path(self, path):
        return os.path.join(self.root, path.lstrip("/"))

    def getattr(self, path, fh=None):
        full = self._full_path(path)
        st = os.lstat(full)
        return {k: getattr(st, k) for k in (
            "st_mode","st_ino","st_dev","st_nlink",
            "st_uid","st_gid","st_size",
            "st_atime","st_mtime","st_ctime"
        )}

    def readdir(self, path, fh):
        full = self._full_path(path)
        yield from [".", ".."] + os.listdir(full)

    def open(self, path, flags):
        full = self._full_path(path)
        uid = self._effective_uid()
        if flags & (os.O_WRONLY | os.O_RDWR) and not has_wbit(full, uid):
            raise OSError(errno.EACCES, "No W permission")
        return os.open(full, flags)

    def create(self, path, mode, fi=None):
        full = self._full_path(path)
        parent = os.path.dirname(full)
        uid = self._effective_uid()
        if not has_wbit(parent, uid):
            raise OSError(errno.EACCES, "No W on parent")
        return os.open(full, os.O_WRONLY | os.O_CREAT, mode)

    def truncate(self, path, length, fh=None):
        full = self._full_path(path)
        uid = self._effective_uid()
        if os.path.exists(full) and not has_wbit(full, uid):
            raise OSError(errno.EACCES, "No W permission")
        if not os.path.exists(full) and not has_wbit(os.path.dirname(full), uid):
            raise OSError(errno.EACCES, "No W on parent")
        mode_open = "r+" if os.path.exists(full) else "w+"
        with open(full, mode_open) as f:
            f.truncate(length)
        return 0

    def read(self, path, size, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, size)

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def mkdir(self, path, mode):
        full = self._full_path(path)
        uid = self._effective_uid()
        if not has_wbit(os.path.dirname(full), uid):
            raise OSError(errno.EACCES, "No W on parent")
        return os.mkdir(full, mode)

    def unlink(self, path):
        full = self._full_path(path)
        uid = self._effective_uid()
        if not has_wbit(full, uid):
            raise OSError(errno.EACCES, "No W permission")
        return os.unlink(full)

    def rmdir(self, path):
        full = self._full_path(path)
        uid = self._effective_uid()
        if not has_wbit(full, uid):
            raise OSError(errno.EACCES, "No W permission")
        return os.rmdir(full)

    def rename(self, old, new):
        old_p, new_p = self._full_path(old), self._full_path(new)
        uid = self._effective_uid()
        if not has_wbit(old_p, uid) or not has_wbit(os.path.dirname(new_p), uid):
            raise OSError(errno.EACCES, "No W permission")
        return os.rename(old_p, new_p)

    def chmod(self, path, mode):
        full = self._full_path(path)
        real_uid, _, _ = fuse_get_context()
        prev = has_wbit(full, real_uid)
        # root CLI grants/revokes for target
        if real_uid == 0:
            # use CLI args in __main__ for specific user
            pass
        else:
            # sticky-bit toggle for launcher UID
            if mode & 0o1000 and not prev:
                grant_wbit(full, real_uid)
            elif not (mode & 0o1000) and prev:
                revoke_wbit(full, real_uid)
        os.chmod(full, mode & 0o777)
        return 0

    def statfs(self, path):
        full = self._full_path(path)
        st = os.statvfs(full)
        return {k: getattr(st, k) for k in (
            "f_bsize","f_frsize","f_blocks","f_bfree","f_bavail",
            "f_files","f_ffree","f_favail","f_flag","f_namemax"
        )}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UGOWShim manager or FUSE mount")
    parser.add_argument("root", nargs="?", help="Backing root path or --grant args")
    parser.add_argument("mountpoint", nargs="?", help="FUSE mount point")
    parser.add_argument("--grant", nargs=2, metavar=("UID","PATH"), help="Grant W-bit for UID on PATH")
    parser.add_argument("--revoke", nargs=2, metavar=("UID","PATH"), help="Revoke W-bit for UID on PATH")
    args = parser.parse_args()

    if args.grant:
        uid, p = int(args.grant[0]), args.grant[1]
        grant_wbit(p, uid)
        sys.exit(0)
    if args.revoke:
        uid, p = int(args.revoke[0]), args.revoke[1]
        revoke_wbit(p, uid)
        sys.exit(0)

    if not args.root or not args.mountpoint:
        parser.print_help()
        sys.exit(1)

    FUSE(UGOWShim(args.root), args.mountpoint,
         foreground=True, allow_other=True, default_permissions=True)
