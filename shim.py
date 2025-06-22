#!/usr/bin/env python3
import os
import errno
import subprocess
from fuse import FUSE, Operations, fuse_get_context
import xattr

# Capture the user who launched the shim (to remap root)
LAUNCHER_UID = os.getuid()
# xattr key where we store the W-bit mask
XATTR_KEY = "user.wperm"


def has_wbit(path, uid):
    """Check if the file or dir at path grants W-permission to this uid."""
    try:
        data = xattr.getxattr(path, XATTR_KEY).decode()
        uids = set(int(u) for u in data.split(',') if u)
        return uid in uids
    except (OSError, KeyError):
        return False


def grant_wbit(path, uid):
    """Add uid to the file's or dir's user.wperm xattr and mirror to Windows ACL."""
    try:
        data = xattr.getxattr(path, XATTR_KEY).decode()
        uids = set(int(u) for u in data.split(',') if u)
    except (OSError, KeyError):
        uids = set()
    uids.add(uid)
    xattr.setxattr(path, XATTR_KEY, ",".join(str(u) for u in uids).encode())
    # Optional: call Windows helper to set real NTFS ACL
    # win_user = f"wsl_{uid}"
    # subprocess.run([
    #   "powershell.exe", "-Command",
    #   f"if (-Not (Get-LocalUser -Name {win_user})) " +
    #   f"{{ New-LocalUser -Name {win_user} -NoPassword }}; " +
    #   f"icacls '{path}' /grant {win_user}:(OI)(CI)F"
    # ], check=True)


class UGOWShim(Operations):
    def __init__(self, root):
        self.root = root

    def _effective_uid(self):
        uid, _, _ = fuse_get_context()
        return LAUNCHER_UID if uid == 0 else uid

    def _full_path(self, path):
        return os.path.join(self.root, path.lstrip("/"))

    def getattr(self, path, fh=None):
        full = self._full_path(path)
        st = os.lstat(full)
        return {k: getattr(st, k) for k in (
            "st_mode", "st_ino", "st_dev", "st_nlink",
            "st_uid", "st_gid", "st_size",
            "st_atime", "st_mtime", "st_ctime",
        )}

    def readdir(self, path, fh):
        full = self._full_path(path)
        yield from [".", ".."] + os.listdir(full)

    def open(self, path, flags):
        full = self._full_path(path)
        uid = self._effective_uid()
        # enforce W-bit on writes
        if flags & (os.O_WRONLY | os.O_RDWR):
            if not has_wbit(full, uid):
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
        if os.path.exists(full):
            if not has_wbit(full, uid):
                raise OSError(errno.EACCES, "No W permission")
        else:
            parent = os.path.dirname(full)
            if not has_wbit(parent, uid):
                raise OSError(errno.EACCES, "No W on parent")
        mode = "r+" if os.path.exists(full) else "w+"
        with open(full, mode) as f:
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
        parent = os.path.dirname(full)
        uid = self._effective_uid()
        if not has_wbit(parent, uid):
            raise OSError(errno.EACCES, "No W on parent")
        return os.mkdir(full, mode)

    def unlink(self, path):
        full = self._full_path(path)
        uid = self._effective_uid()
        if not has_wbit(full, uid):
            raise OSError(errno.EACCES, "No W permission")
        return os.unlink(full)

    def rename(self, old, new):
        full_old = self._full_path(old)
        full_new = self._full_path(new)
        uid = self._effective_uid()
        if not has_wbit(full_old, uid) or not has_wbit(os.path.dirname(full_new), uid):
            raise OSError(errno.EACCES, "No W permission")
        return os.rename(full_old, full_new)

    def chmod(self, path, mode):
        full = self._full_path(path)
        uid = self._effective_uid()
        # use sticky bit (0o1000) as grant-w flag
        if mode & 0o1000:
            grant_wbit(full, uid)
        os.chmod(full, mode & 0o777)
        return 0

    def statfs(self, path):
        full = self._full_path(path)
        st = os.statvfs(full)
        return {k: getattr(st, k) for k in (
            "f_bsize", "f_frsize", "f_blocks", "f_bfree", "f_bavail",
            "f_files", "f_ffree", "f_favail", "f_flag", "f_namemax"
        )}


if __name__ == "__main__":
    import sys
    root = sys.argv[1]
    mnt  = sys.argv[2]
    FUSE(UGOWShim(root), mnt, foreground=True, allow_other=True)
# This shim allows WSL users to set W-permissions on files and directories
# by using an extended attribute (xattr) to store a list of UIDs that have
# write access. The shim intercepts file operations and checks these permissions.