#!/usr/bin/env python3
import os
import sys
import errno
import argparse
import logging
from fuse import FUSE, Operations, fuse_get_context

from permstore import PermStore, DEFAULT_DB_PATH  # noqa: F401

LAUNCHER_UID = None

log = logging.getLogger("ugow")


# ---------------------------------------------------------------------------
# FUSE filesystem
# ---------------------------------------------------------------------------

class UGOWShim(Operations):
    def __init__(self, root, store):
        self.root = os.path.realpath(root)
        self.store = store

    def _effective_uid(self):
        real_uid, _, _ = fuse_get_context()
        if real_uid == 0 and LAUNCHER_UID is not None:
            return LAUNCHER_UID
        return real_uid

    def _full_path(self, path):
        full = os.path.realpath(os.path.join(self.root, path.lstrip("/")))
        if not (full == self.root or full.startswith(self.root + os.sep)):
            raise OSError(errno.EACCES, "Path escapes backing root")
        return full

    # -- Metadata -----------------------------------------------------------

    def getattr(self, path, fh=None):
        full = self._full_path(path)
        st = os.lstat(full)
        d = {
            k: getattr(st, k)
            for k in (
                "st_mode", "st_ino", "st_dev", "st_nlink",
                "st_uid", "st_gid", "st_size",
                "st_atime", "st_mtime", "st_ctime",
            )
        }
        uid = self._effective_uid()
        if not self.store.has_wbit(full, uid):
            d["st_mode"] &= ~0o222
        return d

    def getxattr(self, path, name, position=0):
        if name == "user.ugow.wbit":
            full = self._full_path(path)
            uid = self._effective_uid()
            return b"1" if self.store.has_wbit(full, uid) else b"0"
        full = self._full_path(path)
        try:
            return os.getxattr(full, name)
        except OSError:
            raise OSError(errno.ENODATA, "")

    def listxattr(self, path):
        full = self._full_path(path)
        try:
            attrs = list(os.listxattr(full))
        except OSError:
            attrs = []
        attrs.append("user.ugow.wbit")
        return attrs

    def access(self, path, amode):
        full = self._full_path(path)
        if amode & os.W_OK:
            uid = self._effective_uid()
            if not self.store.has_wbit(full, uid):
                raise OSError(errno.EACCES, "No W permission")
        if not os.access(full, amode):
            raise OSError(errno.EACCES, "")

    def readdir(self, path, fh):
        full = self._full_path(path)
        yield from [".", ".."] + os.listdir(full)

    def readlink(self, path):
        return os.readlink(self._full_path(path))

    def statfs(self, path):
        full = self._full_path(path)
        st = os.statvfs(full)
        return {
            k: getattr(st, k)
            for k in (
                "f_bsize", "f_frsize", "f_blocks", "f_bfree", "f_bavail",
                "f_files", "f_ffree", "f_favail", "f_flag", "f_namemax",
            )
        }

    # -- File I/O -----------------------------------------------------------

    def open(self, path, flags):
        full = self._full_path(path)
        uid = self._effective_uid()
        if flags & (os.O_WRONLY | os.O_RDWR) and not self.store.has_wbit(full, uid):
            raise OSError(errno.EACCES, "No W permission")
        return os.open(full, flags)

    def create(self, path, mode, fi=None):
        full = self._full_path(path)
        uid = self._effective_uid()
        if not self.store.has_wbit(os.path.dirname(full), uid):
            raise OSError(errno.EACCES, "No W on parent")
        return os.open(full, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, size, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, size)

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full = self._full_path(path)
        uid = self._effective_uid()
        if not self.store.has_wbit(full, uid):
            raise OSError(errno.EACCES, "No W permission")
        if fh is not None:
            os.ftruncate(fh, length)
        else:
            with open(full, "r+b") as f:
                f.truncate(length)
        return 0

    def flush(self, path, fh):
        return 0

    def release(self, path, fh):
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        if fdatasync and hasattr(os, "fdatasync"):
            return os.fdatasync(fh)
        return os.fsync(fh)

    # -- Directory operations -----------------------------------------------

    def mkdir(self, path, mode):
        full = self._full_path(path)
        uid = self._effective_uid()
        if not self.store.has_wbit(os.path.dirname(full), uid):
            raise OSError(errno.EACCES, "No W on parent")
        return os.mkdir(full, mode)

    def rmdir(self, path):
        full = self._full_path(path)
        uid = self._effective_uid()
        if not self.store.has_wbit(os.path.dirname(full), uid):
            raise OSError(errno.EACCES, "No W on parent")
        return os.rmdir(full)

    # -- Entry operations ---------------------------------------------------

    def unlink(self, path):
        full = self._full_path(path)
        uid = self._effective_uid()
        if not self.store.has_wbit(os.path.dirname(full), uid):
            raise OSError(errno.EACCES, "No W on parent")
        return os.unlink(full)

    def rename(self, old, new):
        old_p, new_p = self._full_path(old), self._full_path(new)
        uid = self._effective_uid()
        if not self.store.has_wbit(os.path.dirname(old_p), uid) or \
           not self.store.has_wbit(os.path.dirname(new_p), uid):
            raise OSError(errno.EACCES, "No W on parent")
        return os.rename(old_p, new_p)

    def symlink(self, target, source):
        """Create a symlink at *target* pointing to *source*."""
        new_link = self._full_path(target)
        uid = self._effective_uid()
        if not self.store.has_wbit(os.path.dirname(new_link), uid):
            raise OSError(errno.EACCES, "No W on parent")
        return os.symlink(source, new_link)

    def link(self, target, source):
        """Create a hard link at *target* referencing *source*."""
        new_link = self._full_path(target)
        existing = self._full_path(source)
        uid = self._effective_uid()
        if not self.store.has_wbit(os.path.dirname(new_link), uid):
            raise OSError(errno.EACCES, "No W on parent")
        return os.link(existing, new_link)

    # -- Permission / attribute operations ----------------------------------

    def chmod(self, path, mode):
        full = self._full_path(path)
        uid = self._effective_uid()
        prev = self.store.has_wbit(full, uid)
        if mode & 0o1000 and not prev:
            self.store.grant(full, uid)
        elif not (mode & 0o1000) and prev:
            self.store.revoke(full, uid)
        os.chmod(full, mode & 0o777)
        return 0

    def chown(self, path, uid, gid):
        return os.lchown(self._full_path(path), uid, gid)

    def utimens(self, path, times=None):
        full = self._full_path(path)
        os.utime(full, times=times)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="UGOW: FUSE shim with W-bit permission control"
    )
    parser.add_argument("root", nargs="?", help="Backing root path")
    parser.add_argument("mountpoint", nargs="?", help="FUSE mount point")
    parser.add_argument(
        "--grant", nargs=2, metavar=("UID", "PATH"),
        help="Grant W-bit for UID on PATH",
    )
    parser.add_argument(
        "--revoke", nargs=2, metavar=("UID", "PATH"),
        help="Revoke W-bit for UID on PATH",
    )
    parser.add_argument(
        "--list", action="store_true", help="List all W-bit grants"
    )
    parser.add_argument(
        "--list-for-uid", type=int, metavar="UID",
        help="List W-bit grants for a specific UID",
    )
    parser.add_argument(
        "--cleanup-acl", action="store_true",
        help="Remove stale wsl_* Windows users with no grants",
    )
    parser.add_argument(
        "--check", metavar="PATH",
        help="Check if current user has W-bit on PATH (exit 0=granted, 1=denied)",
    )
    parser.add_argument(
        "--mirror-acl", action="store_true",
        help="Enable NTFS ACL mirroring via PowerShell",
    )
    parser.add_argument(
        "--db", default=DEFAULT_DB_PATH,
        help="Path to SQLite DB (default: %(default)s)",
    )
    parser.add_argument(
        "--launcher-uid", type=int, default=None,
        help="UID to remap root operations to (detects SUDO_UID if omitted)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.launcher_uid is not None:
        LAUNCHER_UID = args.launcher_uid
    elif os.environ.get("SUDO_UID"):
        LAUNCHER_UID = int(os.environ["SUDO_UID"])
    else:
        uid = os.getuid()
        if uid != 0:
            LAUNCHER_UID = uid

    store = PermStore(db_path=args.db, mirror_acl=args.mirror_acl)

    if args.grant:
        uid, p = int(args.grant[0]), os.path.abspath(args.grant[1])
        store.grant(p, uid)
        print(f"Granted W-bit: uid={uid} path={p}")
        sys.exit(0)

    if args.revoke:
        uid, p = int(args.revoke[0]), os.path.abspath(args.revoke[1])
        store.revoke(p, uid)
        print(f"Revoked W-bit: uid={uid} path={p}")
        sys.exit(0)

    if args.list or args.list_for_uid is not None:
        grants = store.list_grants(uid=args.list_for_uid)
        if not grants:
            print("No grants found.")
        else:
            for gpath, guid in grants:
                print(f"  uid={guid}\t{gpath}")
        sys.exit(0)

    if args.check:
        path = os.path.abspath(args.check)
        uid = os.getuid()
        has = store.has_wbit(path, uid)
        status = "GRANTED" if has else "DENIED"
        print(f"W-bit {status} for uid={uid} on {path}")
        sys.exit(0 if has else 1)

    if args.cleanup_acl:
        store.cleanup_acl()
        sys.exit(0)

    if not args.root or not args.mountpoint:
        parser.print_help()
        sys.exit(1)

    FUSE(
        UGOWShim(args.root, store), args.mountpoint,
        foreground=True, allow_other=True, default_permissions=True,
    )
