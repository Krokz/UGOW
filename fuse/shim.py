#!/usr/bin/env python3
import os
import sys
import errno
import argparse
import logging

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in [_HERE, "/opt/ugow/lib"]:
    if os.path.isfile(os.path.join(_p, "permstore.py")):
        sys.path.insert(0, _p)
        break

from fuse import FUSE, Operations, fuse_get_context  # noqa: E402
from permstore import PermStore, DEFAULT_DB_PATH  # noqa: E402

LAUNCHER_UID = None

log = logging.getLogger("ugow")

# setuid/setgid on a Windows drive buys nothing and is a privilege-escalation
# primitive if the mount is ever missing nosuid, so the shim never sets them.
_MODE_MASK = 0o1777


def _safe_mode(mode):
    return mode & _MODE_MASK


# ---------------------------------------------------------------------------
# FUSE filesystem
# ---------------------------------------------------------------------------

class UGOWShim(Operations):
    def __init__(self, root, mountpoint, store):
        self.root = os.path.abspath(root)
        self.mountpoint = os.path.abspath(mountpoint)
        self.store = store

    def _grant_path(self, backing_path):
        """Convert backing store path to user-visible mount path for grant lookups."""
        rel = os.path.relpath(backing_path, self.root)
        if rel == '.':
            return self.mountpoint
        return os.path.join(self.mountpoint, rel)

    def _effective_uid(self):
        real_uid, _, _ = fuse_get_context()
        if real_uid == 0 and LAUNCHER_UID is not None:
            return LAUNCHER_UID
        return real_uid

    def _deny(self, op, backing_path, uid, reason, err=errno.EACCES):
        """Log and raise. Every denial is auditable."""
        log.warning(
            "deny %s uid=%d path=%s (%s)",
            op, uid, self._grant_path(backing_path), reason,
        )
        raise OSError(err, reason)

    def _require_wbit(self, op, backing_path, uid):
        """Raise EACCES unless *uid* holds the W-bit on *backing_path*."""
        if not self.store.has_wbit(self._grant_path(backing_path), uid):
            self._deny(op, backing_path, uid, "no W permission")

    def _require_parent_wbit(self, op, backing_path, uid):
        """Raise EACCES unless *uid* holds the W-bit on the parent directory."""
        parent = os.path.dirname(backing_path)
        if not self.store.has_wbit(self._grant_path(parent), uid):
            self._deny(op, parent, uid, "no W permission on parent")

    def _full_path(self, path):
        full = os.path.abspath(os.path.join(self.root, path.lstrip("/")))
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
        if self.store.has_wbit(self._grant_path(full), uid):
            d["st_mode"] |= 0o222
        else:
            d["st_mode"] &= ~0o222
        return d

    def getxattr(self, path, name, position=0):
        if name == "user.ugow.wbit":
            full = self._full_path(path)
            uid = self._effective_uid()
            return b"1" if self.store.has_wbit(self._grant_path(full), uid) else b"0"
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
            self._require_wbit("access", full, self._effective_uid())
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
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_TRUNC | os.O_APPEND):
            self._require_wbit("open", full, self._effective_uid())
        return os.open(full, flags)

    def create(self, path, mode, fi=None):
        full = self._full_path(path)
        self._require_parent_wbit("create", full, self._effective_uid())
        # fusepy's create() carries no flags, so O_EXCL cannot be honoured here;
        # the kernel's lookup-then-create path decides existence instead.
        return os.open(full, os.O_WRONLY | os.O_CREAT, _safe_mode(mode))

    def read(self, path, size, offset, fh):
        # Positioned I/O: fusepy dispatches multithreaded, so a shared
        # lseek+read would race the file offset between concurrent ops.
        return os.pread(fh, size, offset)

    def write(self, path, buf, offset, fh):
        # Positioned I/O -- see read() for why we avoid lseek+write.
        return os.pwrite(fh, buf, offset)

    def truncate(self, path, length, fh=None):
        full = self._full_path(path)
        self._require_wbit("truncate", full, self._effective_uid())
        if fh is not None:
            os.ftruncate(fh, length)
        else:
            with open(full, "r+b") as f:
                f.truncate(length)
        return 0

    def flush(self, path, fh):
        # flush() fires on every close(); fsync-on-close would force a disk
        # sync per close on already-slow 9P/DrvFs. Durability is left to the
        # fsync() hook, which callers invoke explicitly when they need it.
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
        self._require_parent_wbit("mkdir", full, self._effective_uid())
        return os.mkdir(full, _safe_mode(mode))

    def rmdir(self, path):
        full = self._full_path(path)
        self._require_parent_wbit("rmdir", full, self._effective_uid())
        return os.rmdir(full)

    # -- Entry operations ---------------------------------------------------

    def unlink(self, path):
        full = self._full_path(path)
        self._require_parent_wbit("unlink", full, self._effective_uid())
        return os.unlink(full)

    def rename(self, old, new):
        old_p, new_p = self._full_path(old), self._full_path(new)
        uid = self._effective_uid()
        self._require_parent_wbit("rename", old_p, uid)
        self._require_parent_wbit("rename", new_p, uid)
        return os.rename(old_p, new_p)

    def symlink(self, target, source):
        """Create a symlink at *target* pointing to *source*."""
        new_link = self._full_path(target)
        self._require_parent_wbit("symlink", new_link, self._effective_uid())
        return os.symlink(source, new_link)

    def link(self, target, source):
        """Create a hard link at *target* referencing *source*."""
        new_link = self._full_path(target)
        existing = self._full_path(source)
        uid = self._effective_uid()
        self._require_parent_wbit("link", new_link, uid)
        # A second name must not grant rights the first name did not have:
        # without this, linking a protected file into a granted directory
        # would make it writable through the new path.
        self._require_wbit("link", existing, uid)
        return os.link(existing, new_link)

    # -- Permission / attribute operations ----------------------------------

    def chmod(self, path, mode):
        full = self._full_path(path)
        # chmod is a write to the file's metadata and must be gated like any
        # other write -- the shim runs as root, so an ungated chmod would let
        # any caller re-mode every file on the drive.
        self._require_wbit("chmod", full, self._effective_uid())
        os.chmod(full, _safe_mode(mode))
        return 0

    def chown(self, path, uid, gid):
        # Compare the *real* caller uid: _effective_uid() remaps root to the
        # launching user, which would make this test unsatisfiable for root.
        real_uid, _, _ = fuse_get_context()
        if real_uid != 0:
            self._deny("chown", self._full_path(path), real_uid,
                       "only root can chown", err=errno.EPERM)
        return os.lchown(self._full_path(path), uid, gid)

    def utimens(self, path, times=None):
        full = self._full_path(path)
        self._require_wbit("utimens", full, self._effective_uid())
        os.utime(full, times=times)


# ---------------------------------------------------------------------------
# Daemon entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="UGOW FUSE shim daemon"
    )
    parser.add_argument("root", help="Backing root path")
    parser.add_argument("mountpoint", help="FUSE mount point")
    parser.add_argument(
        "--db", default=DEFAULT_DB_PATH,
        help="Path to SQLite DB (default: %(default)s)",
    )
    parser.add_argument(
        "--launcher-uid", type=int, default=None,
        help="UID to remap root operations to (detects SUDO_UID if omitted)",
    )
    parser.add_argument(
        "--mirror-acl", action="store_true",
        help="Enable NTFS ACL mirroring via PowerShell",
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

    store = PermStore(db_path=args.db, mirror_acl=args.mirror_acl, watch_db=True)

    FUSE(
        UGOWShim(args.root, args.mountpoint, store), args.mountpoint,
        foreground=True, allow_other=True, default_permissions=True,
        # nosuid/nodev: the backing store is a Windows drive that any granted
        # user can write to, so it must never carry privilege bits.
        nosuid=True, nodev=True,
        # getattr() reports the W-bit in st_mode for the *calling* uid, but the
        # kernel's attribute cache is per-inode. Caching would let one user's
        # mode answer decide default_permissions checks for another user, so
        # attributes and lookups must not be cached.
        attr_timeout=0, entry_timeout=0, negative_timeout=0,
    )
