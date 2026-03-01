import os
import errno
import pytest
from shim import UGOWShim


UID = 1000


class TestReadOnlyOps:
    """Read-only operations should pass through without W-bit checks."""

    def test_getattr(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "hello.txt")
        with open(fpath, "w") as f:
            f.write("hi")
        attr = shim.getattr("/hello.txt")
        assert attr["st_size"] == 2

    def test_readdir(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        os.makedirs(os.path.join(backing_root, "sub"))
        with open(os.path.join(backing_root, "file.txt"), "w") as f:
            f.write("")
        entries = list(shim.readdir("/", None))
        assert "." in entries
        assert ".." in entries
        assert "sub" in entries
        assert "file.txt" in entries

    def test_readlink(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        target = os.path.join(backing_root, "real.txt")
        link = os.path.join(backing_root, "link.txt")
        with open(target, "w") as f:
            f.write("data")
        os.symlink(target, link)
        assert shim.readlink("/link.txt") == target

    def test_statfs(self, shim, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        sf = shim.statfs("/")
        assert "f_bsize" in sf
        assert "f_namemax" in sf


class TestOpenCreateReadWrite:
    def test_open_read_only_no_wbit(self, shim, backing_root, mock_fuse_ctx):
        """Opening for read should succeed without W-bit."""
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "r.txt")
        with open(fpath, "w") as f:
            f.write("read me")
        fh = shim.open("/r.txt", os.O_RDONLY)
        try:
            data = shim.read("/r.txt", 100, 0, fh)
            assert data == b"read me"
        finally:
            shim.release("/r.txt", fh)

    def test_open_write_denied_without_wbit(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "w.txt")
        with open(fpath, "w") as f:
            f.write("")
        with pytest.raises(OSError) as exc:
            shim.open("/w.txt", os.O_WRONLY)
        assert exc.value.errno == errno.EACCES

    def test_open_write_allowed_with_wbit(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "w.txt")
        with open(fpath, "w") as f:
            f.write("")
        store.grant(fpath, UID)
        fh = shim.open("/w.txt", os.O_WRONLY)
        shim.release("/w.txt", fh)

    def test_create_denied_without_parent_wbit(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        with pytest.raises(OSError) as exc:
            shim.create("/newfile.txt", 0o644)
        assert exc.value.errno == errno.EACCES

    def test_create_allowed_with_parent_wbit(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        store.grant(backing_root, UID)
        fh = shim.create("/created.txt", 0o644)
        shim.release("/created.txt", fh)
        assert os.path.exists(os.path.join(backing_root, "created.txt"))

    def test_write_data(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "wr.txt")
        with open(fpath, "w") as f:
            f.write("")
        store.grant(fpath, UID)
        fh = shim.open("/wr.txt", os.O_WRONLY)
        written = shim.write("/wr.txt", b"hello", 0, fh)
        assert written == 5
        shim.release("/wr.txt", fh)
        with open(fpath) as f:
            assert f.read() == "hello"


class TestTruncate:
    def test_truncate_denied_without_wbit(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "t.txt")
        with open(fpath, "w") as f:
            f.write("abcdef")
        with pytest.raises(OSError) as exc:
            shim.truncate("/t.txt", 3)
        assert exc.value.errno == errno.EACCES

    def test_truncate_allowed_with_wbit(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "t.txt")
        with open(fpath, "w") as f:
            f.write("abcdef")
        store.grant(fpath, UID)
        shim.truncate("/t.txt", 3)
        with open(fpath) as f:
            assert f.read() == "abc"

    def test_truncate_with_fh(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "t2.txt")
        with open(fpath, "w") as f:
            f.write("abcdef")
        store.grant(fpath, UID)
        fh = shim.open("/t2.txt", os.O_RDWR)
        shim.truncate("/t2.txt", 2, fh=fh)
        shim.release("/t2.txt", fh)
        with open(fpath) as f:
            assert f.read() == "ab"


class TestDirectoryOps:
    def test_mkdir_denied(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        with pytest.raises(OSError) as exc:
            shim.mkdir("/newdir", 0o755)
        assert exc.value.errno == errno.EACCES

    def test_mkdir_allowed(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        store.grant(backing_root, UID)
        shim.mkdir("/newdir", 0o755)
        assert os.path.isdir(os.path.join(backing_root, "newdir"))

    def test_rmdir_denied(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        os.mkdir(os.path.join(backing_root, "delme"))
        with pytest.raises(OSError) as exc:
            shim.rmdir("/delme")
        assert exc.value.errno == errno.EACCES

    def test_rmdir_allowed(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        dpath = os.path.join(backing_root, "delme")
        os.mkdir(dpath)
        store.grant(backing_root, UID)
        shim.rmdir("/delme")
        assert not os.path.exists(dpath)


class TestUnlinkRename:
    def test_unlink_denied(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "rm.txt")
        with open(fpath, "w") as f:
            f.write("")
        with pytest.raises(OSError) as exc:
            shim.unlink("/rm.txt")
        assert exc.value.errno == errno.EACCES

    def test_unlink_allowed(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "rm.txt")
        with open(fpath, "w") as f:
            f.write("")
        store.grant(backing_root, UID)
        shim.unlink("/rm.txt")
        assert not os.path.exists(fpath)

    def test_rename_denied_source(self, shim, store, backing_root, mock_fuse_ctx):
        """W-bit on destination parent but not on source should deny rename."""
        mock_fuse_ctx(UID)
        src_dir = os.path.join(backing_root, "srcdir")
        dst_dir = os.path.join(backing_root, "dstdir")
        os.makedirs(src_dir)
        os.makedirs(dst_dir)
        src = os.path.join(src_dir, "file.txt")
        with open(src, "w") as f:
            f.write("")
        store.grant(dst_dir, UID)  # W on dest parent, but not on source
        with pytest.raises(OSError) as exc:
            shim.rename("/srcdir/file.txt", "/dstdir/file.txt")
        assert exc.value.errno == errno.EACCES

    def test_rename_allowed(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        src = os.path.join(backing_root, "src.txt")
        with open(src, "w") as f:
            f.write("data")
        store.grant(backing_root, UID)
        shim.rename("/src.txt", "/dst.txt")
        assert not os.path.exists(src)
        assert os.path.exists(os.path.join(backing_root, "dst.txt"))


class TestSymlinkLink:
    def test_symlink_denied(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        with pytest.raises(OSError) as exc:
            shim.symlink("/newlink", "/some/target")
        assert exc.value.errno == errno.EACCES

    def test_symlink_allowed(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        store.grant(backing_root, UID)
        shim.symlink("/mylink", "/some/target")
        link_path = os.path.join(backing_root, "mylink")
        assert os.path.islink(link_path)
        assert os.readlink(link_path) == "/some/target"

    def test_link_denied(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        existing = os.path.join(backing_root, "existing.txt")
        with open(existing, "w") as f:
            f.write("data")
        with pytest.raises(OSError) as exc:
            shim.link("/hardlink", "/existing.txt")
        assert exc.value.errno == errno.EACCES

    def test_link_allowed(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        existing = os.path.join(backing_root, "existing.txt")
        with open(existing, "w") as f:
            f.write("linked")
        store.grant(backing_root, UID)
        shim.link("/hardlink", "/existing.txt")
        hl = os.path.join(backing_root, "hardlink")
        assert os.path.exists(hl)
        with open(hl) as f:
            assert f.read() == "linked"


class TestChmod:
    def test_chmod_passthrough(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "ch.txt")
        with open(fpath, "w") as f:
            f.write("")
        shim.chmod("/ch.txt", 0o755)
        assert os.stat(fpath).st_mode & 0o7777 == 0o755

    def test_chmod_does_not_grant_wbit(self, shim, store, backing_root, mock_fuse_ctx):
        """chmod +t must NOT grant W-bit -- grants only via 'sudo ugow allow'."""
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "sticky.txt")
        with open(fpath, "w") as f:
            f.write("")
        shim.chmod("/sticky.txt", 0o1644)
        assert store.has_wbit(fpath, UID) is False


class TestChown:
    def test_chown_denied_for_non_root(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "own.txt")
        with open(fpath, "w") as f:
            f.write("")
        with pytest.raises(OSError) as exc:
            shim.chown("/own.txt", 0, 0)
        assert exc.value.errno == errno.EPERM

    def test_chown_allowed_for_root(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(0)
        fpath = os.path.join(backing_root, "own.txt")
        with open(fpath, "w") as f:
            f.write("")
        shim.chown("/own.txt", os.getuid(), os.getgid())


class TestAccess:
    def test_access_read_no_wbit(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "a.txt")
        with open(fpath, "w") as f:
            f.write("")
        shim.access("/a.txt", os.R_OK)

    def test_access_write_denied(self, shim, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "a.txt")
        with open(fpath, "w") as f:
            f.write("")
        with pytest.raises(OSError) as exc:
            shim.access("/a.txt", os.W_OK)
        assert exc.value.errno == errno.EACCES

    def test_access_write_allowed(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "a.txt")
        with open(fpath, "w") as f:
            f.write("")
        store.grant(fpath, UID)
        shim.access("/a.txt", os.W_OK)


class TestReleaseFlush:
    def test_release_closes_fd(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "rel.txt")
        with open(fpath, "w") as f:
            f.write("x")
        fh = shim.open("/rel.txt", os.O_RDONLY)
        shim.release("/rel.txt", fh)
        with pytest.raises(OSError):
            os.read(fh, 1)

    def test_flush_syncs_fd(self, shim, store, backing_root, mock_fuse_ctx):
        mock_fuse_ctx(UID)
        fpath = os.path.join(backing_root, "fl.txt")
        with open(fpath, "w") as f:
            f.write("x")
        fh = shim.open("/fl.txt", os.O_RDONLY)
        shim.flush("/fl.txt", fh)
        shim.release("/fl.txt", fh)
