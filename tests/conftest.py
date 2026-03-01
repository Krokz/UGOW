import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shim import PermStore, UGOWShim  # noqa: E402


@pytest.fixture()
def tmp_db(tmp_path):
    """Yield the path to a fresh temporary SQLite database."""
    return str(tmp_path / "test_wperm.db")


@pytest.fixture()
def store(tmp_db):
    """A PermStore backed by a temporary database, ACL mirroring off."""
    return PermStore(db_path=tmp_db, mirror_acl=False)


@pytest.fixture()
def backing_root(tmp_path):
    """A temporary directory to serve as the backing filesystem root."""
    root = tmp_path / "root"
    root.mkdir()
    return str(root)


@pytest.fixture()
def shim(backing_root, store):
    """A UGOWShim wired to the temporary root and store."""
    return UGOWShim(backing_root, backing_root, store)


@pytest.fixture()
def mock_fuse_ctx(monkeypatch):
    """Return a helper that patches fuse_get_context to a given (uid, gid, pid)."""
    def _set(uid, gid=1000, pid=1):
        monkeypatch.setattr(
            "shim.fuse_get_context", lambda: (uid, gid, pid)
        )
    return _set
