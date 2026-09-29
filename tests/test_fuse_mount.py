"""End-to-end tests against a real FUSE mount of the shim.

The other shim tests call UGOWShim's methods directly with a mocked FUSE
context. These mount it for real, as root -- the way wsl-fuse-shim@.service
runs it -- and act on the mount as an ordinary user, so the kernel's own path
walk, `default_permissions` and `allow_other` take part in every decision, as
they do in production.

They need Linux, /dev/fuse and passwordless sudo, and are skipped without
them -- unless UGOW_FUSE_TESTS=require (set in CI), where a missing
prerequisite fails instead of quietly skipping the whole module.
"""

import errno
import os
import shutil
import subprocess
import sys
import time

import pytest

from permstore import PermStore

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIM = os.path.join(REPO, "fuse", "shim.py")
REQUIRED = os.environ.get("UGOW_FUSE_TESTS") == "require"


def _missing_prerequisites():
    if not sys.platform.startswith("linux"):
        return ["Linux"]
    missing = []
    if not os.path.exists("/dev/fuse"):
        missing.append("/dev/fuse")
    if shutil.which("sudo") is None or subprocess.run(
        ["sudo", "-n", "true"], capture_output=True
    ).returncode != 0:
        missing.append("passwordless sudo")
    return missing


MISSING = _missing_prerequisites()
pytestmark = pytest.mark.skipif(
    bool(MISSING) and not REQUIRED,
    reason=f"needs {', '.join(MISSING)}",
)


@pytest.fixture(scope="module")
def mount(tmp_path_factory):
    """Mount the shim as root over a backing tree; yield (mnt, backing)."""
    if MISSING:
        pytest.fail(f"UGOW_FUSE_TESTS=require, but missing: {', '.join(MISSING)}")

    base = tmp_path_factory.mktemp("fuse")
    backing, mnt, db = base / "backing", base / "mnt", str(base / "wperm.db")
    for d in ("granted/sub", "locked"):
        (backing / d).mkdir(parents=True)
    for f in ("granted/f", "locked/f", "locked/chmod-me", "locked/victim", "locked/move-me"):
        (backing / f).write_text("x")
        (backing / f).chmod(0o666)
    mnt.mkdir()

    uid = os.getuid()
    # Grants are written before the mount: once the root-run shim opens the
    # database, its WAL files belong to root and this process can't write.
    store = PermStore(db_path=db, mirror_acl=False)
    store.grant(f"{mnt}/granted", uid)
    store.close()

    log_path = base / "shim.log"
    with open(log_path, "w") as log:
        proc = subprocess.Popen(
            ["sudo", "-n", "env", f"PYTHONPATH={REPO}", sys.executable, SHIM,
             "--db", db, "--launcher-uid", "4242", str(backing), str(mnt)],
            stdout=log, stderr=subprocess.STDOUT,
        )
    try:
        deadline = time.monotonic() + 15
        while not os.path.ismount(mnt):
            if proc.poll() is not None or time.monotonic() > deadline:
                pytest.fail(f"shim did not mount:\n{log_path.read_text()}")
            time.sleep(0.1)
        yield mnt, backing, log_path
    finally:
        subprocess.run(["sudo", "-n", "umount", str(mnt)], capture_output=True)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            subprocess.run(["sudo", "-n", "kill", str(proc.pid)], capture_output=True)
        # Hand root-owned leftovers (the WAL files) back so pytest can clean up.
        subprocess.run(["sudo", "-n", "chown", "-R", f"{uid}:{os.getgid()}", str(base)],
                       capture_output=True)


def _errno_of(fn, *args):
    try:
        fn(*args)
    except OSError as e:
        return e.errno
    return 0


def _open_for_append(path):
    with open(path, "a"):
        pass


class TestRealMount:
    def test_unprivileged_user_reaches_a_root_mount(self, mount):
        """allow_other: without it, only root could use the mount at all."""
        mnt, _, _ = mount
        assert os.path.ismount(mnt)
        assert sorted(os.listdir(mnt)) == ["granted", "locked"]

    def test_reads_are_never_gated(self, mount):
        mnt, _, _ = mount
        with open(mnt / "locked" / "f") as f:
            assert f.read() == "x"

    def test_write_needs_a_grant(self, mount):
        mnt, _, _ = mount
        assert _errno_of(_open_for_append, mnt / "granted" / "f") == 0
        assert _errno_of(_open_for_append, mnt / "locked" / "f") == errno.EACCES

    def test_grant_covers_descendants(self, mount):
        mnt, _, _ = mount
        assert _errno_of(_open_for_append, mnt / "granted" / "sub" / "new") == 0

    def test_create_needs_a_grant_on_the_parent(self, mount):
        mnt, _, _ = mount
        assert _errno_of(_open_for_append, mnt / "locked" / "new") == errno.EACCES
        assert not (mnt / "locked" / "new").exists()

    def test_stat_and_access_report_the_callers_wbit(self, mount):
        mnt, _, _ = mount
        assert os.stat(mnt / "granted" / "f").st_mode & 0o222 == 0o222
        assert os.stat(mnt / "locked" / "f").st_mode & 0o222 == 0
        assert os.access(mnt / "granted" / "f", os.W_OK)
        assert not os.access(mnt / "locked" / "f", os.W_OK)

    def test_chmod_by_the_owner_still_needs_a_grant(self, mount):
        """The caller owns the file, so only the shim's gate can refuse this."""
        mnt, backing, _ = mount
        assert os.stat(mnt / "locked" / "chmod-me").st_uid == os.getuid()
        assert _errno_of(os.chmod, mnt / "locked" / "chmod-me", 0o600) == errno.EACCES
        assert (backing / "locked" / "chmod-me").stat().st_mode & 0o777 == 0o666

    def test_hard_link_cannot_move_a_file_into_a_grant(self, mount):
        mnt, _, _ = mount
        assert _errno_of(
            os.link, mnt / "locked" / "victim", mnt / "granted" / "stolen"
        ) == errno.EACCES

    def test_rename_out_of_an_ungranted_directory_is_denied(self, mount):
        mnt, _, _ = mount
        assert _errno_of(
            os.rename, mnt / "locked" / "move-me", mnt / "granted" / "moved"
        ) == errno.EACCES

    def test_created_entries_belong_to_the_caller(self, mount):
        mnt, backing, _ = mount
        (mnt / "granted" / "mine").write_text("y")
        (mnt / "granted" / "mydir").mkdir()
        for name in ("mine", "mydir"):
            st = os.lstat(backing / "granted" / name)
            assert (st.st_uid, st.st_gid) == (os.getuid(), os.getgid())

    def test_denials_are_logged(self, mount):
        # A chmod by the owner passes the kernel's own check and reaches the
        # shim's gate, which logs it; an append-open on a file shown as
        # read-only is refused by the kernel before the shim is asked.
        mnt, _, log_path = mount
        _errno_of(os.chmod, mnt / "locked" / "chmod-me", 0o600)
        assert f"deny chmod uid={os.getuid()}" in log_path.read_text()
