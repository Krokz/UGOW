"""Regression tests for W-bit bypasses.

These wire the shim the way setup.sh does -- a backing root that differs from
the mountpoint -- so the backing->mount path translation that every real grant
depends on is exercised, and grants are expressed as the user-visible paths the
CLI actually stores.
"""

import errno
import os
import stat

import pytest

import shim as shim_mod
from shim import UGOWShim
from permstore import PermStore


MOUNT = "/mnt/c"          # user-visible mount point, as in production
CALLER = 1000             # unprivileged caller
LAUNCHER = 1000           # uid the shim remaps root onto


@pytest.fixture()
def backing(tmp_path):
    """A backing root laid out like a Windows drive: protected area + sandbox."""
    root = tmp_path / "c-backing"
    (root / "Windows" / "System32").mkdir(parents=True)
    (root / "sandbox").mkdir()
    victim = root / "Windows" / "System32" / "victim.exe"
    victim.write_text("trusted")
    victim.chmod(0o755)
    return root


@pytest.fixture()
def fs(backing, tmp_path, monkeypatch):
    """Shim with mountpoint != backing root, plus a grant on /mnt/c/sandbox only."""
    store = PermStore(db_path=str(tmp_path / "wperm.db"), mirror_acl=False)
    store.grant(f"{MOUNT}/sandbox", CALLER)
    monkeypatch.setattr(shim_mod, "LAUNCHER_UID", None)
    shim = UGOWShim(str(backing), MOUNT, store)
    shim.test_store = store
    return shim


@pytest.fixture()
def as_uid(monkeypatch):
    def _set(uid, gid=1000, pid=1):
        monkeypatch.setattr(shim_mod, "fuse_get_context", lambda: (uid, gid, pid))
    return _set


class TestGrantPathTranslation:
    """The backing->mount translation is what makes CLI grants apply at all."""

    def test_backing_path_maps_to_mount_path(self, fs, backing):
        assert fs._grant_path(str(backing)) == MOUNT
        assert fs._grant_path(str(backing / "sandbox")) == f"{MOUNT}/sandbox"
        assert fs._grant_path(str(backing / "a" / "b")) == f"{MOUNT}/a/b"

    def test_grant_on_mount_path_gates_backing_op(self, fs, as_uid):
        as_uid(CALLER)
        fh = fs.create("/sandbox/ok.txt", 0o644)
        fs.release("/sandbox/ok.txt", fh)
        with pytest.raises(OSError) as exc:
            fs.create("/Windows/System32/nope.txt", 0o644)
        assert exc.value.errno == errno.EACCES

    def test_escape_from_backing_root_is_refused(self, fs, as_uid):
        as_uid(CALLER)
        with pytest.raises(OSError) as exc:
            fs.getattr("/../../etc/passwd")
        assert exc.value.errno == errno.EACCES


class TestChmodIsGated:
    """The shim runs as root; an ungated chmod re-modes the whole drive."""

    def test_chmod_denied_without_wbit(self, fs, backing, as_uid):
        as_uid(CALLER)
        victim = backing / "Windows" / "System32" / "victim.exe"
        with pytest.raises(OSError) as exc:
            fs.chmod("/Windows/System32/victim.exe", 0o777)
        assert exc.value.errno == errno.EACCES
        assert stat.S_IMODE(victim.stat().st_mode) == 0o755

    def test_cannot_create_setuid_binary_even_when_granted(self, fs, backing, as_uid):
        as_uid(CALLER)
        target = backing / "sandbox" / "payload"
        target.write_text("#!/bin/sh\n")
        fs.chmod("/sandbox/payload", 0o4755)
        assert not target.stat().st_mode & stat.S_ISUID


class TestUtimensIsGated:
    def test_utimens_denied_without_wbit(self, fs, backing, as_uid):
        as_uid(CALLER)
        victim = backing / "Windows" / "System32" / "victim.exe"
        os.utime(victim, (1000, 1000))
        with pytest.raises(OSError) as exc:
            fs.utimens("/Windows/System32/victim.exe", (999999999, 999999999))
        assert exc.value.errno == errno.EACCES
        assert int(victim.stat().st_mtime) == 1000

    def test_utimens_allowed_with_wbit(self, fs, backing, as_uid):
        as_uid(CALLER)
        target = backing / "sandbox" / "t.txt"
        target.write_text("")
        fs.utimens("/sandbox/t.txt", (999999999, 999999999))
        assert int(target.stat().st_mtime) == 999999999


class TestHardLinkEscape:
    """A second name must not confer rights the first name did not have."""

    def test_link_denied_when_source_has_no_wbit(self, fs, backing, as_uid):
        as_uid(CALLER)
        with pytest.raises(OSError) as exc:
            fs.link("/sandbox/pwned", "/Windows/System32/victim.exe")
        assert exc.value.errno == errno.EACCES
        assert not (backing / "sandbox" / "pwned").exists()

    def test_protected_file_cannot_be_rewritten_via_a_granted_directory(
        self, fs, backing, as_uid
    ):
        as_uid(CALLER)
        victim = backing / "Windows" / "System32" / "victim.exe"
        with pytest.raises(OSError):
            fs.link("/sandbox/pwned", "/Windows/System32/victim.exe")
        assert victim.read_text() == "trusted"

    def test_link_allowed_when_both_ends_are_granted(self, fs, backing, as_uid):
        as_uid(CALLER)
        src = backing / "sandbox" / "src.txt"
        src.write_text("mine")
        fs.link("/sandbox/copy.txt", "/sandbox/src.txt")
        assert (backing / "sandbox" / "copy.txt").exists()


class TestSymlinkEscape:
    def test_symlink_target_outside_grant_is_not_writable_through_the_link(
        self, fs, backing, as_uid
    ):
        """The kernel re-resolves symlinks, so the shim sees the real path; this
        pins the behaviour so a future readlink change cannot regress it."""
        as_uid(CALLER)
        fs.symlink("/sandbox/escape", "/Windows/System32/victim.exe")
        with pytest.raises(OSError) as exc:
            fs.open("/Windows/System32/victim.exe", os.O_WRONLY)
        assert exc.value.errno == errno.EACCES


class TestRootHandling:
    def test_chown_guard_uses_real_uid_not_remapped_uid(
        self, fs, backing, as_uid, monkeypatch
    ):
        """With root remapped to the launching user, a guard on the remapped uid
        would make chown unreachable for genuine root."""
        monkeypatch.setattr(shim_mod, "LAUNCHER_UID", LAUNCHER)
        target = backing / "sandbox" / "owned.txt"
        target.write_text("")
        as_uid(0)
        fs.chown("/sandbox/owned.txt", os.getuid(), os.getgid())

    def test_non_root_chown_still_refused(self, fs, backing, as_uid):
        as_uid(CALLER)
        target = backing / "sandbox" / "owned.txt"
        target.write_text("")
        with pytest.raises(OSError) as exc:
            fs.chown("/sandbox/owned.txt", 0, 0)
        assert exc.value.errno == errno.EPERM

    def test_root_inherits_launcher_grants(self, fs, as_uid, monkeypatch):
        monkeypatch.setattr(shim_mod, "LAUNCHER_UID", LAUNCHER)
        as_uid(0)
        fh = fs.create("/sandbox/root-made.txt", 0o644)
        fs.release("/sandbox/root-made.txt", fh)
        with pytest.raises(OSError) as exc:
            fs.create("/Windows/System32/root-made.txt", 0o644)
        assert exc.value.errno == errno.EACCES


class TestWriteFlagCoverage:
    @pytest.mark.parametrize(
        "flags",
        [os.O_WRONLY, os.O_RDWR, os.O_WRONLY | os.O_APPEND, os.O_RDONLY | os.O_TRUNC],
    )
    def test_every_write_intent_flag_is_gated(self, fs, as_uid, flags):
        as_uid(CALLER)
        with pytest.raises(OSError) as exc:
            fs.open("/Windows/System32/victim.exe", flags)
        assert exc.value.errno == errno.EACCES

    def test_read_only_open_is_not_gated(self, fs, as_uid):
        as_uid(CALLER)
        fh = fs.open("/Windows/System32/victim.exe", os.O_RDONLY)
        try:
            assert fs.read("/Windows/System32/victim.exe", 100, 0, fh) == b"trusted"
        finally:
            fs.release("/Windows/System32/victim.exe", fh)


class TestDenialsAreLogged:
    def test_denial_emits_a_warning_with_uid_and_path(self, fs, as_uid, caplog):
        as_uid(CALLER)
        with caplog.at_level("WARNING", logger="ugow"):
            with pytest.raises(OSError):
                fs.open("/Windows/System32/victim.exe", os.O_WRONLY)
        messages = [r.getMessage() for r in caplog.records]
        assert any("deny open" in m for m in messages)
        assert any("uid=1000" in m for m in messages)
        assert any("/mnt/c/Windows/System32/victim.exe" in m for m in messages)
