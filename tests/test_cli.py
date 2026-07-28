import os
import sys
import types
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cli import resolve_user, _validate_drive, _active_backends, require_root
from permstore import PermStore


# ---------------------------------------------------------------------------
# resolve_user
# ---------------------------------------------------------------------------

class TestResolveUser:
    def test_numeric_uid_existing(self):
        uid, name = resolve_user("0")
        assert uid == 0
        assert isinstance(name, str)

    def test_numeric_uid_nonexistent(self):
        uid, name = resolve_user("99999")
        assert uid == 99999
        assert name == "99999"

    def test_name_root(self):
        uid, name = resolve_user("root")
        assert uid == 0
        assert name == "root"

    def test_unknown_name_exits(self):
        with pytest.raises(SystemExit) as exc:
            resolve_user("__no_such_user_ever__")
        assert exc.value.code == 1


# ---------------------------------------------------------------------------
# _validate_drive
# ---------------------------------------------------------------------------

class TestValidateDrive:
    def test_single_letter(self):
        assert _validate_drive("c") == "c"

    def test_uppercase(self):
        assert _validate_drive("D") == "d"

    def test_with_colon(self):
        assert _validate_drive("E:") == "e"

    def test_invalid_multi_char(self):
        with pytest.raises(SystemExit):
            _validate_drive("cd")

    def test_invalid_number(self):
        with pytest.raises(SystemExit):
            _validate_drive("1")


# ---------------------------------------------------------------------------
# _active_backends
# ---------------------------------------------------------------------------

class TestActiveBackends:
    def test_always_includes_sqlite(self, monkeypatch):
        monkeypatch.setattr("cli._bpf_active", lambda: False)
        monkeypatch.setattr("cli._kmod_active", lambda: False)
        assert _active_backends() == ["sqlite"]

    def test_includes_bpf(self, monkeypatch):
        monkeypatch.setattr("cli._bpf_active", lambda: True)
        monkeypatch.setattr("cli._kmod_active", lambda: False)
        assert _active_backends() == ["sqlite", "bpf"]

    def test_includes_kmod(self, monkeypatch):
        monkeypatch.setattr("cli._bpf_active", lambda: False)
        monkeypatch.setattr("cli._kmod_active", lambda: True)
        assert _active_backends() == ["sqlite", "kmod"]

    def test_includes_both(self, monkeypatch):
        monkeypatch.setattr("cli._bpf_active", lambda: True)
        monkeypatch.setattr("cli._kmod_active", lambda: True)
        assert _active_backends() == ["sqlite", "bpf", "kmod"]


# ---------------------------------------------------------------------------
# require_root
# ---------------------------------------------------------------------------

class TestRequireRoot:
    def test_non_root_exits(self, monkeypatch):
        monkeypatch.setattr("os.getuid", lambda: 1000)
        with pytest.raises(SystemExit) as exc:
            require_root("allow")
        assert exc.value.code == 1

    def test_root_passes(self, monkeypatch):
        monkeypatch.setattr("os.getuid", lambda: 0)
        require_root("allow")


# ---------------------------------------------------------------------------
# cmd_allow / cmd_deny / cmd_check / cmd_list (integration via PermStore)
# ---------------------------------------------------------------------------

class TestCommandIntegration:
    @pytest.fixture()
    def tmp_db(self, tmp_path):
        return str(tmp_path / "test.db")

    @pytest.fixture()
    def fake_args(self, tmp_db):
        def _make(**kwargs):
            defaults = {"db": tmp_db, "mirror_acl": False}
            defaults.update(kwargs)
            return types.SimpleNamespace(**defaults)
        return _make

    def test_allow_and_check(self, monkeypatch, fake_args, tmp_path, capsys):
        from cli import cmd_allow, cmd_check

        monkeypatch.setattr("os.getuid", lambda: 0)
        monkeypatch.setattr("cli._bpf_active", lambda: False)
        monkeypatch.setattr("cli._kmod_active", lambda: False)

        target = str(tmp_path / "data")
        os.makedirs(target, exist_ok=True)

        cmd_allow(fake_args(user="0", path=target))
        captured = capsys.readouterr()
        assert "Allowed" in captured.out

        with pytest.raises(SystemExit) as exc:
            cmd_check(fake_args(path=target))
        assert exc.value.code == 0

    def test_deny_removes_grant(self, monkeypatch, fake_args, tmp_path, capsys):
        from cli import cmd_allow, cmd_deny, cmd_check

        monkeypatch.setattr("os.getuid", lambda: 0)
        monkeypatch.setattr("cli._bpf_active", lambda: False)
        monkeypatch.setattr("cli._kmod_active", lambda: False)

        target = str(tmp_path / "data")
        os.makedirs(target, exist_ok=True)

        cmd_allow(fake_args(user="0", path=target))
        cmd_deny(fake_args(user="0", path=target))

        with pytest.raises(SystemExit) as exc:
            cmd_check(fake_args(path=target))
        assert exc.value.code == 1

    def test_list_shows_grants(self, monkeypatch, fake_args, tmp_path, capsys):
        from cli import cmd_allow, cmd_list

        monkeypatch.setattr("os.getuid", lambda: 0)
        monkeypatch.setattr("cli._bpf_active", lambda: False)
        monkeypatch.setattr("cli._kmod_active", lambda: False)

        target = str(tmp_path / "data")
        os.makedirs(target, exist_ok=True)

        cmd_allow(fake_args(user="0", path=target))
        cmd_list(fake_args())
        captured = capsys.readouterr()
        assert target in captured.out

    def test_list_empty(self, monkeypatch, fake_args, capsys):
        from cli import cmd_list

        monkeypatch.setattr("os.getuid", lambda: 0)
        monkeypatch.setattr("cli._bpf_active", lambda: False)
        monkeypatch.setattr("cli._kmod_active", lambda: False)

        cmd_list(fake_args())
        captured = capsys.readouterr()
        assert "No grants" in captured.out

    def test_check_uses_sudo_uid(self, monkeypatch, fake_args, tmp_path, capsys):
        """cmd_check should use SUDO_UID when running as root via sudo."""
        from cli import cmd_allow, cmd_check

        monkeypatch.setattr("os.getuid", lambda: 0)
        monkeypatch.setenv("SUDO_UID", "1000")
        monkeypatch.setattr("cli._bpf_active", lambda: False)
        monkeypatch.setattr("cli._kmod_active", lambda: False)

        target = str(tmp_path / "chkdata")
        os.makedirs(target, exist_ok=True)

        cmd_allow(fake_args(user="1000", path=target))

        with pytest.raises(SystemExit) as exc:
            cmd_check(fake_args(path=target))
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "uid=1000" in captured.out
        assert "CAN write" in captured.out

    def test_check_user_flag(self, monkeypatch, fake_args, tmp_path, capsys):
        """cmd_check --user should check the specified user."""
        from cli import cmd_allow, cmd_check

        monkeypatch.setattr("os.getuid", lambda: 0)
        monkeypatch.setattr("cli._bpf_active", lambda: False)
        monkeypatch.setattr("cli._kmod_active", lambda: False)

        target = str(tmp_path / "chkuser")
        os.makedirs(target, exist_ok=True)

        cmd_allow(fake_args(user="0", path=target))

        with pytest.raises(SystemExit) as exc:
            cmd_check(fake_args(path=target, user="0"))
        assert exc.value.code == 0

        with pytest.raises(SystemExit) as exc:
            cmd_check(fake_args(path=target, user="99999"))
        assert exc.value.code == 1

    def test_status_shows_covering_grant(self, monkeypatch, fake_args, tmp_path, capsys):
        from cli import cmd_allow, cmd_status

        monkeypatch.setattr("os.getuid", lambda: 0)
        monkeypatch.setattr("cli._bpf_active", lambda: False)
        monkeypatch.setattr("cli._kmod_active", lambda: False)

        parent = str(tmp_path / "parent")
        os.makedirs(parent, exist_ok=True)
        child = os.path.join(parent, "child")

        cmd_allow(fake_args(user="0", path=parent))
        cmd_status(fake_args(path=child))
        captured = capsys.readouterr()
        assert "via" in captured.out


class TestBackendOrdering:
    """A grant must not land in SQLite unless the active kernel backend took it."""

    @pytest.fixture()
    def tmp_db(self, tmp_path):
        return str(tmp_path / "order.db")

    @pytest.fixture()
    def fake_args(self, tmp_db):
        def _make(**kwargs):
            defaults = {"db": tmp_db, "mirror_acl": False}
            defaults.update(kwargs)
            return types.SimpleNamespace(**defaults)
        return _make

    def test_failed_backend_aborts_the_grant(
        self, monkeypatch, fake_args, tmp_db, tmp_path, capsys
    ):
        from cli import cmd_allow

        monkeypatch.setattr("os.getuid", lambda: 0)
        monkeypatch.setattr("cli._bpf_active", lambda: True)
        monkeypatch.setattr("cli._kmod_active", lambda: False)
        monkeypatch.setattr("cli._bpf_grant", lambda uid, path: "BPF grant failed: nope")

        target = str(tmp_path / "data")
        os.makedirs(target, exist_ok=True)

        with pytest.raises(SystemExit) as exc:
            cmd_allow(fake_args(user="0", path=target))
        assert exc.value.code == 1

        # Nothing was written, so `check` cannot claim a permission that the
        # kernel would refuse.
        assert PermStore(db_path=tmp_db, mirror_acl=False).has_wbit(target, 0) is False

    def test_successful_backend_commits_the_grant(
        self, monkeypatch, fake_args, tmp_db, tmp_path
    ):
        from cli import cmd_allow

        monkeypatch.setattr("os.getuid", lambda: 0)
        monkeypatch.setattr("cli._bpf_active", lambda: True)
        monkeypatch.setattr("cli._kmod_active", lambda: False)
        monkeypatch.setattr("cli._bpf_grant", lambda uid, path: None)
        monkeypatch.setattr("cli._relax_dac_for_bpf", lambda store, path: None)

        target = str(tmp_path / "data")
        os.makedirs(target, exist_ok=True)
        cmd_allow(fake_args(user="0", path=target))
        assert PermStore(db_path=tmp_db, mirror_acl=False).has_wbit(target, 0) is True

    def test_deny_still_revokes_when_backend_errors(
        self, monkeypatch, fake_args, tmp_db, tmp_path
    ):
        """A backend error on revoke must not leave the permission in place."""
        from cli import cmd_deny

        monkeypatch.setattr("os.getuid", lambda: 0)
        monkeypatch.setattr("cli._bpf_active", lambda: True)
        monkeypatch.setattr("cli._kmod_active", lambda: False)
        monkeypatch.setattr("cli._bpf_revoke", lambda uid, path: "BPF revoke failed")
        monkeypatch.setattr("cli._restore_dac_after_bpf", lambda store, path: None)

        target = str(tmp_path / "data")
        os.makedirs(target, exist_ok=True)
        PermStore(db_path=tmp_db, mirror_acl=False).grant(target, 0)

        with pytest.raises(SystemExit) as exc:
            cmd_deny(fake_args(user="0", path=target))
        assert exc.value.code == 1
        assert PermStore(db_path=tmp_db, mirror_acl=False).has_wbit(target, 0) is False


class TestDacRestore:
    """BPF mode widens DAC; leaving it widened after a revoke is an open door."""

    def test_original_mode_is_restored_on_last_revoke(self, tmp_path):
        from cli import _relax_dac_for_bpf, _restore_dac_after_bpf

        store = PermStore(db_path=str(tmp_path / "dac.db"), mirror_acl=False)
        target = tmp_path / "restricted"
        target.mkdir()
        target.chmod(0o700)

        store.grant(str(target), 1000)
        _relax_dac_for_bpf(store, str(target))
        assert target.stat().st_mode & 0o222 == 0o222

        store.revoke(str(target), 1000)
        _restore_dac_after_bpf(store, str(target))
        assert target.stat().st_mode & 0o777 == 0o700

    def test_mode_kept_while_another_uid_still_holds_a_grant(self, tmp_path):
        from cli import _relax_dac_for_bpf, _restore_dac_after_bpf

        store = PermStore(db_path=str(tmp_path / "dac.db"), mirror_acl=False)
        target = tmp_path / "shared"
        target.mkdir()
        target.chmod(0o700)

        store.grant(str(target), 1000)
        store.grant(str(target), 2000)
        _relax_dac_for_bpf(store, str(target))

        store.revoke(str(target), 1000)
        _restore_dac_after_bpf(store, str(target))
        assert target.stat().st_mode & 0o222 == 0o222

        store.revoke(str(target), 2000)
        _restore_dac_after_bpf(store, str(target))
        assert target.stat().st_mode & 0o777 == 0o700

    def test_already_writable_path_is_not_recorded(self, tmp_path):
        from cli import _relax_dac_for_bpf

        store = PermStore(db_path=str(tmp_path / "dac.db"), mirror_acl=False)
        target = tmp_path / "open"
        target.mkdir()
        target.chmod(0o777)
        _relax_dac_for_bpf(store, str(target))
        assert store.forget_dac_mode(str(target)) is None


class TestKmodKey:
    """The kmod compares superblock-relative paths, so the CLI must send those."""

    def test_key_is_dev_plus_superblock_relative_path(self, monkeypatch, tmp_path):
        from cli import _kmod_key

        monkeypatch.setattr("cli._mount_point", lambda p: "/mnt/c")
        fake = os.stat_result((0o40755, 1, os.makedev(0, 52), 1, 0, 0, 0, 0, 0, 0))
        monkeypatch.setattr("os.stat", lambda p: fake)

        dev, rel = _kmod_key("/mnt/c/docker/sub")
        assert dev == "0:52"
        assert rel == "/docker/sub"

    def test_mount_root_maps_to_slash(self, monkeypatch):
        from cli import _kmod_key

        monkeypatch.setattr("cli._mount_point", lambda p: "/mnt/c")
        fake = os.stat_result((0o40755, 1, os.makedev(0, 52), 1, 0, 0, 0, 0, 0, 0))
        monkeypatch.setattr("os.stat", lambda p: fake)

        dev, rel = _kmod_key("/mnt/c")
        assert rel == "/"

    def test_missing_path_is_reported_not_raised(self, monkeypatch):
        from cli import _kmod_write

        monkeypatch.setattr("cli._mount_point", lambda p: "/mnt/c")
        err = _kmod_write("grant", 1000, "/mnt/c/does-not-exist")
        assert err is not None
        assert "exist" in err


class TestMissingHelperBinary:
    def test_absent_bpftool_reports_instead_of_tracebacking(self, monkeypatch, tmp_path):
        from cli import _bpf_grant

        def boom(*a, **k):
            raise FileNotFoundError("bpftool")

        monkeypatch.setattr("subprocess.run", boom)
        target = tmp_path / "x"
        target.mkdir()
        err = _bpf_grant(1000, str(target))
        assert err is not None
        assert "bpftool" in err


# ---------------------------------------------------------------------------
# main() arg dispatch
# ---------------------------------------------------------------------------

class TestMainDispatch:
    def test_no_command_exits(self, monkeypatch):
        from cli import main
        monkeypatch.setattr("sys.argv", ["ugow"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

    def test_help_exits(self, monkeypatch):
        from cli import main
        monkeypatch.setattr("sys.argv", ["ugow", "--help"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
