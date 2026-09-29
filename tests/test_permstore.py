import os
import time
import threading
import pytest
import permstore as permstore_mod
from shim import PermStore
from permstore import _WBIT_CACHE_MAX, normalize_path


class TestGrantRevoke:
    def test_grant_then_has_wbit(self, store):
        store.grant("/mnt/c/data", 1000)
        assert store.has_wbit("/mnt/c/data", 1000) is True

    def test_no_grant_means_no_wbit(self, store):
        assert store.has_wbit("/mnt/c/data", 1000) is False

    def test_revoke_removes_wbit(self, store):
        store.grant("/mnt/c/data", 1000)
        store.revoke("/mnt/c/data", 1000)
        assert store.has_wbit("/mnt/c/data", 1000) is False

    def test_revoke_nonexistent_is_noop(self, store):
        store.revoke("/mnt/c/data", 9999)

    def test_double_grant_is_idempotent(self, store):
        store.grant("/mnt/c/data", 1000)
        store.grant("/mnt/c/data", 1000)
        assert store.has_wbit("/mnt/c/data", 1000) is True
        store.revoke("/mnt/c/data", 1000)
        assert store.has_wbit("/mnt/c/data", 1000) is False

    def test_separate_uids(self, store):
        store.grant("/mnt/c/data", 1000)
        assert store.has_wbit("/mnt/c/data", 1000) is True
        assert store.has_wbit("/mnt/c/data", 2000) is False


class TestInheritance:
    def test_child_inherits_parent_wbit(self, store):
        store.grant("/mnt/c/data", 1000)
        assert store.has_wbit("/mnt/c/data/sub/file.txt", 1000) is True

    def test_grandchild_inherits(self, store):
        store.grant("/mnt/c", 1000)
        assert store.has_wbit("/mnt/c/a/b/c/d/e", 1000) is True

    def test_sibling_not_granted(self, store):
        store.grant("/mnt/c/data", 1000)
        assert store.has_wbit("/mnt/c/other", 1000) is False

    def test_parent_not_granted_by_child(self, store):
        store.grant("/mnt/c/data/sub", 1000)
        assert store.has_wbit("/mnt/c/data", 1000) is False

    def test_root_grant_covers_everything(self, store):
        store.grant("/", 1000)
        assert store.has_wbit("/any/path/at/all", 1000) is True


class TestListGrants:
    def test_list_all(self, store):
        store.grant("/mnt/c/a", 1000)
        store.grant("/mnt/c/b", 2000)
        grants = store.list_grants()
        assert len(grants) == 2
        paths = {p for p, _ in grants}
        assert paths == {"/mnt/c/a", "/mnt/c/b"}

    def test_list_by_uid(self, store):
        store.grant("/mnt/c/a", 1000)
        store.grant("/mnt/c/b", 2000)
        grants = store.list_grants(uid=1000)
        assert len(grants) == 1
        assert grants[0] == ("/mnt/c/a", 1000)

    def test_list_empty(self, store):
        assert store.list_grants() == []


class TestCrossProcessCacheCoherence:
    def test_external_grant_visible_with_watch_db(self, tmp_db):
        """A grant written by another connection (e.g. the CLI) must become
        visible to a long-lived watch_db store after its cache would have
        served a stale 'denied'."""
        daemon = PermStore(db_path=tmp_db, mirror_acl=False, watch_db=True)
        # Prime the cache with a negative result.
        assert daemon.has_wbit("/mnt/c/data", 1000) is False

        # Simulate the CLI: a separate store grants on the same DB.
        cli = PermStore(db_path=tmp_db, mirror_acl=False)
        cli.grant("/mnt/c/data", 1000)

        # The watcher polls every 0.5s; give it a bounded window to flush.
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if daemon.has_wbit("/mnt/c/data", 1000) is True:
                break
            time.sleep(0.05)
        assert daemon.has_wbit("/mnt/c/data", 1000) is True


class TestPathNormalization:
    def test_trailing_slash_grant_still_matches(self, store):
        """An unnormalized grant would be a row no ancestor walk can ever hit."""
        store.grant("/mnt/c/data/", 1000)
        assert store.has_wbit("/mnt/c/data", 1000) is True
        assert store.has_wbit("/mnt/c/data/file", 1000) is True

    def test_redundant_separators_normalized(self, store):
        store.grant("/mnt/c//data/./sub", 1000)
        assert store.has_wbit("/mnt/c/data/sub", 1000) is True

    def test_revoke_matches_unnormalized_form(self, store):
        store.grant("/mnt/c/data", 1000)
        store.revoke("/mnt/c/data/", 1000)
        assert store.has_wbit("/mnt/c/data", 1000) is False

    def test_lookup_normalizes_too(self, store):
        store.grant("/mnt/c/data", 1000)
        assert store.has_wbit("/mnt/c/data/", 1000) is True

    def test_normalize_path_keeps_root(self):
        assert normalize_path("/") == "/"


class TestCacheBound:
    def test_cache_is_hard_bounded_during_a_burst(self, tmp_db, monkeypatch):
        """The bound must hold even when no entry is old enough to expire --
        otherwise the eviction pass frees nothing and rescans on every lookup."""
        monkeypatch.setattr(permstore_mod.time, "monotonic", lambda: 1000.0)
        store = PermStore(db_path=tmp_db, mirror_acl=False)
        for i in range(_WBIT_CACHE_MAX * 2):
            store.has_wbit(f"/mnt/c/p{i}", 1000)
        assert len(store._wbit_cache) == _WBIT_CACHE_MAX

    def test_eviction_is_least_recently_used(self, tmp_db, monkeypatch):
        monkeypatch.setattr(permstore_mod.time, "monotonic", lambda: 1000.0)
        store = PermStore(db_path=tmp_db, mirror_acl=False)
        store.has_wbit("/mnt/c/keep-me", 1000)
        for i in range(_WBIT_CACHE_MAX - 1):
            store.has_wbit(f"/mnt/c/p{i}", 1000)
        # Re-touch the oldest entry so it becomes the most recently used.
        store.has_wbit("/mnt/c/keep-me", 1000)
        store.has_wbit("/mnt/c/overflow", 1000)
        assert ("/mnt/c/keep-me", 1000) in store._wbit_cache
        assert ("/mnt/c/p0", 1000) not in store._wbit_cache

    def test_stale_entry_is_refetched_after_ttl(self, tmp_db, monkeypatch):
        clock = {"t": 1000.0}
        monkeypatch.setattr(permstore_mod.time, "monotonic", lambda: clock["t"])
        store = PermStore(db_path=tmp_db, mirror_acl=False)
        assert store.has_wbit("/mnt/c/data", 1000) is False
        store._conn().execute(
            "INSERT INTO wperms (path, uid) VALUES (?, ?)", ("/mnt/c/data", 1000)
        )
        store._conn().commit()
        clock["t"] += permstore_mod._WBIT_CACHE_TTL + 0.1
        assert store.has_wbit("/mnt/c/data", 1000) is True


class TestDbPathHandling:
    def test_bare_filename_db_path(self, tmp_path, monkeypatch):
        """os.path.dirname('x.db') is '' -- makedirs('') raises."""
        monkeypatch.chdir(tmp_path)
        store = PermStore(db_path="wperm.db", mirror_acl=False)
        store.grant("/mnt/c/data", 1000)
        assert store.has_wbit("/mnt/c/data", 1000) is True
        assert os.path.exists(tmp_path / "wperm.db")


class TestConcurrency:
    def test_concurrent_grants(self, tmp_db):
        """Multiple threads granting simultaneously should not corrupt the DB."""
        store = PermStore(db_path=tmp_db, mirror_acl=False)
        errors = []

        def grant_range(start, count):
            try:
                for i in range(start, start + count):
                    store.grant(f"/mnt/c/path_{i}", i)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=grant_range, args=(i * 100, 100))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors during concurrent grants: {errors}"
        grants = store.list_grants()
        assert len(grants) == 400
