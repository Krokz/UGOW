import threading
import pytest
from shim import PermStore


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
