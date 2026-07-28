#!/usr/bin/env python3
"""
UGOW permission store -- SQLite-backed, thread-safe W-bit grant management.

Shared by the CLI, FUSE shim, and BPF manager. Has no dependency on fusepy.
"""

import os
import shutil
import sqlite3
import subprocess
import logging
import threading
import time
import queue
from collections import OrderedDict

DEFAULT_DB_PATH = "/var/lib/ugow/wperm.db"

_POWERSHELL_SEARCH = [
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    "/mnt/c/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell.exe",
]


class AclMirrorUnavailable(RuntimeError):
    """Raised when ACL mirroring is requested but cannot be performed.

    A library must not call sys.exit on its caller's behalf -- the FUSE daemon
    imports this module too, and would die at startup with no explanation.
    """


def _find_powershell():
    """Locate powershell.exe, which sudo may hide by stripping Windows paths."""
    found = shutil.which("powershell.exe")
    if found:
        return found
    for p in _POWERSHELL_SEARCH:
        if os.path.isfile(p):
            return p
    return "powershell.exe"

_WBIT_CACHE_TTL = 2.0
_WBIT_CACHE_MAX = 8192
_DB_WATCH_INTERVAL = 0.5
_ACL_CMD_TIMEOUT = 30
_ACL_FLUSH_TIMEOUT = 60.0

log = logging.getLogger("ugow")


def kernel_dev(st_dev):
    """Convert a stat() st_dev into the kernel's internal dev_t.

    These are two different encodings and they are easy to confuse. What the
    kernel keeps in super_block->s_dev -- the value BPF programs read -- is
    MKDEV(major, minor) == (major << 20) | minor. What stat() hands userspace is
    new_encode_dev(): (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12).

    They happen to agree for major 0 and minor < 256, which covers a freshly
    booted WSL2 /mnt/c and hides the mistake. They diverge as soon as anonymous
    superblocks push a minor past 255, at which point a key built from the raw
    st_dev matches nothing and enforcement silently stops applying.
    """
    return (os.major(st_dev) << 20) | os.minor(st_dev)


def normalize_path(path):
    """Canonical form used as a grant key.

    Grants are matched by walking a path's ancestors, and that walk never
    produces a trailing slash -- so an unnormalized 'a/b/' would be stored as a
    row that can never match anything.
    """
    if not path:
        return path
    normalized = os.path.normpath(path)
    return normalized


def path_to_win(path):
    """Convert a Linux /mnt/<drive>/... path to a Windows drive letter path.

    Only single-letter components are treated as drives: /mnt also holds real
    WSL mounts such as /mnt/wsl and /mnt/wslg that are not Windows drives.
    """
    parts = path.split(os.sep)
    if (
        len(parts) > 2
        and parts[1].lower() == "mnt"
        and len(parts[2]) == 1
        and parts[2].isalpha()
    ):
        drive = parts[2].upper()
        rest = parts[3:]
        return drive + ":\\" + "\\".join(rest)
    return path


def _check_windows_admin():
    """Check if the current Windows session has Administrator privileges."""
    ps = _find_powershell()
    try:
        r = subprocess.run(
            [ps, "-Command",
             "([Security.Principal.WindowsPrincipal]"
             "[Security.Principal.WindowsIdentity]::GetCurrent())"
             ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0 and r.stdout.strip() == "True"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _path_ancestors(path):
    """Yield path and all its ancestor directories up to the root."""
    current = path
    while True:
        yield current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent


# ---------------------------------------------------------------------------
# Permission store (SQLite-backed, thread-safe, optional ACL mirroring)
# ---------------------------------------------------------------------------

class PermStore:
    def __init__(self, db_path=DEFAULT_DB_PATH, mirror_acl=False, watch_db=False):
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._db_path = db_path
        self._local = threading.local()
        self._mirror_acl = mirror_acl
        self._wbit_cache = OrderedDict()
        self._wbit_cache_lock = threading.Lock()
        self._conns_lock = threading.Lock()
        self._thread_conns = []
        self._stop = threading.Event()

        conn = self._conn()
        conn.execute(
            "CREATE TABLE IF NOT EXISTS wperms ("
            "  path TEXT NOT NULL,"
            "  uid  INTEGER NOT NULL,"
            "  PRIMARY KEY (path, uid)"
            ")"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_wperms_path ON wperms(path)"
        )
        # BPF mode widens DAC permissions so the LSM is the only gate. The
        # pre-existing mode is recorded here so revoking a grant can put it
        # back instead of leaving the path world-writable forever.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS dac_modes ("
            "  path TEXT PRIMARY KEY,"
            "  mode INTEGER NOT NULL"
            ")"
        )
        conn.commit()

        self._acl_queue = None
        self._acl_thread = None
        if mirror_acl:
            if not _check_windows_admin():
                raise AclMirrorUnavailable(
                    "--mirror-acl requires Windows Administrator privileges.\n"
                    "  Launch Windows Terminal as Administrator, then run 'wsl' and retry."
                )
            self._acl_queue = queue.Queue()
            self._acl_thread = threading.Thread(
                target=self._acl_worker, daemon=True
            )
            self._acl_thread.start()

        # Long-lived consumers (the FUSE daemon) hold their own cache that
        # other processes -- the `ugow` CLI -- can't reach to invalidate. Poll
        # SQLite's data_version (changes only on commits by *other*
        # connections) off the hot path and flush the cache when it moves.
        if watch_db:
            t = threading.Thread(target=self._db_watch_worker, daemon=True)
            t.start()

    def _conn(self):
        """Return a per-thread SQLite connection (required by sqlite3)."""
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
            with self._conns_lock:
                self._thread_conns.append(conn)
        return self._local.conn

    def close(self):
        """Stop background workers and close SQLite connections.

        A connection created on another thread cannot be closed from here --
        sqlite3 rejects cross-thread use -- so those are left to be reclaimed
        when their thread exits.
        """
        self._stop.set()
        with self._conns_lock:
            conns, self._thread_conns = self._thread_conns, []
        for conn in conns:
            try:
                conn.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def has_wbit(self, path, uid):
        cache_key = (normalize_path(path), uid)
        now = time.monotonic()
        with self._wbit_cache_lock:
            entry = self._wbit_cache.get(cache_key)
            if entry is not None:
                if now - entry[1] < _WBIT_CACHE_TTL:
                    self._wbit_cache.move_to_end(cache_key)
                    return entry[0]
                del self._wbit_cache[cache_key]

        ancestors = list(_path_ancestors(cache_key[0]))
        placeholders = ",".join("?" for _ in ancestors)
        row = self._conn().execute(
            f"SELECT 1 FROM wperms WHERE uid=? AND path IN ({placeholders}) LIMIT 1",
            [uid] + ancestors,
        ).fetchone()
        result = row is not None

        with self._wbit_cache_lock:
            self._wbit_cache[cache_key] = (result, now)
            self._wbit_cache.move_to_end(cache_key)
            # Evict strictly-oldest entries. Filtering by TTL instead would drop
            # nothing during a burst (every entry is still fresh) and re-copy the
            # whole mapping on every subsequent lookup, under this lock.
            while len(self._wbit_cache) > _WBIT_CACHE_MAX:
                self._wbit_cache.popitem(last=False)
        return result

    def _db_watch_worker(self):
        """Flush the W-bit cache when another connection commits a change.

        Uses a dedicated connection (sqlite3 connections are single-thread).
        `PRAGMA data_version` is a header read -- no table scan -- so this is
        far cheaper than re-running grant lookups, and it stays off the
        has_wbit() hot path entirely.
        """
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        last = conn.execute("PRAGMA data_version").fetchone()[0]
        try:
            while not self._stop.wait(_DB_WATCH_INTERVAL):
                try:
                    current = conn.execute("PRAGMA data_version").fetchone()[0]
                    if current != last:
                        last = current
                        with self._wbit_cache_lock:
                            self._wbit_cache.clear()
                except Exception:
                    log.exception("db watch error")
        finally:
            conn.close()

    def _invalidate_cache_for(self, path, uid):
        """Remove cache entries for path and all its descendants for uid."""
        prefix = path if path.endswith("/") else path + "/"
        with self._wbit_cache_lock:
            to_remove = [
                k for k in self._wbit_cache
                if k[1] == uid and (k[0] == path or k[0].startswith(prefix))
            ]
            for k in to_remove:
                del self._wbit_cache[k]

    def grant(self, path, uid):
        path = normalize_path(path)
        conn = self._conn()
        conn.execute(
            "INSERT OR IGNORE INTO wperms (path, uid) VALUES (?, ?)",
            (path, uid),
        )
        conn.commit()
        self._invalidate_cache_for(path, uid)
        if self._acl_queue is not None:
            self._acl_queue.put(("grant", path, uid))
        log.info("grant uid=%d path=%s", uid, path)

    def revoke(self, path, uid):
        path = normalize_path(path)
        conn = self._conn()
        conn.execute(
            "DELETE FROM wperms WHERE path=? AND uid=?", (path, uid)
        )
        conn.commit()
        self._invalidate_cache_for(path, uid)
        if self._acl_queue is not None:
            self._acl_queue.put(("revoke", path, uid))
        log.info("revoke uid=%d path=%s", uid, path)

    def has_any_grant(self, path):
        """True if any uid holds a grant on this exact path."""
        path = normalize_path(path)
        row = self._conn().execute(
            "SELECT 1 FROM wperms WHERE path=? LIMIT 1", (path,)
        ).fetchone()
        return row is not None

    # -- DAC mode bookkeeping (BPF mode) ------------------------------------

    def remember_dac_mode(self, path, mode):
        """Record a path's original mode, once, before it is widened."""
        path = normalize_path(path)
        conn = self._conn()
        conn.execute(
            "INSERT OR IGNORE INTO dac_modes (path, mode) VALUES (?, ?)",
            (path, int(mode)),
        )
        conn.commit()

    def forget_dac_mode(self, path):
        """Remove and return a path's recorded original mode, if any."""
        path = normalize_path(path)
        conn = self._conn()
        row = conn.execute(
            "SELECT mode FROM dac_modes WHERE path=?", (path,)
        ).fetchone()
        if row is None:
            return None
        conn.execute("DELETE FROM dac_modes WHERE path=?", (path,))
        conn.commit()
        return row[0]

    def list_grants(self, uid=None):
        conn = self._conn()
        if uid is not None:
            return conn.execute(
                "SELECT path, uid FROM wperms WHERE uid=? ORDER BY path",
                (uid,),
            ).fetchall()
        return conn.execute(
            "SELECT path, uid FROM wperms ORDER BY path, uid"
        ).fetchall()

    # -- ACL mirroring (background thread) ----------------------------------

    @staticmethod
    def _ps_escape(s):
        """Escape a string for use inside a PowerShell single-quoted literal."""
        return s.replace("'", "''")

    def _acl_worker(self):
        while True:
            try:
                action, path, uid = self._acl_queue.get()
                win_user = f"wsl_{uid}"
                win_path = self._ps_escape(path_to_win(path))

                if action == "grant":
                    # The account exists only as an ACL principal -- nothing
                    # ever authenticates as it -- so give it a random password
                    # and disable it rather than leaving a passwordless local
                    # account on the host. A disabled account's SID still
                    # resolves in ACLs.
                    ps = (
                        f"if (-Not (Get-LocalUser -Name '{win_user}' "
                        f"-ErrorAction SilentlyContinue)) {{ "
                        f"$pw = ConvertTo-SecureString -AsPlainText -Force "
                        f"-String ([Guid]::NewGuid().ToString() + "
                        f"[Guid]::NewGuid().ToString()); "
                        f"New-LocalUser -Name '{win_user}' -Password $pw "
                        f"-PasswordNeverExpires -AccountNeverExpires "
                        f"-Description 'UGOW ACL principal for WSL uid "
                        f"{uid} (no interactive logon)' | Out-Null; "
                        f"Disable-LocalUser -Name '{win_user}' "
                        f"}}; "
                        f"icacls '{win_path}' /grant "
                        f"'{win_user}:(OI)(CI)F' /T"
                    )
                elif action == "revoke":
                    # No /T: the grant was inheritable ((OI)(CI)), so removing
                    # the explicit ACE here also drops the inherited ones from
                    # descendants. Recursing instead would delete explicit ACEs
                    # belonging to still-valid grants on subdirectories.
                    ps = (
                        f"icacls '{win_path}' /remove:g '{win_user}'"
                    )
                else:
                    continue

                result = subprocess.run(
                    [_find_powershell(), "-Command", ps],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    err = (result.stderr or result.stdout or "").strip()
                    log.warning(
                        "ACL mirror %s failed for %s (uid %d): %s",
                        action, path, uid, err,
                    )
            except subprocess.TimeoutExpired:
                log.warning(
                    "ACL mirror %s timed out for %s (uid %d)",
                    action, path, uid,
                )
            except Exception:
                log.exception("ACL worker error")
            finally:
                self._acl_queue.task_done()

    def flush_acl(self, timeout=_ACL_FLUSH_TIMEOUT):
        """Wait for pending ACL operations, but never block indefinitely.

        An unbounded join() here would hang the CLI forever if the worker thread
        has died, so give up after *timeout* and report it instead.
        """
        if self._acl_queue is None:
            return True
        deadline = time.monotonic() + timeout
        while getattr(self._acl_queue, "unfinished_tasks", 0):
            if self._acl_thread is not None and not self._acl_thread.is_alive():
                log.error("ACL mirror worker is not running; %d operation(s) "
                          "were not applied",
                          getattr(self._acl_queue, "unfinished_tasks", 0))
                return False
            if time.monotonic() > deadline:
                log.warning("ACL mirror still busy after %.0fs; %d operation(s) "
                            "pending", timeout,
                            getattr(self._acl_queue, "unfinished_tasks", 0))
                return False
            time.sleep(0.05)
        return True

    def cleanup_acl(self):
        """Remove Windows wsl_* users whose UID has zero grants in the DB."""
        active_uids = {
            row[0]
            for row in self._conn().execute("SELECT DISTINCT uid FROM wperms")
        }
        result = subprocess.run(
            [
                _find_powershell(), "-Command",
                "Get-LocalUser | Where-Object { $_.Name -like 'wsl_*' } "
                "| Select-Object -ExpandProperty Name",
            ],
            capture_output=True,
            text=True,
            timeout=_ACL_CMD_TIMEOUT,
        )
        if result.returncode != 0:
            log.error("Failed to list wsl_* users: %s", result.stderr.strip())
            return

        for line in result.stdout.strip().splitlines():
            name = line.strip()
            if not name.startswith("wsl_"):
                continue
            try:
                uid = int(name[4:])
            except ValueError:
                continue
            if uid not in active_uids:
                rm = subprocess.run(
                    [
                        _find_powershell(), "-Command",
                        f"Remove-LocalUser -Name '{self._ps_escape(name)}' "
                        f"-ErrorAction SilentlyContinue",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=_ACL_CMD_TIMEOUT,
                )
                if rm.returncode == 0:
                    log.info("Removed stale Windows user: %s", name)
                else:
                    log.warning(
                        "Failed to remove %s: %s", name, rm.stderr.strip()
                    )
