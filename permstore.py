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

DEFAULT_DB_PATH = "/var/lib/ugow/wperm.db"

_POWERSHELL_SEARCH = [
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    "/mnt/c/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell.exe",
]


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

log = logging.getLogger("ugow")


def path_to_win(path):
    """Convert a Linux /mnt/<drive>/... path to a Windows drive letter path."""
    parts = path.split(os.sep)
    if len(parts) > 2 and parts[1].lower() == "mnt":
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
    def __init__(self, db_path=DEFAULT_DB_PATH, mirror_acl=False):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._local = threading.local()
        self._mirror_acl = mirror_acl
        self._wbit_cache = {}
        self._wbit_cache_lock = threading.Lock()

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
        conn.commit()

        self._acl_queue = None
        if mirror_acl:
            if not _check_windows_admin():
                raise SystemExit(
                    "Error: --mirror-acl requires Windows Administrator privileges.\n"
                    "  Launch Windows Terminal as Administrator, then run 'wsl' and retry."
                )
            self._acl_queue = queue.Queue()
            t = threading.Thread(target=self._acl_worker, daemon=True)
            t.start()

    def _conn(self):
        """Return a per-thread SQLite connection (required by sqlite3)."""
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
            with self._wbit_cache_lock:
                if not hasattr(self, "_thread_conns"):
                    self._thread_conns = []
                self._thread_conns.append(conn)
        return self._local.conn

    def close(self):
        """Close all per-thread SQLite connections."""
        conns = getattr(self, "_thread_conns", [])
        for conn in conns:
            try:
                conn.close()
            except Exception:
                pass
        conns.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def has_wbit(self, path, uid):
        cache_key = (path, uid)
        now = time.monotonic()
        with self._wbit_cache_lock:
            entry = self._wbit_cache.get(cache_key)
            if entry is not None and now - entry[1] < _WBIT_CACHE_TTL:
                return entry[0]

        ancestors = list(_path_ancestors(path))
        placeholders = ",".join("?" for _ in ancestors)
        row = self._conn().execute(
            f"SELECT 1 FROM wperms WHERE uid=? AND path IN ({placeholders}) LIMIT 1",
            [uid] + ancestors,
        ).fetchone()
        result = row is not None

        with self._wbit_cache_lock:
            self._wbit_cache[cache_key] = (result, now)
            if len(self._wbit_cache) > 8192:
                cutoff = now - _WBIT_CACHE_TTL
                self._wbit_cache = {
                    k: v for k, v in self._wbit_cache.items()
                    if v[1] > cutoff
                }
        return result

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
        conn = self._conn()
        conn.execute(
            "INSERT OR IGNORE INTO wperms (path, uid) VALUES (?, ?)",
            (path, uid),
        )
        conn.commit()
        self._invalidate_cache_for(path, uid)
        if self._acl_queue is not None:
            self._acl_queue.put(("grant", path, uid))

    def revoke(self, path, uid):
        conn = self._conn()
        conn.execute(
            "DELETE FROM wperms WHERE path=? AND uid=?", (path, uid)
        )
        conn.commit()
        self._invalidate_cache_for(path, uid)
        if self._acl_queue is not None:
            self._acl_queue.put(("revoke", path, uid))

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
                    ps = (
                        f"if (-Not (Get-LocalUser -Name '{win_user}' "
                        f"-ErrorAction SilentlyContinue)) {{ "
                        f"New-LocalUser -Name '{win_user}' -NoPassword "
                        f"}}; "
                        f"icacls '{win_path}' /grant "
                        f"'{win_user}:(OI)(CI)F' /T"
                    )
                elif action == "revoke":
                    ps = (
                        f"icacls '{win_path}' /remove "
                        f"'{win_user}' /T"
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

    def flush_acl(self):
        """Block until all pending ACL operations have completed."""
        if self._acl_queue is not None:
            self._acl_queue.join()

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
                        f"Remove-LocalUser -Name '{name}' "
                        f"-ErrorAction SilentlyContinue",
                    ],
                    capture_output=True,
                    text=True,
                )
                if rm.returncode == 0:
                    log.info("Removed stale Windows user: %s", name)
                else:
                    log.warning(
                        "Failed to remove %s: %s", name, rm.stderr.strip()
                    )
