#!/usr/bin/env python3
"""
UGOW BPF LSM manager -- loads the BPF program and manages the grant maps.

Resolves filesystem paths to (inode, device, uid) triples for the BPF
program so the kernel-side code never touches strings.  Persists grants
in the same SQLite database used by the FUSE shim so both enforcement
layers share a single source of truth.

Requires: bpftool, clang (for initial compilation)
"""

import os
import sys
import json
import struct
import argparse
import subprocess
import sqlite3
import logging

for _p in [os.path.join(os.path.dirname(__file__), ".."), "/opt/ugow/lib"]:
    if os.path.isfile(os.path.join(_p, "permstore.py")):
        sys.path.insert(0, _p)
        break
from permstore import PermStore, DEFAULT_DB_PATH  # noqa: E402

log = logging.getLogger("ugow-bpf")

_BPF_SEARCH = [
    os.path.join(os.path.dirname(__file__), "ugow.bpf.o"),
    "/opt/ugow/bpf/ugow.bpf.o",
]
BPF_OBJ = next((p for p in _BPF_SEARCH if os.path.isfile(p)), _BPF_SEARCH[0])
PIN_PATH = "/sys/fs/bpf/ugow"


def run(cmd, check=True):
    log.debug("$ %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def stat_path(path):
    """Return (inode, dev_t) for a filesystem path."""
    st = os.stat(path)
    return st.st_ino, st.st_dev


def dev_major_minor(dev):
    return os.major(dev), os.minor(dev)


# -- Map operations via bpftool -------------------------------------------

def grant_key_bytes(ino, dev, uid):
    """Encode a grant_key struct matching the BPF map layout."""
    return struct.pack("=QII", ino, dev, uid)


def grant_key_hex(ino, dev, uid):
    """Hex-string representation for bpftool."""
    raw = grant_key_bytes(ino, dev, uid)
    return " ".join(f"0x{b:02x}" for b in raw)


def map_update(map_path, key_hex, value_hex="0x01"):
    r = run([
        "bpftool", "map", "update", "pinned", map_path,
        "key", "hex"] + key_hex.split() + [
        "value", "hex", value_hex,
    ], check=False)
    if r.returncode != 0:
        log.error("bpftool map update failed (rc=%d): %s",
                  r.returncode, r.stderr.strip())
        raise subprocess.CalledProcessError(r.returncode, r.args)


def map_delete(map_path, key_hex):
    run([
        "bpftool", "map", "delete", "pinned", map_path,
        "key", "hex"] + key_hex.split(),
        check=False,
    )


def map_dump(map_path):
    r = run(["bpftool", "map", "dump", "pinned", map_path, "-j"], check=False)
    if r.returncode != 0:
        return []
    return json.loads(r.stdout)


# -- High-level commands ---------------------------------------------------

def _ensure_bpffs():
    """Mount bpffs at /sys/fs/bpf if not already mounted."""
    if os.path.ismount("/sys/fs/bpf"):
        return
    r = subprocess.run(
        ["mount", "-t", "bpf", "bpffs", "/sys/fs/bpf"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        log.error("Failed to mount bpffs: %s", r.stderr.strip())
        sys.exit(1)
    log.info("Mounted bpffs at /sys/fs/bpf")


def cmd_load(args):
    """Load the BPF program and pin maps."""
    _ensure_bpffs()

    maps_pinned = all(
        os.path.exists(f"{PIN_PATH}/{m}") for m in ("target_devs", "grants")
    )
    if maps_pinned:
        log.info("BPF programs already pinned at %s", PIN_PATH)
        return

    if os.path.exists(PIN_PATH):
        log.info("Cleaning stale pin directory %s", PIN_PATH)
        run(["rm", "-rf", PIN_PATH], check=False)

    os.makedirs(PIN_PATH, exist_ok=True)

    r = run([
        "bpftool", "prog", "loadall", BPF_OBJ, PIN_PATH,
        "type", "lsm", "autoattach",
        "pinmaps", PIN_PATH,
    ], check=False)
    if r.returncode != 0:
        log.error("Failed to load/attach BPF program: %s", r.stderr.strip())
        run(["rm", "-rf", PIN_PATH], check=False)
        sys.exit(1)
    log.info("BPF LSM programs loaded, pinned, and attached at %s", PIN_PATH)


def cmd_unload(args):
    """Detach LSM hooks, then unpin BPF programs."""
    if not os.path.exists(PIN_PATH):
        log.info("Nothing pinned at %s", PIN_PATH)
        return

    r = run(["bpftool", "prog", "list", "-j"], check=False)
    if r.returncode == 0:
        progs = json.loads(r.stdout)
        for p in progs:
            if p.get("name", "").startswith("ugow_"):
                prog_id = p["id"]
                run([
                    "bpftool", "prog", "detach", "id", str(prog_id), "lsm",
                ], check=False)
                log.info("Detached program %s (id=%d)", p["name"], prog_id)

    run(["rm", "-rf", PIN_PATH], check=False)
    log.info("BPF programs unpinned from %s", PIN_PATH)


def cmd_add_device(args):
    """Register a mount's device as a target for enforcement."""
    path = os.path.abspath(args.mount_path)
    _, dev = stat_path(path)
    dev_key = struct.pack("=I", dev)
    key_hex = " ".join(f"0x{b:02x}" for b in dev_key)
    map_update(f"{PIN_PATH}/target_devs", key_hex)
    major, minor = dev_major_minor(dev)
    log.info("Added target device %d:%d (%s)", major, minor, path)


def cmd_remove_device(args):
    """Remove a mount's device from enforcement."""
    path = os.path.abspath(args.mount_path)
    _, dev = stat_path(path)
    dev_key = struct.pack("=I", dev)
    key_hex = " ".join(f"0x{b:02x}" for b in dev_key)
    map_delete(f"{PIN_PATH}/target_devs", key_hex)
    major, minor = dev_major_minor(dev)
    log.info("Removed target device %d:%d (%s)", major, minor, path)


def cmd_grant(args):
    """Grant W-bit for a UID on a path."""
    path = os.path.abspath(args.path)
    uid = args.uid
    ino, dev = stat_path(path)

    key_hex = grant_key_hex(ino, dev, uid)
    map_update(f"{PIN_PATH}/grants", key_hex)

    store = PermStore(db_path=args.db, mirror_acl=False)
    store.grant(path, uid)

    log.info("Granted: uid=%d path=%s (ino=%d dev=%d)", uid, path, ino, dev)


def cmd_revoke(args):
    """Revoke W-bit for a UID on a path."""
    path = os.path.abspath(args.path)
    uid = args.uid
    ino, dev = stat_path(path)

    key_hex = grant_key_hex(ino, dev, uid)
    map_delete(f"{PIN_PATH}/grants", key_hex)

    store = PermStore(db_path=args.db, mirror_acl=False)
    store.revoke(path, uid)

    log.info("Revoked: uid=%d path=%s (ino=%d dev=%d)", uid, path, ino, dev)


def _flush_grants_map():
    """Remove all entries from the BPF grants map."""
    grants_path = f"{PIN_PATH}/grants"
    entries = map_dump(grants_path)
    for entry in entries:
        key_bytes = bytes(entry.get("key", []))
        if len(key_bytes) >= 16:
            key_hex = " ".join(f"0x{b:02x}" for b in key_bytes[:16])
            map_delete(grants_path, key_hex)


def cmd_sync(args):
    """Sync all grants from SQLite into the BPF map (full refresh)."""
    _flush_grants_map()
    log.info("Flushed stale entries from BPF grants map")

    store = PermStore(db_path=args.db, mirror_acl=False)
    grants = store.list_grants()

    loaded = 0
    for path, uid in grants:
        try:
            ino, dev = stat_path(path)
        except FileNotFoundError:
            log.warning("Skipping missing path: %s", path)
            continue
        key_hex = grant_key_hex(ino, dev, uid)
        map_update(f"{PIN_PATH}/grants", key_hex)
        loaded += 1

    log.info("Synced %d grants from %s into BPF map", loaded, args.db)


def cmd_check(args):
    """Check if a UID has W-bit on a path (queries SQLite, not the BPF map)."""
    path = os.path.abspath(args.path)
    uid = args.uid if args.uid is not None else os.getuid()
    store = PermStore(db_path=args.db, mirror_acl=False)
    has = store.has_wbit(path, uid)
    status = "GRANTED" if has else "DENIED"
    print(f"W-bit {status} for uid={uid} on {path}")
    sys.exit(0 if has else 1)


def cmd_list(args):
    """List entries in the BPF grants map."""
    entries = map_dump(f"{PIN_PATH}/grants")
    if not entries:
        print("No grants in BPF map.")
        return
    for entry in entries:
        key_bytes = bytes(entry.get("key", []))
        if len(key_bytes) >= 16:
            ino, dev, uid = struct.unpack("=QII", key_bytes[:16])
            print(f"  uid={uid}\tino={ino}\tdev={dev}")


def main():
    parser = argparse.ArgumentParser(
        description="UGOW BPF LSM manager"
    )
    parser.add_argument(
        "--db", default=DEFAULT_DB_PATH,
        help="SQLite DB path (default: %(default)s)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("load", help="Load BPF programs and pin maps")
    sub.add_parser("unload", help="Unpin and detach BPF programs")

    p = sub.add_parser("add-device", help="Register a mount for enforcement")
    p.add_argument("mount_path", help="Mount path (e.g. /mnt/c)")

    p = sub.add_parser("remove-device", help="Remove a mount from enforcement")
    p.add_argument("mount_path", help="Mount path (e.g. /mnt/d)")

    p = sub.add_parser("grant", help="Grant W-bit")
    p.add_argument("uid", type=int)
    p.add_argument("path")

    p = sub.add_parser("revoke", help="Revoke W-bit")
    p.add_argument("uid", type=int)
    p.add_argument("path")

    p = sub.add_parser("sync", help="Sync SQLite grants into BPF map")
    sub.add_parser("list", help="List BPF map entries")

    p = sub.add_parser("check", help="Check if a UID has W-bit on a path")
    p.add_argument("path")
    p.add_argument("--uid", type=int, default=None,
                   help="UID to check (default: current user)")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    handler = {
        "load": cmd_load,
        "unload": cmd_unload,
        "add-device": cmd_add_device,
        "remove-device": cmd_remove_device,
        "grant": cmd_grant,
        "revoke": cmd_revoke,
        "sync": cmd_sync,
        "list": cmd_list,
        "check": cmd_check,
    }
    handler[args.command](args)


if __name__ == "__main__":
    main()
