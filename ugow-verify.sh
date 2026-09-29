#!/usr/bin/env bash
# ugow-verify.sh -- end-to-end checks for UGOW on a real WSL2 machine.
#
# Runs against whichever backend is active (FUSE shim, BPF LSM or kmod): builds
# a scratch tree on a Windows drive, grants an unprivileged test uid write
# access to one directory and not another, and checks every gated operation
# from that uid. The uid owns its files and has full DAC access in both
# directories, so a grant is the only difference between them.
#
#   sudo ./ugow-verify.sh                  full run; removes its grants and files
#   sudo ./ugow-verify.sh persist-setup    leave a grant in place, then restart
#                                          WSL (wsl --shutdown) and run:
#   sudo ./ugow-verify.sh persist-check    grants and enforcement survived
#
# Options:
#   --drive <letter>  drive to test (default: c)
#   --dir <path>      scratch tree (default: /mnt/<drive>/ugow-verify.<pid>)
#   --uid <n>         test uid (default: first uid from 61000 with no account)
#   --keep            leave the scratch tree and grants in place
#
# The test grants go into the real permission store and are revoked on exit.
# Exit status: 0 if nothing failed, 1 if a check failed, 2 on a setup error.

# No -e: checks are expected to fail, and each failure is reported rather than
# ending the run.
set -uo pipefail

UGOW=${UGOW:-/usr/local/bin/ugow}
STATE_FILE=/var/lib/ugow/verify-persist
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

PHASE=run
DRIVE=c
DIR=
TEST_UID=
KEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    run|persist-setup|persist-check) PHASE=$1; shift ;;
    --drive) DRIVE=${2:-}; shift 2 ;;
    --dir)   DIR=${2:-}; shift 2 ;;
    --uid)   TEST_UID=${2:-}; shift 2 ;;
    --keep)  KEEP=1; shift ;;
    -h|--help) sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ $PHASE == persist-check ]]; then
  [[ -r $STATE_FILE ]] || { echo "no $STATE_FILE; run persist-setup first" >&2; exit 2; }
  # shellcheck disable=SC1090
  source "$STATE_FILE"
fi

# ── Output ────────────────────────────────────────────────────────────────

PASS=0 FAIL=0 SKIP=0
if [[ -t 1 ]]; then G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' N=$'\e[0m'; else G='' R='' Y='' N=''; fi
pass()    { PASS=$((PASS + 1)); echo "  ${G}PASS${N} $*"; }
fail()    { FAIL=$((FAIL + 1)); echo "  ${R}FAIL${N} $*"; }
skip()    { SKIP=$((SKIP + 1)); echo "  ${Y}SKIP${N} $*"; }
info()    { echo "  info $*"; }
section() { echo; echo "== $*"; }
die()     { echo "ugow-verify: $*" >&2; exit 2; }

# ── Preconditions ─────────────────────────────────────────────────────────

[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
grep -qi microsoft /proc/version || die "not running under WSL"
[[ $DRIVE =~ ^[a-z]$ ]] || die "--drive takes a single lowercase letter"
for cmd in python3 setpriv findmnt "$UGOW"; do
  command -v "$cmd" >/dev/null || die "'$cmd' not found"
done

MNT=/mnt/$DRIVE
BACKING=/mnt/.$DRIVE-backing

if [[ -z $TEST_UID ]]; then
  for ((u = 61000; u < 62000; u++)); do
    getent passwd "$u" >/dev/null || { TEST_UID=$u; break; }
  done
fi
[[ $TEST_UID =~ ^[1-9][0-9]*$ ]] || die "--uid must be a non-zero number"

# ── Backend detection ─────────────────────────────────────────────────────

MODE=
BACKENDS=()
if systemctl is-active --quiet "wsl-fuse-shim@$DRIVE.service"; then
  MODE=fuse; BACKENDS+=(fuse)
fi
[[ -e /sys/fs/bpf/ugow/grants ]] && BACKENDS+=(bpf)
[[ -e /sys/kernel/security/ugow/grant ]] && BACKENDS+=(kmod)
if [[ -z $MODE && ${#BACKENDS[@]} -gt 0 ]]; then
  MODE=${BACKENDS[-1]}   # kmod wins if both kernel backends are loaded
fi
[[ -n $MODE ]] || die "no UGOW backend is active for $MNT"
mountpoint -q "$MNT" || die "$MNT is not mounted"

# FUSE mode gates root too (the shim remaps it to the launching user), so
# fixtures are made through the root-only backing mount. Kernel backends
# exempt root by default, so fixtures go through the drive itself.
raw() {
  if [[ $MODE == fuse ]]; then printf '%s\n' "$BACKING${1#"$MNT"}"; else printf '%s\n' "$1"; fi
}

settle() {
  # The shim notices grant changes by polling SQLite every 0.5s.
  if [[ $MODE == fuse ]]; then sleep 1; fi
}

# ── Operations as the test uid ────────────────────────────────────────────

# Prints OK, or the errno name the operation failed with.
read -r -d '' OP_PY <<'PY'
import errno, os, sys
op, *a = sys.argv[1:]
ops = {
    "stat":      lambda: os.stat(a[0]),
    "read":      lambda: os.close(os.open(a[0], os.O_RDONLY)),
    "write":     lambda: os.close(os.open(a[0], os.O_WRONLY | os.O_APPEND)),
    "create":    lambda: os.close(os.open(a[0], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)),
    "truncate":  lambda: os.truncate(a[0], 0),
    "mkdir":     lambda: os.mkdir(a[0]),
    "rmdir":     lambda: os.rmdir(a[0]),
    "unlink":    lambda: os.unlink(a[0]),
    "rename":    lambda: os.rename(a[0], a[1]),
    "symlink":   lambda: os.symlink("target", a[0]),
    "link":      lambda: os.link(a[0], a[1]),
    "mkfifo":    lambda: os.mkfifo(a[0], 0o666),
    "chmod":     lambda: os.chmod(a[0], int(a[1], 8)),
    "utime-set": lambda: os.utime(a[0], (1_000_000_000, 1_000_000_000)),
    "utime-now": lambda: os.utime(a[0], None),
    "setxattr":  lambda: os.setxattr(a[0], "user.ugow_verify", b"1"),
}
try:
    ops[op]()
except OSError as e:
    print(errno.errorcode.get(e.errno, str(e.errno)))
else:
    print("OK")
PY

as_uid() {
  # A clean environment, so nothing inherited from sudo (PYTHONPATH and the
  # like) changes what the operation does.
  (cd / && setpriv --reuid="$TEST_UID" --regid="$TEST_UID" --clear-groups \
     -- env -i PATH=/usr/bin:/bin python3 -c "$OP_PY" "$@" 2>&1)
}

# expect <want> <description> <op> <args...>
expect() {
  local want=$1 desc=$2 got
  shift 2
  got=$(as_uid "$@")
  if [[ $got == "$want" ]]; then pass "$desc"; else fail "$desc: expected $want, got $got"; fi
}

# gated <description> <op> <args with a grant...> -- <args without one...>
#
# The operation must succeed with a grant and fail with EACCES without one.
# If it fails with a grant for any other reason, the filesystem is refusing
# it and a denial would prove nothing, so the check is skipped instead.
gated() {
  local desc=$1 op=$2 got
  shift 2
  local -a with=() without=()
  while [[ $# -gt 0 && $1 != -- ]]; do with+=("$1"); shift; done
  shift
  without=("$@")

  got=$(as_uid "$op" "${with[@]}")
  if [[ $got == EACCES ]]; then
    fail "$desc: denied even with a grant"
    return
  elif [[ $got != OK ]]; then
    skip "$desc: unsupported on this drive ($got with a grant)"
    return
  fi
  got=$(as_uid "$op" "${without[@]}")
  if [[ $got == EACCES ]]; then pass "$desc"; else fail "$desc: expected EACCES without a grant, got $got"; fi
}

# ── Fixtures and grants ───────────────────────────────────────────────────

GRANTS=()

FIXTURE_HINT="is $MNT mounted with -o metadata? If uid $TEST_UID is refused, retry with --uid <an existing uid>."
[[ $MODE == fuse ]] || FIXTURE_HINT+=" Kernel backends also need root exempt (the default)."

mkfile() {
  local p
  for p in "$@"; do
    p=$(raw "$p")
    { : > "$p" && chown "$TEST_UID:$TEST_UID" "$p" && chmod 0666 "$p"; } \
      || die "could not create $p: $FIXTURE_HINT"
  done
}

mkdirs() {
  local p
  for p in "$@"; do
    p=$(raw "$p")
    { mkdir -p "$p" && chown "$TEST_UID:$TEST_UID" "$p" && chmod 0777 "$p"; } \
      || die "could not create $p: $FIXTURE_HINT"
  done
}

grant() {
  "$UGOW" allow "$TEST_UID" "$1" >/dev/null || die "ugow allow $TEST_UID $1 failed"
  GRANTS+=("$1")
  settle
}

revoke() {
  local g kept=()
  "$UGOW" deny "$TEST_UID" "$1" >/dev/null || fail "ugow deny $TEST_UID $1 reported an error"
  for g in "${GRANTS[@]}"; do [[ $g == "$1" ]] || kept+=("$g"); done
  GRANTS=("${kept[@]}")
  settle
}

cleanup() {
  local g
  [[ $KEEP == 1 ]] && return
  # Revoke before deleting: BPF grants are keyed by inode and need the path.
  for g in "${GRANTS[@]}"; do "$UGOW" deny "$TEST_UID" "$g" >/dev/null 2>&1; done
  [[ -n ${CREATED:-} ]] && rm -rf -- "$(raw "$DIR")"
}
trap cleanup EXIT

make_tree() {
  [[ -z $DIR ]] && DIR=$MNT/ugow-verify.$$
  [[ $DIR == "$MNT"/?* ]] || die "--dir must be inside $MNT"
  [[ -e $(raw "$DIR") ]] && die "$DIR already exists"
  # A grant the uid already holds on an ancestor would cover locked/ too.
  if "$UGOW" check --user "$TEST_UID" "$DIR/locked" >/dev/null; then
    die "uid $TEST_UID already has a grant covering $DIR; pick another --uid or --dir"
  fi
  mkdirs "$DIR"
  CREATED=1
}

show_environment() {
  section "Environment"
  info "kernel $(uname -r), backend $MODE (active: ${BACKENDS[*]}), test uid $TEST_UID"
  info "scratch tree $DIR"
  if [[ -r /sys/kernel/security/lsm ]]; then
    info "active LSMs: $(cat /sys/kernel/security/lsm)"
  fi
}

# Everything below this point exits through cleanup().

reachable() {
  local got
  got=$(as_uid stat "$DIR")
  if [[ $got == OK ]]; then return 0; fi
  fail "uid $TEST_UID cannot reach $DIR ($got); the remaining checks need it"
  namei -l "$DIR" 2>/dev/null | sed 's/^/       /'
  return 1
}

# ── Backend-specific setup checks ─────────────────────────────────────────

check_backend() {
  section "Backend ($MODE)"
  local lsm=
  [[ -r /sys/kernel/security/lsm ]] && lsm=$(cat /sys/kernel/security/lsm)

  case $MODE in
  fuse)
    local fstype opts
    fstype=$(findmnt -no FSTYPE "$MNT")
    if [[ $fstype == fuse* ]]; then pass "$MNT is the FUSE shim ($fstype)"; else fail "$MNT is $fstype, not FUSE"; fi
    opts=$(findmnt -no OPTIONS "$BACKING")
    if [[ ,$opts, == *,nosuid,* && ,$opts, == *,nodev,* ]]; then
      pass "backing mount has nosuid,nodev"
    else
      fail "backing mount options lack nosuid/nodev: $opts"
    fi
    ;;
  bpf)
    if [[ ,$lsm, == *,bpf,* ]]; then pass "bpf is an active LSM"; else fail "bpf is not in the active LSM list; hooks load but never run"; fi
    local loaded expected
    loaded=$(bpftool prog show -j 2>/dev/null \
      | python3 -c 'import json,sys; print(sum(p.get("name","").startswith("ugow_") for p in json.load(sys.stdin)))')
    if [[ -f $SCRIPT_DIR/bpf/ugow.bpf.c ]]; then
      expected=$(grep -c 'SEC("lsm/' "$SCRIPT_DIR/bpf/ugow.bpf.c")
      if [[ $loaded == "$expected" ]]; then pass "all $loaded BPF programs are loaded"; else fail "$loaded of $expected BPF programs are loaded"; fi
    else
      info "$loaded ugow_ BPF programs loaded"
    fi
    if systemctl is-active --quiet ugow-bpf.service; then pass "ugow-bpf.service is active"; else fail "ugow-bpf.service is not active"; fi
    if "$UGOW" drives 2>/dev/null | grep -q "^${DRIVE^^}:"; then pass "$MNT's device is registered for enforcement"; else fail "$MNT's device is not in target_devs"; fi
    # Linux 6.9 changed the inode_setattr prototype; the chmod and timestamp
    # checks below exercise whichever one this kernel has.
    local ver; ver=$(uname -r | cut -d. -f1,2)
    if printf '%s\n' 6.9 "$ver" | sort -VC; then
      info "inode_setattr takes (idmap, dentry, attr) on this kernel"
    else
      info "inode_setattr takes (dentry, attr) on this kernel"
    fi
    ;;
  kmod)
    if [[ ,$lsm, == *,ugow,* ]]; then pass "ugow is an active LSM"; else fail "ugow is not in the active LSM list"; fi
    local f missing=()
    for f in grant revoke grants devices; do
      [[ -e /sys/kernel/security/ugow/$f ]] || missing+=("$f")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then pass "securityfs interface is complete"; else fail "securityfs is missing: ${missing[*]}"; fi
    ;;
  esac

  if [[ $MODE != fuse ]]; then
    if systemctl is-enabled --quiet ugow-sync.service; then
      pass "ugow-sync.service is enabled (grants replay at boot)"
    else
      fail "ugow-sync.service is not enabled; grants are lost on restart"
    fi
  fi
}

# ── Phase: full run ───────────────────────────────────────────────────────

run_all() {
  make_tree
  show_environment
  check_backend

  local W=$DIR/granted L=$DIR/locked
  mkdirs "$W" "$L" "$W/d-rm" "$L/d-rm" "$W/sub/deeper"
  mkfile "$L/f-read" \
    "$W/f-write" "$L/f-write" "$W/f-trunc" "$L/f-trunc" \
    "$W/f-unlink" "$L/f-unlink" "$W/f-mv" "$L/f-mv" \
    "$W/f-mv3" "$L/f-out" "$W/f-mv5" "$W/f-leave" \
    "$W/f-chmod" "$L/f-chmod" "$W/f-utime" "$L/f-utime" \
    "$W/f-touch" "$L/f-touch" "$W/f-xattr" "$L/f-xattr" \
    "$W/f-link" "$L/f-victim"
  grant "$W"

  section "Enforcement (uid $TEST_UID, grant on granted/ only)"
  reachable || return

  expect OK "reads are never gated" read "$L/f-read"
  gated "open for writing"          write     "$W/f-write"          -- "$L/f-write"
  gated "create a file"             create    "$W/new"              -- "$L/new"
  gated "truncate"                  truncate  "$W/f-trunc"          -- "$L/f-trunc"
  gated "mkdir"                     mkdir     "$W/newdir"           -- "$L/newdir"
  gated "rmdir"                     rmdir     "$W/d-rm"             -- "$L/d-rm"
  gated "unlink"                    unlink    "$W/f-unlink"         -- "$L/f-unlink"
  gated "rename within a directory" rename    "$W/f-mv" "$W/f-mv2"  -- "$L/f-mv" "$L/f-mv2"
  gated "rename out of an ungranted directory" \
                                    rename    "$W/f-mv3" "$W/f-mv4" -- "$L/f-out" "$W/f-in"
  gated "rename into an ungranted directory" \
                                    rename    "$W/f-mv5" "$W/f-mv6" -- "$W/f-leave" "$L/f-arrive"
  gated "symlink"                   symlink   "$W/sym"              -- "$L/sym"
  gated "mkfifo (inode_mknod)"      mkfifo    "$W/fifo"             -- "$L/fifo"
  gated "chmod as owner (inode_setattr)" \
                                    chmod     "$W/f-chmod" 0640     -- "$L/f-chmod" 0640
  gated "set explicit timestamps as owner (inode_setattr)" \
                                    utime-set "$W/f-utime"          -- "$L/f-utime"
  gated "touch timestamps to now"   utime-now "$W/f-touch"          -- "$L/f-touch"
  gated "set an xattr"              setxattr  "$W/f-xattr"          -- "$L/f-xattr"
  gated "hard link: an ungranted file cannot gain a name in a granted directory" \
                                    link      "$W/f-link" "$W/f-link2" -- "$L/f-victim" "$W/f-stolen"
  expect OK "a grant covers descendants" create "$W/sub/deeper/new"

  if "$UGOW" check --user "$TEST_UID" "$W/f-write" >/dev/null \
     && ! "$UGOW" check --user "$TEST_UID" "$L/f-write" >/dev/null; then
    pass "ugow check agrees with enforcement"
  else
    fail "ugow check disagrees with enforcement"
  fi

  mode_specific "$W" "$L"

  if [[ $MODE != fuse ]]; then
    section "Resync"
    if "$UGOW" sync >/dev/null 2>&1; then pass "ugow sync succeeds"; else fail "ugow sync failed"; fi
    expect OK     "grant still applies after sync" write "$W/f-write"
    expect EACCES "denial still applies after sync" write "$L/f-write"
  fi

  section "Revocation"
  revoke "$W"
  expect EACCES "revoking the grant takes effect" write "$W/f-write"
}

mode_specific() {
  local W=$1 L=$2
  case $MODE in
  fuse)
    section "FUSE shim"
    mkfile "$W/f-suid"
    if [[ $(as_uid chmod "$W/f-suid" 6755) == OK ]]; then
      local m; m=$(stat -c %a "$(raw "$W/f-suid")")
      if (( 8#$m & 8#6000 )); then fail "setuid/setgid reached the backing file (mode $m)"; else pass "setuid/setgid are stripped (mode $m)"; fi
    else
      skip "setuid strip: chmod failed with a grant"
    fi
    if journalctl -u "wsl-fuse-shim@$DRIVE.service" --since "@$START" --no-pager 2>/dev/null \
       | grep -q "deny .*uid=$TEST_UID"; then
      pass "denials are in the audit log"
    else
      fail "no denial for uid $TEST_UID in journalctl -u wsl-fuse-shim@$DRIVE.service"
    fi
    ;;
  bpf)
    section "BPF DAC handling"
    # ugow allow widens DAC so the LSM is the only gate; the last revoke must
    # put the original mode back.
    local D=$DIR/dac before after
    mkdir -p "$D" && chmod 0755 "$D"
    before=$(stat -c %a "$D")
    grant "$D"
    after=$(stat -c %a "$D")
    if [[ $after == 777 ]]; then pass "ugow allow widens DAC ($before -> $after)"; else fail "ugow allow left mode $after"; fi
    revoke "$D"
    after=$(stat -c %a "$D")
    if [[ $after == "$before" ]]; then pass "last revoke restores the mode ($after)"; else fail "revoke left mode $after, expected $before"; fi
    ;;
  kmod)
    section "kmod interface"
    local dev rel
    dev=$(python3 -c 'import os,sys; d=os.stat(sys.argv[1]).st_dev; print(f"{os.major(d)}:{os.minor(d)}")' "$MNT")
    rel=${W#"$MNT"}
    if grep -qx "$dev" /sys/kernel/security/ugow/devices; then pass "device $dev is registered"; else fail "device $dev is not in the devices list"; fi
    if grep -qxF "$TEST_UID"$'\t'"$dev"$'\t'"$rel" /sys/kernel/security/ugow/grants; then
      pass "grant is filed superblock-relative ($rel)"
    else
      fail "grants does not list '$TEST_UID $dev $rel'"
    fi
    ;;
  esac
}

# ── Phase: persistence across a WSL restart ──────────────────────────────

persist_setup() {
  [[ -e $STATE_FILE ]] && die "$STATE_FILE exists; run persist-check first or remove it"
  make_tree
  show_environment
  check_backend
  mkdirs "$DIR/granted" "$DIR/locked"
  mkfile "$DIR/granted/f" "$DIR/locked/f"
  grant "$DIR/granted"

  section "Before restart"
  reachable || return
  expect OK     "granted write works" write "$DIR/granted/f"
  expect EACCES "ungranted write is denied" write "$DIR/locked/f"

  printf 'DIR=%q\nTEST_UID=%q\nDRIVE=%q\n' "$DIR" "$TEST_UID" "$DRIVE" > "$STATE_FILE"
  KEEP=1
  echo
  echo "Now restart WSL from Windows (wsl --shutdown), reopen it, and run:"
  echo "  sudo $0 persist-check"
}

persist_check() {
  [[ -e $(raw "$DIR") ]] || die "$DIR is gone"
  CREATED=1
  GRANTS=("$DIR/granted")
  rm -f "$STATE_FILE"

  show_environment
  check_backend
  if [[ $MODE != fuse ]]; then
    info "ugow-sync.service: $(systemctl show -p Result -p ConditionResult --value ugow-sync.service | paste -sd' ')"
  fi

  section "After restart"
  reachable || return
  expect OK     "granted write still works" write "$DIR/granted/f"
  expect EACCES "ungranted write is still denied" write "$DIR/locked/f"
}

# ── Main ──────────────────────────────────────────────────────────────────

START=$(date +%s)
case $PHASE in
  run)           run_all ;;
  persist-setup) persist_setup ;;
  persist-check) persist_check ;;
esac

echo
echo "== ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
[[ $FAIL -eq 0 ]]
