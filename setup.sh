#!/usr/bin/env bash
set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────

MODE="fuse"
UNINSTALL=false
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Parse arguments ─────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: $0 [--mode fuse|bpf] [--uninstall]

Modes:
  fuse        (default) FUSE overlay shim -- easiest, no kernel requirements
  bpf         BPF LSM enforcement -- faster, kernel-level, stock WSL2 kernel

Options:
  --uninstall Remove all UGOW components (both modes)

The CLI (ugow) and permission store are always installed regardless of mode.
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --uninstall)
      UNINSTALL=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      ;;
  esac
done

# ── Define paths ───────────────────────────────────────────────────────────

WSL_CONF=/etc/wsl.conf
FUSE_CONF=/etc/fuse.conf
UGOW_BIN=/usr/local/bin/ugow
UGOW_LIB=/opt/ugow/lib
VE=/opt/ugow

# ═══════════════════════════════════════════════════════════════════════════
# Uninstall
# ═══════════════════════════════════════════════════════════════════════════

_spin() {
  local msg="$1"
  local chars='/-\|'
  local i=0
  tput civis 2>/dev/null
  while true; do
    printf "\r  [%c] %s" "${chars:i:1}" "$msg"
    i=$(( (i + 1) % 4 ))
    sleep 0.12
  done
}

_spin_stop() {
  kill "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
  tput cnorm 2>/dev/null || true
  printf "\r\033[K  [*] %s\n" "$2"
}

if [[ "$UNINSTALL" == true ]]; then
  cat <<'BANNER'
  _   _    ____    ___   __        __
 | | | |  / ___|  / _ \  \ \      / /
 | | | | | |  _  | | | |  \ \ /\ / /
 | |_| | | |_| | | |_| |   \ V  V /
  \___/   \____|  \___/     \_/\_/
         Uninstalling ...
BANNER
  echo ""

  # Stop and disable FUSE shim units, collecting drive letters
  managed_drives=()
  if [[ -f /etc/systemd/system/wsl-fuse-shim@.service ]]; then
    for unit in $(systemctl list-units 'wsl-fuse-shim@*.service' \
                  --plain --no-legend 2>/dev/null | awk '{print $1}'); do
      letter=$(echo "$unit" | sed 's/wsl-fuse-shim@\(.\)\.service/\1/')
      managed_drives+=("$letter")
      _spin "Stopping $unit" &
      spin_pid=$!
      sudo systemctl disable --now "$unit" 2>/dev/null || true
      sudo systemctl reset-failed "$unit" 2>/dev/null || true
      _spin_stop "$spin_pid" "Stopped $unit"
    done
    sudo rm -f /etc/systemd/system/wsl-fuse-shim@.service
  fi

  # Stop and disable BPF unit
  if systemctl list-unit-files ugow-bpf.service &>/dev/null; then
    sudo systemctl disable --now ugow-bpf.service 2>/dev/null || true
    echo "  Stopped: ugow-bpf.service"
  fi
  sudo rm -f /etc/systemd/system/ugow-bpf.service

  sudo systemctl daemon-reload

  # Unmount any remaining FUSE backing mounts
  for backing in /mnt/.*-backing; do
    [ -d "$backing" ] && sudo umount "$backing" 2>/dev/null || true
  done

  # Remove installed files
  sudo rm -f "$UGOW_BIN"
  sudo rm -f /usr/local/bin/wsl-fuse-shim
  sudo rm -rf /opt/ugow

  # Remove BPF pins
  sudo rm -rf /sys/fs/bpf/ugow

  # Re-enable WSL automount so drives mount normally on next restart
  if grep -q 'enabled = false' "$WSL_CONF" 2>/dev/null; then
    sudo sed -i 's/enabled = false/enabled = true/' "$WSL_CONF"
    echo "  WSL automount re-enabled in $WSL_CONF"
  fi

  # Offer to re-mount drives that were managed by UGOW
  if [[ ${#managed_drives[@]} -gt 0 ]]; then
    echo ""
    echo "  The following drives were managed by UGOW: ${managed_drives[*]}"
    while true; do
      read -rp "  Re-mount them as standard DrvFs now? [Y/n] " answer
      case "${answer,,}" in
        y|"") break ;;
        n)    break ;;
        *)    echo "  Please answer Y or n." ;;
      esac
    done
    if [[ -z "$answer" || "${answer,,}" == "y" ]]; then
      for letter in "${managed_drives[@]}"; do
        sudo mkdir -p "/mnt/$letter"
        sudo mount -t drvfs "$(echo "$letter" | tr a-z A-Z):" "/mnt/$letter" -o metadata \
          && echo "  Mounted: /mnt/$letter" \
          || echo "  Failed to mount: /mnt/$letter"
      done
    fi
  fi

  echo ""
  echo "  UGOW has been fully uninstalled."
  echo ""
  echo "  Note: /var/lib/ugow/wperm.db (permission database) was preserved."
  echo "  To remove it:  sudo rm -rf /var/lib/ugow"
  echo ""
  exit 0
fi

if [[ "$MODE" != "fuse" && "$MODE" != "bpf" ]]; then
  echo "Error: --mode must be 'fuse' or 'bpf'" >&2
  usage
fi

# ── Ensure we're in WSL ────────────────────────────────────────────────────

if ! grep -qi Microsoft /proc/version; then
  echo "This installer only works inside WSL2. Aborting." >&2
  exit 1
fi

# ── Conflict detection ─────────────────────────────────────────────────────

if [[ "$MODE" == "fuse" ]]; then
  if systemctl is-active --quiet ugow-bpf.service 2>/dev/null; then
    cat >&2 <<EOF
Error: BPF enforcement is already active.
  Run 'sudo systemctl disable --now ugow-bpf.service' to remove it first.
EOF
    exit 1
  fi
elif [[ "$MODE" == "bpf" ]]; then
  if systemctl list-units --type=service --state=running --plain --no-legend \
       'wsl-fuse-shim@*.service' 2>/dev/null | grep -q .; then
    cat >&2 <<EOF
Error: FUSE shim is already active.
  Run 'sudo systemctl disable --now wsl-fuse-shim@*.service' to remove it first.
EOF
    exit 1
  fi
fi

# ── Backup originals ──────────────────────────────────────────────────────

for f in "$WSL_CONF" "$FUSE_CONF"; do
  if [ -e "$f" ]; then
    sudo cp -n "$f" "${f}.bak_$(date +%Y%m%d%H%M)" \
      && echo "Backup: $f -> ${f}.bak_*"
  fi
done

# ── Helper: update wsl.conf without clobbering user sections ──────────────

_ugow_set_wsl_conf() {
  local automount_enabled="$1"

  sudo touch "$WSL_CONF"

  # Ensure [automount] section exists and set enabled + options
  if grep -q '^\[automount\]' "$WSL_CONF"; then
    if grep -q '^enabled' "$WSL_CONF"; then
      sudo sed -i "s/^enabled.*/enabled = $automount_enabled/" "$WSL_CONF"
    else
      sudo sed -i "/^\[automount\]/a enabled = $automount_enabled" "$WSL_CONF"
    fi
    if ! grep -q '^options' "$WSL_CONF"; then
      sudo sed -i '/^\[automount\]/a options = "metadata"' "$WSL_CONF"
    fi
  else
    printf '\n[automount]\nenabled = %s\noptions = "metadata"\n' \
      "$automount_enabled" | sudo tee -a "$WSL_CONF" > /dev/null
  fi

  # Ensure [boot] section exists with systemd = true
  if grep -q '^\[boot\]' "$WSL_CONF"; then
    if ! grep -q '^systemd' "$WSL_CONF"; then
      sudo sed -i '/^\[boot\]/a systemd = true' "$WSL_CONF"
    fi
  else
    printf '\n[boot]\nsystemd = true\n' | sudo tee -a "$WSL_CONF" > /dev/null
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
# Base install (always): CLI + permstore + venv
# ═══════════════════════════════════════════════════════════════════════════

cat <<BANNER
  _   _    ____    ___   __        __
 | | | |  / ___|  / _ \  \ \      / /
 | | | | | |  _  | | | |  \ \ /\ / /
 | |_| | | |_| | | |_| |   \ V  V /
  \___/   \____|  \___/     \_/\_/
         Installing ($MODE) ...
BANNER
echo ""

echo "--- Installing base (CLI + permission store) ---"

sudo mkdir -p "$UGOW_LIB"
sudo install -m 644 "$SCRIPT_DIR/permstore.py" "$UGOW_LIB/permstore.py"
sudo install -m 755 "$SCRIPT_DIR/cli.py"       "$UGOW_BIN"

sudo mkdir -p /var/lib/ugow
sudo chmod 0700 /var/lib/ugow
sudo chown root:root /var/lib/ugow

if [ ! -d "$VE/venv" ]; then
  sudo mkdir -p "$VE"
  sudo python3 -m venv "$VE/venv"
fi

echo "  CLI installed: $UGOW_BIN"
echo "  Lib installed: $UGOW_LIB/permstore.py"

# ═══════════════════════════════════════════════════════════════════════════
# Mode: FUSE
# ═══════════════════════════════════════════════════════════════════════════

if [[ "$MODE" == "fuse" ]]; then
  echo ""
  echo "--- Installing FUSE shim ---"

  SHIM_BIN=/usr/local/bin/wsl-fuse-shim
  UNIT_TEMPLATE=/etc/systemd/system/wsl-fuse-shim@.service
  REAL_UID="${SUDO_UID:-$(id -u)}"

  # Ensure system FUSE packages are installed (fusepy needs libfuse2)
  if ! command -v fusermount &>/dev/null; then
    echo "  Installing system FUSE packages..."
    if command -v apt-get &>/dev/null; then
      sudo apt-get update -qq && sudo apt-get install -y fuse libfuse2
    else
      echo "Error: 'fusermount' not found. Install the 'fuse' package for your distro." >&2
      exit 1
    fi
  fi

  # Install fusepy into the venv
  sudo "$VE/venv/bin/pip" install --upgrade --quiet fusepy

  # Install shim + permstore + helper scripts for the FUSE daemon
  if [ -e "$SHIM_BIN" ] && ! grep -q '# Shim: UGOW' "$SHIM_BIN"; then
    echo "$SHIM_BIN exists and doesn't look like UGOW shim. Aborting." >&2
    exit 1
  fi
  sudo install -m 755 "$SCRIPT_DIR/shim.py" "$SHIM_BIN"
  echo "# Shim: UGOW" | sudo tee -a "$SHIM_BIN" >/dev/null
  sudo install -m 644 "$SCRIPT_DIR/permstore.py" "$UGOW_LIB/permstore.py"
  sudo install -m 755 "$SCRIPT_DIR/mount-backing.sh" "$UGOW_LIB/mount-backing.sh"

  # Enable user_allow_other in /etc/fuse.conf
  if ! grep -q '^user_allow_other' "$FUSE_CONF"; then
    echo "  Enabling 'user_allow_other' in $FUSE_CONF"
    sudo sed -i 's/^#user_allow_other/user_allow_other/' "$FUSE_CONF"
  fi

  # Disable WSL automount so UGOW owns /mnt/*
  _ugow_set_wsl_conf "false"
  echo "  WSL automount disabled; UGOW will mount drives via FUSE."

  # Create the systemd template unit (one instance per drive letter)
  sudo tee "$UNIT_TEMPLATE" > /dev/null <<EOF
[Unit]
Description=UGOW FUSE Shim for /mnt/%i
After=local-fs.target

[Service]
Type=simple
TimeoutStartSec=30
TimeoutStopSec=10
ExecStartPre=-/bin/sh -c 'pkill -9 -f "[w]sl-fuse-shim.*/mnt/%i" 2>/dev/null; true'
ExecStartPre=-/bin/umount -l /mnt/%i
ExecStartPre=-/usr/bin/fusermount -uz /mnt/%i
ExecStartPre=/bin/mkdir -p /mnt/.%i-backing /mnt/%i
ExecStartPre=${UGOW_LIB}/mount-backing.sh %i
ExecStartPre=-/bin/chmod 0700 /mnt/.%i-backing
Environment=PYTHONPATH=${UGOW_LIB}
ExecStart=${VE}/venv/bin/python ${SHIM_BIN} --launcher-uid ${REAL_UID} /mnt/.%i-backing /mnt/%i
ExecStopPost=-/bin/sh -c 'fusermount -uz /mnt/%i 2>/dev/null; umount -l /mnt/%i 2>/dev/null; umount /mnt/.%i-backing 2>/dev/null; true'
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF

  # Enable & start for C: by default
  sudo systemctl daemon-reload
  sudo systemctl enable --now wsl-fuse-shim@c.service

  # Verify the service actually started
  echo ""
  echo "  Waiting for FUSE shim to start..."
  for _try in 1 2 3 4 5; do
    sleep 2
    systemctl is-active --quiet wsl-fuse-shim@c.service && break
  done
  if systemctl is-active --quiet wsl-fuse-shim@c.service; then
    cat <<'MSG'

  FUSE mode installed successfully.

  Architecture (per drive):
    Raw DrvFs  -> /mnt/.<letter>-backing  (root-only, chmod 0700)
    FUSE shim  -> /mnt/<letter>           (transparent to all users)

  Drive C: is active by default. Add more with:
    ugow mount d
    ugow mount e

MSG
  else
    cat >&2 <<'MSG'

  WARNING: wsl-fuse-shim@c.service failed to start.

  Debug with:
    sudo systemctl status wsl-fuse-shim@c.service
    sudo journalctl -u wsl-fuse-shim@c.service -n 30

  Common fixes:
    - Ensure /dev/fuse exists:  sudo modprobe fuse
    - Restart WSL and retry:    wsl --shutdown  (from Windows)

MSG
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# Mode: BPF
# ═══════════════════════════════════════════════════════════════════════════

if [[ "$MODE" == "bpf" ]]; then
  echo ""
  echo "--- Installing BPF LSM enforcement ---"

  BPF_UNIT=/etc/systemd/system/ugow-bpf.service
  BPF_LIB=/opt/ugow/bpf

  # Check prerequisites
  for cmd in clang bpftool; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "Error: '$cmd' is required for BPF mode but not found." >&2
      echo "  Install with: sudo apt install -y clang linux-tools-generic" >&2
      exit 1
    fi
  done

  if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "Error: kernel BTF not available at /sys/kernel/btf/vmlinux." >&2
    echo "  Your kernel needs CONFIG_DEBUG_INFO_BTF=y (stock WSL2 kernel has this)." >&2
    exit 1
  fi

  # Build the BPF object
  echo "  Building BPF program..."
  make -C "$SCRIPT_DIR/bpf" -s

  # Install BPF artifacts
  sudo mkdir -p "$BPF_LIB"
  sudo install -m 644 "$SCRIPT_DIR/bpf/ugow.bpf.o" "$BPF_LIB/ugow.bpf.o"
  sudo install -m 755 "$SCRIPT_DIR/bpf/ugow_manage.py" "$UGOW_LIB/ugow_manage.py"
  sudo install -m 644 "$SCRIPT_DIR/permstore.py" "$UGOW_LIB/permstore.py"

  # BPF mode does NOT disable automount -- enforce on the real mount
  _ugow_set_wsl_conf "true"
  echo "  WSL automount left enabled; BPF enforces on real /mnt/c."

  # Create the systemd unit for BPF
  sudo tee "$BPF_UNIT" > /dev/null <<EOF
[Unit]
Description=UGOW BPF LSM enforcement
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=PYTHONPATH=${UGOW_LIB}
ExecStart=${VE}/venv/bin/python ${UGOW_LIB}/ugow_manage.py load
ExecStartPost=${VE}/venv/bin/python ${UGOW_LIB}/ugow_manage.py add-device /mnt/c
ExecStartPost=${VE}/venv/bin/python ${UGOW_LIB}/ugow_manage.py sync
ExecStop=${VE}/venv/bin/python ${UGOW_LIB}/ugow_manage.py unload

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable --now ugow-bpf.service

  cat <<'MSG'

  BPF mode installed successfully.

  Architecture:
    BPF LSM hooks enforce W-bit directly on /mnt/c (kernel-level).
    No FUSE overlay, no mount redirection.

  WSL automount is left enabled -- BPF enforces on the real mount.

MSG
fi

# ═══════════════════════════════════════════════════════════════════════════
# Common output
# ═══════════════════════════════════════════════════════════════════════════

cat <<MSG
Quick start:

  ugow allow ubuntu /mnt/c/docker     # grant write access
  ugow deny  ubuntu /mnt/c/docker     # revoke write access
  ugow check /mnt/c/docker            # can I write here?
  ugow status /mnt/c/docker           # who can write here?
  ugow list                           # show all grants

Installed mode: $MODE

To rollback:

  sudo ./setup.sh --uninstall

MSG
