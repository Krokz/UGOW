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

if [[ "$UNINSTALL" == true ]]; then
  echo "--- Uninstalling UGOW ---"

  # Stop and disable FUSE shim units
  for unit in $(systemctl list-units 'wsl-fuse-shim@*.service' \
                --plain --no-legend --all 2>/dev/null | awk '{print $1}'); do
    sudo systemctl disable --now "$unit" 2>/dev/null || true
    echo "  Stopped: $unit"
  done
  sudo rm -f /etc/systemd/system/wsl-fuse-shim@.service

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

  echo ""
  echo "  UGOW has been fully uninstalled."
  echo ""
  echo "  Note: /var/lib/ugow/wperm.db (permission database) was preserved."
  echo "  To remove it:  sudo rm -rf /var/lib/ugow"
  echo ""
  echo "  Run 'wsl --shutdown' from Windows to apply wsl.conf changes."
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

# ═══════════════════════════════════════════════════════════════════════════
# Base install (always): CLI + permstore + venv
# ═══════════════════════════════════════════════════════════════════════════

echo "--- Installing base (CLI + permission store) ---"

sudo mkdir -p "$UGOW_LIB"
sudo install -m 644 "$SCRIPT_DIR/permstore.py" "$UGOW_LIB/permstore.py"
sudo install -m 755 "$SCRIPT_DIR/cli.py"       "$UGOW_BIN"

sudo mkdir -p /var/lib/ugow
sudo chmod 0700 /var/lib/ugow
sudo chown root:root /var/lib/ugow

if [ ! -d "$VE/venv" ]; then
  sudo mkdir -p "$VE"
  sudo chown "$USER":"$USER" "$VE"
  python3 -m venv "$VE/venv"
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
  "$VE/venv/bin/pip" install --upgrade --quiet fusepy

  # Install shim + permstore for the FUSE daemon
  if [ -e "$SHIM_BIN" ] && ! grep -q '# Shim: UGOW' "$SHIM_BIN"; then
    echo "$SHIM_BIN exists and doesn't look like UGOW shim. Aborting." >&2
    exit 1
  fi
  sudo install -m 755 "$SCRIPT_DIR/shim.py" "$SHIM_BIN"
  echo "# Shim: UGOW" | sudo tee -a "$SHIM_BIN" >/dev/null
  sudo install -m 644 "$SCRIPT_DIR/permstore.py" "$UGOW_LIB/permstore.py"

  # Enable user_allow_other in /etc/fuse.conf
  if ! grep -q '^user_allow_other' "$FUSE_CONF"; then
    echo "  Enabling 'user_allow_other' in $FUSE_CONF"
    sudo sed -i 's/^#user_allow_other/user_allow_other/' "$FUSE_CONF"
  fi

  # Disable WSL automount so UGOW owns /mnt/*
  sudo tee "$WSL_CONF" > /dev/null <<'WSLEOF'
[automount]
enabled = false
options = "metadata"

[boot]
systemd = true
WSLEOF
  echo "  WSL automount disabled; UGOW will mount drives via FUSE."

  # Create the systemd template unit (one instance per drive letter)
  sudo tee "$UNIT_TEMPLATE" > /dev/null <<EOF
[Unit]
Description=UGOW FUSE Shim for /mnt/%i
After=local-fs.target

[Service]
Type=simple
ExecStartPre=-/bin/umount -l /mnt/%i
ExecStartPre=-/usr/bin/fusermount -uz /mnt/%i
ExecStartPre=/bin/mkdir -p /mnt/.%i-backing /mnt/%i
ExecStartPre=/bin/sh -c 'mountpoint -q /mnt/.%i-backing && exit 0; n=0; while [ \$n -lt 5 ]; do mount -t drvfs "\$(echo %i | tr a-z A-Z):" /mnt/.%i-backing -o metadata && exit 0; n=\$((n+1)); sleep 2; done; echo "drvfs mount failed after 5 attempts" >&2; exit 1'
ExecStartPre=-/bin/chmod 0700 /mnt/.%i-backing
Environment=PYTHONPATH=${UGOW_LIB}
ExecStart=${VE}/venv/bin/python ${SHIM_BIN} --launcher-uid ${REAL_UID} /mnt/.%i-backing /mnt/%i
ExecStopPost=-/bin/sh -c 'fusermount -uz /mnt/%i 2>/dev/null; umount /mnt/.%i-backing 2>/dev/null; true'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  # Enable & start for C: by default
  sudo systemctl daemon-reload
  sudo systemctl enable --now wsl-fuse-shim@c.service

  # Verify the service actually started
  echo ""
  echo "  Waiting for FUSE shim to start..."
  sleep 3
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
  sudo tee "$WSL_CONF" > /dev/null <<'WSLEOF'
[automount]
enabled = true
options = "metadata"

[boot]
systemd = true
WSLEOF
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

  sudo ./install.sh --uninstall
  wsl --shutdown

MSG
