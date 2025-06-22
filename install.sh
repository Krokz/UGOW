#!/usr/bin/env bash
set -euo pipefail

# Ensure we’re in WSL
if ! grep -qi Microsoft /proc/version; then
  echo "⚠️  This installer only works inside WSL2. Aborting." >&2
  exit 1
fi

# Define paths
WSL_CONF=/etc/wsl.conf
FUSE_CONF=/etc/fuse.conf
UNIT_FILE=/etc/systemd/system/wsl-fuse-shim.service
SHIM_BIN=/usr/local/bin/wsl-fuse-shim

# Backup originals
for f in "$WSL_CONF" "$FUSE_CONF" "$UNIT_FILE"; do
  if [ -e "$f" ]; then
    sudo cp -n "$f" "${f}.bak_$(date +%Y%m%d%H%M)" \
      && echo "Backup: $f → ${f}.bak_*"
  fi
done

# Install the shim binary
if [ -e "$SHIM_BIN" ] && ! grep -q '# Shim: UGOW' "$SHIM_BIN"; then
  echo "⚠️  $SHIM_BIN exists and doesn't look like UGOW shim. Aborting." >&2
  exit 1
fi
sudo install -m 755 shim.py "$SHIM_BIN"
echo "# Shim: UGOW" | sudo tee -a "$SHIM_BIN" >/dev/null

# Install Python deps into a dedicated venv (avoids polluting system Python)
VE_PATCH=/opt/wsl-fuse-shim
if [ ! -d "$VE_PATCH/venv" ]; then
  sudo mkdir -p "$VE_PATCH"
  sudo chown "$USER":"$USER" "$VE_PATCH"
  python3 -m venv "$VE_PATCH/venv"
  "$VE_PATCH/venv/bin/pip" install --upgrade fusepy xattr
fi

# Enable user_allow_other in /etc/fuse.conf
if ! grep -q '^user_allow_other' "$FUSE_CONF"; then
  echo "Enabling 'user_allow_other' in $FUSE_CONF"
  sudo sed -i 's/^#user_allow_other/user_allow_other/' "$FUSE_CONF"
fi

# Write a safe /etc/wsl.conf
sudo tee "$WSL_CONF" > /dev/null <<'EOF'
[automount]
enabled = false
options = "metadata"

[boot]
systemd = true
EOF
echo "⏱  WSL will now use metadata, and automount is disabled."

# Create your systemd unit
sudo tee "$UNIT_FILE" > /dev/null <<'EOF'
[Unit]
Description=UGOW FUSE Shim for Windows Drives
After=network-online.target

[Service]
Type=simple
ExecStart=${SHIM_BIN} /mnt/c /mnt/c -o allow_other,default_permissions
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Enable & start the service
sudo systemctl daemon-reload
sudo systemctl enable wsl-fuse-shim.service
sudo systemctl start  wsl-fuse-shim.service

cat <<MSG

✅ Installation complete!

• A backup of any modified file lives alongside the original (e.g. /etc/wsl.conf.bak_*)
• Your shim is running as a systemd service over /mnt/c
• To rollback:
    sudo systemctl disable --now wsl-fuse-shim.service
    sudo rm $UNIT_FILE
    sudo cp /etc/wsl.conf.bak_* /etc/wsl.conf
    sudo cp /etc/fuse.conf.bak_* /etc/fuse.conf
    wsl --shutdown

Now, reboot your WSL (`wsl --shutdown`), then everything under /mnt/c will go through your UGOWShim automatically—**no per-session commands** required.

MSG
