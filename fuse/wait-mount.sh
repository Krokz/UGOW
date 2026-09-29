#!/bin/bash
# Block until the FUSE shim has finished mounting /mnt/<letter>.
#
# The shim runs in the foreground, so systemd's Type=simple considers the unit
# started as soon as the process forks -- before libfuse has mounted anything.
# Running this as ExecStartPost keeps the unit in "activating" until the mount
# is real, so units ordered After= it do not race an unmounted drive.
set -euo pipefail

LETTER="$1"
MOUNT="/mnt/${LETTER}"
TIMEOUT_DECISECONDS="${2:-200}"   # default: 20s in 0.1s steps

n=0
while [ "$n" -lt "$TIMEOUT_DECISECONDS" ]; do
    if mountpoint -q "$MOUNT"; then
        exit 0
    fi
    n=$((n + 1))
    sleep 0.1
done

echo "$MOUNT did not become a mount point in time" >&2
exit 1
