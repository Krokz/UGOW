#!/bin/bash
set -euo pipefail

LETTER="$1"
BACKING="/mnt/.${LETTER}-backing"

mountpoint -q "$BACKING" && exit 0

for n in $(seq 1 5); do
    mount -t drvfs "$(echo "$LETTER" | tr a-z A-Z):" "$BACKING" -o metadata && exit 0
    sleep 2
done

echo "drvfs mount failed after 5 attempts" >&2
exit 1
