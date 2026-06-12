#!/usr/bin/env bash
set -e

WORK="$HOME/sift_small_case"
SEED="$WORK/seed"
IMAGE="$HOME/small_case.dd"

rm -rf "$WORK"
rm -f "$IMAGE"
mkdir -p "$SEED/Users/analyst/Documents"
mkdir -p "$SEED/Windows/Temp"
mkdir -p "$SEED/Windows/System32/drivers/etc"
mkdir -p "$SEED/ProgramData/Microsoft"

cat > "$SEED/Users/analyst/Documents/incident_notes.txt" <<'TEXT'
Incident notes 2026-06-10
Observed an encoded PowerShell command launched from a scheduled task.
A new executable appeared under Windows\Temp after a remote logon.
Outbound traffic to an unfamiliar host followed shortly after.
TEXT

printf 'MZ' > "$SEED/Windows/Temp/svchost_update.exe"
printf '\x90\x00\x03\x00\x00\x00\x04\x00' >> "$SEED/Windows/Temp/svchost_update.exe"
printf 'This program cannot be run in DOS mode.\r\n' >> "$SEED/Windows/Temp/svchost_update.exe"
head -c 4096 /dev/urandom >> "$SEED/Windows/Temp/svchost_update.exe"

cat > "$SEED/ProgramData/Microsoft/run_once.bat" <<'TEXT'
@echo off
powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA
TEXT

cat > "$SEED/Windows/System32/drivers/etc/hosts" <<'TEXT'
127.0.0.1 localhost
185.234.219.10 update.microsoft-cdn-secure.com
TEXT

if command -v mke2fs >/dev/null 2>&1; then
  mke2fs -q -F -t ext2 -L SIFTCASE -d "$SEED" "$IMAGE" 16M
  echo "FILESYSTEM=ext2"
elif command -v mkfs.vfat >/dev/null 2>&1 && command -v mcopy >/dev/null 2>&1; then
  dd if=/dev/zero of="$IMAGE" bs=1M count=16 status=none
  mkfs.vfat -F 16 -n SIFTCASE "$IMAGE" >/dev/null
  ( cd "$SEED" && for entry in *; do mcopy -s -i "$IMAGE" "$entry" ::; done )
  echo "FILESYSTEM=fat"
else
  echo "ERROR: no usable filesystem builder (need mke2fs or mkfs.vfat+mcopy)" >&2
  exit 3
fi

echo "IMAGE=$IMAGE"
echo "SIZE_BYTES=$(stat -c%s "$IMAGE")"
echo "SHA256=$(sha256sum "$IMAGE" | cut -d' ' -f1)"
