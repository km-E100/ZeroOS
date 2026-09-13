#!/bin/sh
set -e
OUT="$1"
SRC="$2"
ESP_REL="$3"
if [ -n "$ESP_REL" ]; then
  ESP_ABS="$SRC/$ESP_REL"
else
  ESP_ABS=""
fi
TRIED_ESP=0

USE_XORRISO=0
if command -v xorriso >/dev/null 2>&1; then
  if xorriso -as mkisofs -version >/dev/null 2>&1; then
    USE_XORRISO=1
  fi
fi

if [ "$USE_XORRISO" -eq 0 ]; then
  if [ -x /opt/homebrew/bin/mkisofs ]; then
    MKISOFS=/opt/homebrew/bin/mkisofs
  elif command -v mkisofs >/dev/null 2>&1; then
    MKISOFS=$(command -v mkisofs)
  else
    echo "xtask: error: mkisofs not found; install cdrtools or set MKISOFS" >&2
    exit 1
  fi
fi

run_mkisofs() {
  if [ "$USE_XORRISO" -eq 1 ]; then
    xorriso -as mkisofs "$@"
  else
    "$MKISOFS" "$@"
  fi
}

if [ -n "$ESP_REL" ] && [ -f "$ESP_ABS" ]; then
  TRIED_ESP=1
  if run_mkisofs -R -J -V ZEROOS -eltorito-alt-boot -eltorito-platform efi -e "$ESP_REL" -no-emul-boot -append_partition 2 0xef "$ESP_ABS" -o "$OUT" "$SRC"; then
    exit 0
  fi
fi

if [ "$TRIED_ESP" -eq 1 ]; then
  echo "xtask: warning: mkisofs rejected -eltorito-alt-boot for ESP image, retrying with -b" >&2
fi
if run_mkisofs -R -J -V ZEROOS -b EFI/BOOT/BOOTAA64.EFI -no-emul-boot -o "$OUT" "$SRC"; then
  exit 0
fi

echo "xtask: warning: mkisofs lacks El Torito support; generating basic ISO" >&2
run_mkisofs -R -J -o "$OUT" "$SRC"
