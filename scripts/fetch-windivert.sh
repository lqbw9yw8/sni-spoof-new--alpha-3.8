#!/usr/bin/env bash
# Fetch the official WinDivert SDK files needed to build/run dpi_guard.
#
# The repo never commits WinDivert.dll/.lib/.sys (see .gitignore). This
# script downloads the pinned official release and verifies the archive
# and every extracted file against SHA-256 pins before placing them next
# to the repo root. Any mismatch aborts with nothing kept.
#
# Usage:  scripts/fetch-windivert.sh [arch]     # arch: x64 (default) | x86
set -euo pipefail

ARCH="${1:-x64}"
case "$ARCH" in
  x64) SYS="WinDivert64.sys" ;;
  x86) SYS="WinDivert32.sys" ;;
  *) echo "unknown arch: $ARCH (use x64 or x86)"; exit 1 ;;
esac

VER="2.2.2"
URL="https://github.com/basil00/WinDivert/releases/download/v${VER}/WinDivert-${VER}-A.zip"
ZIP_SHA256="63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15"
# Per-file pins for the official 2.2.2 release (x64 files).
PIN_DLL="c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"
PIN_LIB="c5678d544eb0121a189d1139f54e0c67854dc64d1c897111a27ef2e52cb38eb3"
PIN_SYS64="8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "downloading WinDivert ${VER} (${ARCH})..."
curl -fsSL -o "$TMP/wd.zip" "$URL"

echo "$ZIP_SHA256  $TMP/wd.zip" | sha256sum -c -

UNPACK="$TMP/WinDivert-${VER}-A"
unzip -q -o "$TMP/wd.zip" -d "$TMP"

verify() { # file pin
  local got
  got="$(sha256sum "$1" | cut -d' ' -f1)"
  if [ -n "$2" ]; then
    [ "$got" = "$2" ] || { echo "FATAL: $(basename "$1") hash mismatch ($got)"; exit 1; }
  fi
  echo "OK  $(basename "$1")  $got"
}

verify "$UNPACK/$ARCH/WinDivert.dll" "$PIN_DLL"
verify "$UNPACK/$ARCH/WinDivert.lib" "$PIN_LIB"
# x86 is covered by the zip pin; only x64 has an individual pin.
if [ "$SYS" = "WinDivert64.sys" ]; then
  verify "$UNPACK/$ARCH/$SYS" "$PIN_SYS64"
else
  verify "$UNPACK/$ARCH/$SYS" ""
fi

cp "$UNPACK/$ARCH/WinDivert.dll" "$REPO/WinDivert.dll"
cp "$UNPACK/$ARCH/WinDivert.lib" "$REPO/WinDivert.lib"
cp "$UNPACK/$ARCH/$SYS" "$REPO/$SYS"
echo "WinDivert ${VER} files installed in $REPO (hash-verified)."
