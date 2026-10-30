#!/bin/sh
set -eu
ROOT=/Volumes/FYP-DEV
export PATH="$ROOT/Tools/bin:$PATH"
if [ ! -d "$ROOT" ]; then
  echo "ERROR: /Volumes/FYP-DEV is not mounted." >&2
  exit 1
fi
for tool in nmap ffuf gobuster nikto; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "[$tool] $(command -v "$tool")"
    case "$tool" in
      nmap) nmap --version | head -1 ;;
      ffuf) ffuf -V ;;
      gobuster) gobuster --version ;;
      nikto) nikto -Version ;;
    esac
  else
    echo "[$tool] MISSING"
  fi
done
