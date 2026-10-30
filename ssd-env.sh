#!/bin/sh
set -eu
ROOT=/Volumes/FYP-DEV
if [ ! -d "$ROOT" ]; then
  echo "ERROR: /Volumes/FYP-DEV is not mounted." >&2
  return 1 2>/dev/null || exit 1
fi
export FYP_ROOT="$ROOT"
export FYP_PROJECT="$ROOT/Projects/FYP"
export PIP_CACHE_DIR="$ROOT/Caches/pip"
export npm_config_cache="$ROOT/Caches/npm"
export GOPATH="$ROOT/Tools/gopath"
export GOBIN="$ROOT/Tools/bin"
export GOCACHE="$ROOT/Caches/go"
export NMAP_PATH="$ROOT/Tools/bin/nmap"
export FFUF_PATH="$ROOT/Tools/bin/ffuf"
export GOBUSTER_PATH="$ROOT/Tools/bin/gobuster"
export NIKTO_PATH="$ROOT/Tools/bin/nikto"
export NMAPDIR="$ROOT/Tools/Nmap/nmap.app/Contents/Resources/share/nmap"
export DYLD_LIBRARY_PATH="$ROOT/Tools/Nmap/nmap.app/Contents/Resources/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export PATH="$ROOT/Tools/bin:$ROOT/Environments/FYP-DEV/bin:$PATH"
