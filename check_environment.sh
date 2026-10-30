#!/bin/sh
set -eu
ROOT=/Volumes/FYP-DEV
PROJECT="$ROOT/Projects/FYP"
export PATH="$ROOT/Tools/bin:$PATH"
if [ ! -d "$ROOT" ]; then
  echo "ERROR: /Volumes/FYP-DEV is not mounted. Refusing to use internal storage." >&2
  exit 1
fi
if [ ! -d "$PROJECT" ]; then
  echo "ERROR: SSD project is missing at $PROJECT" >&2
  exit 1
fi
echo "SSD volume: $ROOT"
df -h "$ROOT"
echo "Project: $PROJECT"
echo "Python: ${ROOT}/Environments/FYP-DEV/bin/python"
echo "Pip cache: ${ROOT}/Caches/pip"
echo "npm cache: ${ROOT}/Caches/npm"
echo "Go GOPATH: ${ROOT}/Tools/gopath"
for tool in nmap ffuf gobuster nikto docker; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "$tool: $(command -v "$tool")"
  else
    echo "$tool: missing"
  fi
done
