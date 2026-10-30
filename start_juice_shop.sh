#!/bin/sh
set -eu
ROOT=/Volumes/FYP-DEV
if [ ! -d "$ROOT" ]; then
  echo "ERROR: /Volumes/FYP-DEV is not mounted. Refusing to use internal storage." >&2
  exit 1
fi
if [ -f "$ROOT/JuiceShop/source/build/app.js" ]; then
  mkdir -p "$ROOT/Logs" "$ROOT/Runtime"
  cd "$ROOT/JuiceShop/source"
  if /usr/sbin/lsof -nP -iTCP:3000 -sTCP:LISTEN >/dev/null 2>&1; then
    echo "ERROR: port 3000 is already in use; refusing to replace an unknown listener." >&2
    exit 1
  fi
  HOST=127.0.0.1 PORT=3000 nohup node build/app.js >"$ROOT/Logs/juice-shop.log" 2>&1 &
  echo $! >"$ROOT/Runtime/juice-shop.pid"
  echo "Juice Shop: http://127.0.0.1:3000"
  exit 0
elif command -v docker >/dev/null 2>&1; then
  cd "$ROOT/Projects/FYP"
  docker compose up -d juice-shop
  echo "Juice Shop: http://127.0.0.1:3000"
  exit 0
fi
echo "ERROR: Native Juice Shop build is unavailable and Docker is not installed." >&2
exit 1
