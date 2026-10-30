#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SSD_ROOT="/Volumes/FYP-DEV"
RUNTIME_ROOT="$SSD_ROOT/Runtime/fyp-launcher"
LOCK_ROOT="$RUNTIME_ROOT/lock"

if [[ "$PROJECT_ROOT" != "$SSD_ROOT/Projects/FYP" || ! -d "$SSD_ROOT" ]]; then
  printf 'ERROR: Refusing shutdown outside the authoritative SSD project: %s\n' "$PROJECT_ROOT" >&2
  exit 1
fi

process_command() { ps -ww -p "$1" -o command= 2>/dev/null || true; }
process_cwd() { /usr/sbin/lsof -a -p "$1" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1; }

stop_recorded_orphan() {
  local service="$1" record="$RUNTIME_ROOT/$service.pid" pid expected_cwd fragment owner_pid command cwd attempt
  [[ -f "$record" ]] || return 0
  IFS='|' read -r pid expected_cwd fragment owner_pid < "$record" || true
  if [[ ! "${pid:-}" =~ ^[0-9]+$ || -z "${expected_cwd:-}" || -z "${fragment:-}" || ! "${owner_pid:-}" =~ ^[0-9]+$ ]]; then
    printf 'WARN: Invalid %s ownership record; leaving it untouched.\n' "$service" >&2
    return 1
  fi
  if kill -0 "$owner_pid" 2>/dev/null && [[ "$(process_command "$owner_pid")" == *'start_all.sh'* ]]; then
    printf 'WARN: Launcher PID %s is still active; it must perform its own cleanup.\n' "$owner_pid" >&2
    return 1
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$record"
    return 0
  fi
  command="$(process_command "$pid")"
  cwd="$(process_cwd "$pid")"
  if [[ "$cwd" != "$expected_cwd" || "$command" != *"$fragment"* ]]; then
    printf 'WARN: PID %s no longer matches the recorded %s process; refusing to signal it.\n' "$pid" "$service" >&2
    return 1
  fi
  printf 'Stopping verified orphaned launcher process %s (PID %s)...\n' "$service" "$pid"
  kill -TERM "$pid" 2>/dev/null || true
  for ((attempt=0; attempt<12; attempt++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$record"
      return 0
    fi
    command="$(process_command "$pid")"
    cwd="$(process_cwd "$pid")"
    if [[ "$cwd" != "$expected_cwd" || "$command" != *"$fragment"* ]]; then
      rm -f "$record"
      return 0
    fi
    sleep 1
  done
  command="$(process_command "$pid")"
  cwd="$(process_cwd "$pid")"
  if [[ "$cwd" == "$expected_cwd" && "$command" == *"$fragment"* ]]; then
    printf 'WARN: %s did not exit after SIGTERM; leaving it running for safety.\n' "$service" >&2
    return 1
  fi
  rm -f "$record"
}

manager_pid=''
if [[ -f "$LOCK_ROOT/manager.pid" ]]; then
  manager_pid="$(cat "$LOCK_ROOT/manager.pid" 2>/dev/null || true)"
fi
if [[ "$manager_pid" =~ ^[0-9]+$ ]] && kill -0 "$manager_pid" 2>/dev/null; then
  manager_command="$(process_command "$manager_pid")"
  if [[ "$manager_command" != *'start_all.sh'* ]]; then
    printf 'ERROR: Runtime lock PID %s does not identify start_all.sh; refusing to signal it.\n' "$manager_pid" >&2
    exit 1
  fi
  printf 'Requesting graceful shutdown from FYP launcher (PID %s)...\n' "$manager_pid"
  kill -TERM "$manager_pid"
  for ((attempt=0; attempt<20; attempt++)); do
    [[ -d "$LOCK_ROOT" ]] || { printf 'Launcher-owned services stopped. Logs and application data were preserved.\n'; exit 0; }
    sleep 1
  done
  printf 'ERROR: Launcher did not release its runtime lock in time. Inspect %s.\n' "$RUNTIME_ROOT" >&2
  exit 1
fi

stopped=0
for service in frontend backend juice-shop; do
  if [[ -f "$RUNTIME_ROOT/$service.pid" ]]; then
    stop_recorded_orphan "$service" && stopped=1 || true
  fi
done
if [[ -f "$LOCK_ROOT/manager.pid" ]]; then
  rm -f "$LOCK_ROOT/manager.pid"
  rmdir "$LOCK_ROOT" 2>/dev/null || true
fi
if [[ "$stopped" -eq 1 ]]; then
  printf 'Orphaned launcher-owned processes stopped. Logs and application data were preserved.\n'
else
  printf 'No active processes owned by the universal launcher. Existing healthy services were left untouched.\n'
fi
