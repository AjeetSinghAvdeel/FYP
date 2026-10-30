#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SSD_ROOT="/Volumes/FYP-DEV"
EXPECTED_PROJECT="$SSD_ROOT/Projects/FYP"
PYTHON="$SSD_ROOT/Environments/FYP-DEV/bin/python"
TOOLS="$SSD_ROOT/Tools/bin"
JUICE_ROOT="$SSD_ROOT/JuiceShop/source"
BACKEND_ROOT="$PROJECT_ROOT/backend"
FRONTEND_ROOT="$PROJECT_ROOT/frontend"
RUNTIME_ROOT="$SSD_ROOT/Runtime/fyp-launcher"
LOCK_ROOT="$RUNTIME_ROOT/lock"
LOG_ROOT="$SSD_ROOT/Logs"

if [[ "$PROJECT_ROOT" != "$EXPECTED_PROJECT" ]]; then
  printf 'ERROR: Refusing to start from %s. The active project must be %s.\n' "$PROJECT_ROOT" "$EXPECTED_PROJECT" >&2
  exit 1
fi
if [[ ! -d "$SSD_ROOT" || ! -x "$PYTHON" ]]; then
  printf 'ERROR: SSD project or Python environment is unavailable. Expected %s and %s.\n' "$EXPECTED_PROJECT" "$PYTHON" >&2
  exit 1
fi

source "$PROJECT_ROOT/ssd-env.sh"
export PATH="$TOOLS:$SSD_ROOT/Environments/FYP-DEV/bin:$PATH"
export PIP_CACHE_DIR="$SSD_ROOT/Caches/pip"
export npm_config_cache="$SSD_ROOT/Caches/npm"
export FYP_BIND_HOST=127.0.0.1
export PYTHONUNBUFFERED=1
export PENTEST_EXECUTION_MODE="${PENTEST_EXECUTION_MODE:-mock}"

mkdir -p "$RUNTIME_ROOT" "$LOG_ROOT" "$SSD_ROOT/Caches/pip" "$SSD_ROOT/Caches/npm"
exec > >(tee -a "$LOG_ROOT/fyp-launcher.log") 2>&1

JUICE_URL='http://127.0.0.1:3000/'
BACKEND_URL='http://127.0.0.1:8000/api/health'
FRONTEND_URL='http://127.0.0.1:5173/'

say() { printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

service_port() {
  case "$1" in
    juice-shop) printf '3000' ;;
    backend) printf '8000' ;;
    frontend) printf '5173' ;;
    *) return 2 ;;
  esac
}

service_url() {
  case "$1" in
    juice-shop) printf '%s' "$JUICE_URL" ;;
    backend) printf '%s' "$BACKEND_URL" ;;
    frontend) printf '%s' "$FRONTEND_URL" ;;
    *) return 2 ;;
  esac
}

service_cwd() {
  case "$1" in
    juice-shop) printf '%s' "$JUICE_ROOT" ;;
    backend) printf '%s' "$BACKEND_ROOT" ;;
    frontend) printf '%s' "$FRONTEND_ROOT" ;;
    *) return 2 ;;
  esac
}

service_fragment() {
  case "$1" in
    juice-shop) printf 'build/app.js' ;;
    backend) printf 'uvicorn app.main:app' ;;
    frontend) printf 'vite/bin/vite.js' ;;
    *) return 2 ;;
  esac
}

listener_pids() {
  /usr/sbin/lsof -nP -t -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | sort -u
}

listener_output() {
  /usr/sbin/lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null || true
}

has_listener() {
  [[ -n "$(listener_pids "$1")" ]]
}

listener_is_loopback() {
  local port="$1" line endpoint found=0
  local output
  output="$(listener_output "$port")"
  [[ -n "$output" ]] || return 1
  while IFS= read -r line; do
    [[ "$line" == COMMAND* ]] && continue
    endpoint="$(printf '%s\n' "$line" | awk '{print $(NF-1)}')"
    case "$endpoint" in
      "127.0.0.1:$port"|"[::1]:$port") found=1 ;;
      *) return 1 ;;
    esac
  done <<< "$output"
  [[ "$found" -eq 1 ]]
}

process_cwd() {
  /usr/sbin/lsof -a -p "$1" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1
}

process_command() {
  ps -ww -p "$1" -o command= 2>/dev/null || true
}

process_matches_service() {
  local service="$1" pid="$2" expected_cwd command
  expected_cwd="$(service_cwd "$service")"
  command="$(process_command "$pid")"
  [[ -n "$command" ]] || return 1
  [[ "$(process_cwd "$pid")" == "$expected_cwd" ]] || return 1
  case "$service" in
    juice-shop) [[ "$command" == *'build/app.js'* ]] ;;
    backend) [[ "$command" == *'uvicorn app.main:app'* || "$command" == *'run.py'* || "$command" == *'spawn_main'* ]] ;;
    frontend) [[ "$command" == *'vite'* ]] ;;
    *) return 1 ;;
  esac
}

service_health() {
  local service="$1" body
  case "$service" in
    juice-shop)
      body="$(curl -fsS --max-time 3 "$JUICE_URL" 2>/dev/null)" || return 1
      [[ "$body" == *'OWASP Juice Shop'* ]] ;;
    backend)
      body="$(curl -fsS --max-time 3 "$BACKEND_URL" 2>/dev/null)" || return 1
      [[ "$body" =~ \"status\"[[:space:]]*:[[:space:]]*\"ok\" ]] ;;
    frontend)
      body="$(curl -fsS --max-time 3 "$FRONTEND_URL" 2>/dev/null)" || return 1
      [[ "$body" == *'<html'* ]] ;;
    *) return 1 ;;
  esac
}

service_identity_is_expected() {
  local service="$1" port pid found=0
  port="$(service_port "$service")"
  listener_is_loopback "$port" || return 1
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    process_matches_service "$service" "$pid" || return 1
    found=1
  done <<< "$(listener_pids "$port")"
  [[ "$found" -eq 1 ]]
}

verify_healthy_service() {
  local service="$1"
  service_health "$service" && service_identity_is_expected "$service"
}

preflight_service() {
  local service="$1" port
  port="$(service_port "$service")"
  if has_listener "$port"; then
    if ! verify_healthy_service "$service"; then
      printf 'ERROR: TCP port %s is occupied, but the listener is not a healthy, loopback-bound %s service from this SSD project. It was left untouched.\n' "$port" "$service" >&2
      listener_output "$port" >&2
      return 1
    fi
    printf '%s' already-running
  else
    printf '%s' absent
  fi
}

write_owned_record() {
  local service="$1" pid="$2"
  local record="$RUNTIME_ROOT/$service.pid" temp="$RUNTIME_ROOT/$service.pid.tmp"
  printf '%s|%s|%s|%s\n' "$pid" "$(service_cwd "$service")" "$(service_fragment "$service")" "$$" > "$temp"
  mv "$temp" "$record"
}

stop_owned_service() {
  local service="$1"
  local record="$RUNTIME_ROOT/$service.pid" pid expected_cwd fragment owner_pid command actual_cwd attempt
  [[ -f "$record" ]] || return 0
  IFS='|' read -r pid expected_cwd fragment owner_pid < "$record" || true
  if [[ ! "$pid" =~ ^[0-9]+$ || -z "${expected_cwd:-}" || -z "${fragment:-}" || ! "${owner_pid:-}" =~ ^[0-9]+$ ]]; then
    say "WARN: Invalid ownership record for $service; leaving it untouched."
    return 1
  fi
  [[ "$owner_pid" == "$$" ]] || return 0
  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$record"
    return 0
  fi
  command="$(process_command "$pid")"
  actual_cwd="$(process_cwd "$pid")"
  if [[ "$actual_cwd" != "$expected_cwd" || "$command" != *"$fragment"* ]]; then
    say "WARN: PID $pid no longer matches the recorded $service process; refusing to signal it."
    return 1
  fi
  say "Stopping launcher-owned $service (PID $pid)..."
  kill -TERM "$pid" 2>/dev/null || true
  for ((attempt=0; attempt<12; attempt++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$record"
      return 0
    fi
    command="$(process_command "$pid")"
    actual_cwd="$(process_cwd "$pid")"
    if [[ "$actual_cwd" != "$expected_cwd" || "$command" != *"$fragment"* ]]; then
      rm -f "$record"
      return 0
    fi
    sleep 1
  done
  command="$(process_command "$pid")"
  actual_cwd="$(process_cwd "$pid")"
  if [[ "$actual_cwd" == "$expected_cwd" && "$command" == *"$fragment"* ]]; then
    say "WARN: $service did not stop after SIGTERM; sending SIGKILL to the verified launcher-owned PID $pid."
    kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f "$record"
}

stop_owned_services() {
  stop_owned_service frontend || true
  stop_owned_service backend || true
  stop_owned_service juice-shop || true
}

release_lock() {
  if [[ -f "$LOCK_ROOT/manager.pid" ]] && [[ "$(cat "$LOCK_ROOT/manager.pid")" == "$$" ]]; then
    rm -f "$LOCK_ROOT/manager.pid"
    rmdir "$LOCK_ROOT" 2>/dev/null || true
  fi
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  stop_owned_services
  release_lock
  exit "$status"
}

on_signal() {
  say ''
  say 'Shutdown requested; stopping only services started by this launcher.'
  exit 0
}

check_live_manager() {
  local pid command
  [[ -f "$LOCK_ROOT/manager.pid" ]] || return 1
  pid="$(cat "$LOCK_ROOT/manager.pid" 2>/dev/null || true)"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  command="$(process_command "$pid")"
  [[ "$command" == *'start_all.sh'* ]]
}

print_running_urls() {
  say ''
  say '========================================'
  say '           PROJECT IS RUNNING'
  say '========================================'
  say 'Frontend:    http://127.0.0.1:5173'
  say 'Backend:     http://127.0.0.1:8000'
  say 'Health:      http://127.0.0.1:8000/api/health'
  say 'Juice Shop:  http://127.0.0.1:3000'
  say "Logs:        $LOG_ROOT/fyp-*.log"
  say 'Press Ctrl+C or run npm run stop:all to stop services started by this launcher.'
  say '========================================'
}

if check_live_manager; then
  ready=0
  for ((attempt=0; attempt<45; attempt++)); do
    if verify_healthy_service juice-shop && verify_healthy_service backend && verify_healthy_service frontend; then ready=1; break; fi
    sleep 1
  done
  [[ "$ready" -eq 1 ]] || fail 'The active launcher has not reached a healthy state; no duplicate services were started.'
  say 'The FYP launcher already owns a healthy stack; no duplicate services were started.'
  print_running_urls
  exit 0
fi

check_step="$(preflight_service juice-shop)" || fail 'Juice Shop port preflight failed.'
EXISTING_JUICE=0; [[ "$check_step" == already-running ]] && EXISTING_JUICE=1
check_step="$(preflight_service backend)" || fail 'Backend port preflight failed.'
EXISTING_BACKEND=0; [[ "$check_step" == already-running ]] && EXISTING_BACKEND=1
check_step="$(preflight_service frontend)" || fail 'Frontend port preflight failed.'
EXISTING_FRONTEND=0; [[ "$check_step" == already-running ]] && EXISTING_FRONTEND=1

if [[ -d "$LOCK_ROOT" ]]; then
  stale_pid="$(cat "$LOCK_ROOT/manager.pid" 2>/dev/null || true)"
  if [[ "$stale_pid" =~ ^[0-9]+$ ]] && kill -0 "$stale_pid" 2>/dev/null; then
    fail "Launcher lock is held by PID $stale_pid, whose identity could not be verified. No process was changed."
  fi
  rm -f "$LOCK_ROOT/manager.pid"
  rmdir "$LOCK_ROOT" 2>/dev/null || fail 'Could not clear stale launcher lock safely.'
fi
mkdir "$LOCK_ROOT" 2>/dev/null || fail 'Another launcher instance is acquiring the runtime lock; retry shortly.'
printf '%s\n' "$$" > "$LOCK_ROOT/manager.pid"
trap cleanup EXIT
trap on_signal INT TERM HUP

say '========================================'
say '       FYP UNIVERSAL PROJECT LAUNCHER'
say '========================================'
say '[1/6] Checking SSD project directory... OK'
say '[2/6] Loading SSD environment... OK'

if [[ ! -x "$PYTHON" ]]; then fail "SSD Python is unavailable: $PYTHON"; fi
if [[ ! -x "$(command -v node || true)" || ! -x "$(command -v npm || true)" ]]; then fail 'Node.js and npm must be available on PATH.'; fi
if [[ ! -f "$JUICE_ROOT/build/app.js" ]]; then fail "Juice Shop build is missing: $JUICE_ROOT/build/app.js"; fi

if ! "$PYTHON" -c 'import fastapi, uvicorn, sqlalchemy, pydantic_settings' >/dev/null 2>&1; then
  say 'Python runtime dependencies are missing; installing into the SSD virtual environment...'
  "$PYTHON" -m pip install -r "$BACKEND_ROOT/requirements.txt"
fi
"$PYTHON" -m pip check >/dev/null || fail 'Python environment has dependency conflicts; see pip check output.'
if [[ ! -x "$FRONTEND_ROOT/node_modules/.bin/vite" ]]; then
  say 'Frontend dependencies are missing; installing into the SSD project...'
  if [[ -f "$FRONTEND_ROOT/package-lock.json" ]]; then
    npm --prefix "$FRONTEND_ROOT" ci --cache "$npm_config_cache"
  else
    npm --prefix "$FRONTEND_ROOT" install --cache "$npm_config_cache"
  fi
fi
[[ -f "$FRONTEND_ROOT/node_modules/vite/bin/vite.js" ]] || fail 'Vite is not installed in the SSD frontend node_modules.'
say '[3/6] Checking Python and Node dependencies... OK'

for tool in nmap ffuf gobuster nikto; do
  tool_path="$TOOLS/$tool"
  [[ -x "$tool_path" ]] || fail "Required SSD security tool is missing or not executable: $tool_path"
  case "$tool" in
    nmap) version_output="$("$tool_path" --version 2>&1)" ;;
    ffuf) version_output="$("$tool_path" -V 2>&1)" ;;
    gobuster) version_output="$("$tool_path" --version 2>&1)" ;;
    nikto) version_output="$("$tool_path" -Version 2>&1)" ;;
  esac
  [[ -n "$version_output" ]] || fail "Could not verify $tool version."
  printf '  %s: %s\n' "$tool" "${version_output%%$'\n'*}"
done
say '[4/6] Checking security tools... OK'

printf '[5/6] Starting OWASP Juice Shop... '
if [[ "$EXISTING_JUICE" -eq 1 ]]; then
  say 'READY (already healthy; left untouched)'
else
  if has_listener 3000; then fail 'Port 3000 became occupied during startup; refusing to signal its owner.'; fi
  cd "$JUICE_ROOT"
  HOST=127.0.0.1 PORT=3000 nohup node build/app.js >> "$LOG_ROOT/fyp-juice-shop.log" 2>&1 &
  juice_pid=$!
  write_owned_record juice-shop "$juice_pid"
  ready=0
  for ((attempt=0; attempt<45; attempt++)); do
    if verify_healthy_service juice-shop; then ready=1; break; fi
    if ! kill -0 "$juice_pid" 2>/dev/null; then break; fi
    sleep 1
  done
  if [[ "$ready" -ne 1 ]]; then
    tail -n 30 "$LOG_ROOT/fyp-juice-shop.log" >&2 || true
    fail 'Juice Shop failed its loopback HTTP health check; launcher-owned services will be stopped.'
  fi
  say 'READY'
fi

printf '[6/6] Starting backend and frontend... '
if [[ "$EXISTING_BACKEND" -eq 0 ]]; then
  if has_listener 8000; then fail 'Port 8000 became occupied during startup; refusing to signal its owner.'; fi
  cd "$BACKEND_ROOT"
  nohup "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log >> "$LOG_ROOT/fyp-backend.log" 2>&1 &
  backend_pid=$!
  write_owned_record backend "$backend_pid"
fi
if [[ "$EXISTING_FRONTEND" -eq 0 ]]; then
  if has_listener 5173; then fail 'Port 5173 became occupied during startup; refusing to signal its owner.'; fi
  cd "$FRONTEND_ROOT"
  nohup node "$FRONTEND_ROOT/node_modules/vite/bin/vite.js" --host 127.0.0.1 --port 5173 --strictPort >> "$LOG_ROOT/fyp-frontend.log" 2>&1 &
  frontend_pid=$!
  write_owned_record frontend "$frontend_pid"
fi

for service in backend frontend; do
  case "$service" in
    backend) existing="$EXISTING_BACKEND" ;;
    frontend) existing="$EXISTING_FRONTEND" ;;
  esac
  if [[ "$existing" -eq 1 ]]; then
    verify_healthy_service "$service" || fail "Pre-existing $service stopped responding during startup."
    printf '%s: READY (already healthy; left untouched)\n' "$service"
    continue
  fi
  ready=0
  for ((attempt=0; attempt<45; attempt++)); do
    if verify_healthy_service "$service"; then ready=1; break; fi
    case "$service" in
      backend) current_pid="$backend_pid" ;;
      frontend) current_pid="$frontend_pid" ;;
    esac
    if ! kill -0 "$current_pid" 2>/dev/null; then break; fi
    sleep 1
  done
  if [[ "$ready" -ne 1 ]]; then
    case "$service" in
      backend) tail -n 40 "$LOG_ROOT/fyp-backend.log" >&2 || true ;;
      frontend) tail -n 40 "$LOG_ROOT/fyp-frontend.log" >&2 || true ;;
    esac
    fail "$service failed its loopback HTTP health check; launcher-owned services will be stopped."
  fi
  printf '%s: READY\n' "$service"
done

say '[6/6] Backend and frontend health checks... OK'
print_running_urls

while true; do
  for service in juice-shop backend frontend; do
    verify_healthy_service "$service" || fail "$service became unhealthy; stopping launcher-owned services."
  done
  sleep 2
done
