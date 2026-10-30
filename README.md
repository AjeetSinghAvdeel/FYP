# Risk-Guided Adaptive Pentest Prototype

## SSD Development Environment

The verified external SSD volume is mounted at `/Volumes/Ajeet SSD 1`; the APFS sparse bundle is mounted at `/Volumes/FYP-DEV`. The migrated project is `/Volumes/FYP-DEV/Projects/FYP`. The original `/Users/mac/Desktop/FYP` remains intact.

Open the migrated copy in VS Code with:

```bash
code /Volumes/FYP-DEV/Projects/FYP
```

Run `/Volumes/FYP-DEV/Projects/FYP/check_environment.sh` before starting. The SSD Python environment is `/Volumes/FYP-DEV/Environments/FYP-DEV`; pip/npm/Go caches and reports are under the SSD volume. Start and stop services with `start_fyp.sh` and `stop_fyp.sh` from the migrated project. These scripts refuse to run when the SSD volume is unavailable.

The physical SSD is ExFAT and was not formatted. The APFS development filesystem is a 240 GB sparse bundle at `/Volumes/Ajeet SSD 1/FYP-Storage/FYP-DEV.sparsebundle`. To remount it after disconnecting the SSD:

```bash
hdiutil attach '/Volumes/Ajeet SSD 1/FYP-Storage/FYP-DEV.sparsebundle' -nobrowse
```

Use `/Volumes/FYP-DEV/start_juice_shop.sh` only after Docker or a native Juice Shop installation is available. The lab target must remain bound to loopback.

A local-lab FastAPI and React prototype for adaptive, authorized security assessment. The backend ranks predefined actions with deterministic eight-factor scoring, applies policy checks, executes safe adapters, validates evidence, and updates an attack-graph snapshot. The rule-based planner is the default; OpenAI-compatible and Ollama providers are optional.

## Run locally

```bash
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
PENTEST_EXECUTION_MODE=mock python3 run.py
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL, register a user, register a loopback target such as `http://127.0.0.1:3000`, create an assessment, and run steps from the assessment queue. Swagger is available at `http://localhost:8000/docs`.

For the isolated native Juice Shop lab, see [LAB.md](LAB.md) and run `/Volumes/FYP-DEV/Projects/FYP/start_juice_shop.sh`. The verified build uses Node 22 on macOS and binds to loopback; Docker Desktop is optional.

## Safety defaults

Only localhost, `.local` hostnames, and private, loopback, or link-local IP addresses are accepted by default. Keep `PENTEST_EXECUTION_MODE=mock` for demonstrations. Set `ALLOW_PUBLIC_TARGETS=true` only when the operator has documented authorization and understands the risk. Real adapters use argument arrays, append the registered target themselves, and enforce a timeout.

## Risk model

The backend calculates `P(a) = B(a) - D(a)` using Severity, Exploitability, Asset Criticality, Privilege Gain, Impact, Information Gain, Execution Cost, and Uncertainty. The six weights in the paper's chart are retained as the initial reference profile; Information Gain and Uncertainty remain explicit configurable factors. Numerical scores are never supplied by the LLM.

## External tools and providers

Install the real tools on supported macOS versions with `brew install nmap ffuf gobuster nikto`. On macOS 12, Homebrew may require source builds or fail due its support tier; this host has no verified binaries. Missing tools do not prevent mock execution. The adapters automatically detect availability and expose versions at `/api/tools/health`. FFUF and Gobuster use `backend/data/wordlist.txt` unless overridden with `FFUF_WORDLIST` or `GOBUSTER_WORDLIST`. Set `LLM_PROVIDER=ollama` or `LLM_PROVIDER=openai` and the relevant model/API variables to enable an external planner; the deterministic planner remains the fallback.

The assessment event stream is available at `/api/assessments/{id}/events` and the frontend consumes it with authenticated fetch streaming. New users are `security_operator` accounts. Only an administrator can use `/api/admin/users` and change roles.

## Persistent jobs, reports, and evaluation

Run `alembic upgrade head` from `backend/` when migrating an existing database. The first migration bootstraps a clean database and adds lifecycle, tool execution, audit, and evaluation tables without deleting existing user or assessment data. `alembic downgrade base` is available for rollback in development.

Assessments support synchronous steps through `/api/assessments/{id}/run` and background jobs through `/start`, `/pause`, `/resume`, and `/stop`. Jobs use a bounded in-process executor and persist progress and failure state in SQLite. Audit records are hash chained and can be verified at `/api/assessments/{id}/audit`.

Reports are available as JSON at `/api/assessments/{id}/report` and PDF at `/api/assessments/{id}/report.pdf`. Mock executions are marked as simulated in both formats. Evaluation runs are submitted at `/api/evaluations/run` with explicit ground truth and support configurations A, B, and C plus ablation labels; no benchmark result is generated without supplied observations.

Tool availability and versions are exposed at `/api/tools/health`. Real execution mode is opt-in with `PENTEST_EXECUTION_MODE=real`; this environment has none of Nmap, FFUF, Gobuster, or Nikto installed, so real tool execution was not performed.

## Verification

```bash
cd backend && .venv/bin/python -m pytest -q
python -m alembic upgrade head
cd frontend && npm run build
```

The current suite contains 7 backend tests covering risk scoring, adaptive selection, policy boundaries, adapter validation, audit tamper detection, and evaluation metrics. The frontend build passes. Browser automation was attempted with Chromium and failed because the installed Playwright version does not support Chromium on macOS 12. SafariDriver is present, but the repository browser helper is Chromium-based and no Safari Playwright harness was added.

This prototype is not a production scanner. It does not implement destructive exploitation, credential theft, persistence, denial-of-service testing, distributed workers, WebSocket streaming, or a full multi-role administration surface.
