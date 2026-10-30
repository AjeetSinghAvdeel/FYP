#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
import random
import re
import statistics
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path('/Volumes/FYP-DEV')
PROJECT = ROOT / 'Projects' / 'FYP'
BACKEND = PROJECT / 'backend'
OUTPUT = ROOT / 'Reports' / 'experiments' / 'real'
OUTPUT.mkdir(parents=True, exist_ok=True)
MASTER_PATH = OUTPUT / 'experiment_master.json'
if MASTER_PATH.exists():
    raise SystemExit(f'Refusing to overwrite existing real experiment outputs: {OUTPUT}')

os.environ['DATABASE_URL'] = f"sqlite:///{OUTPUT / 'experiment_records.sqlite3'}"
os.environ['PENTEST_EXECUTION_MODE'] = 'real'
os.environ['ALLOW_PUBLIC_TARGETS'] = 'false'
for tool in ('nmap', 'ffuf', 'gobuster', 'nikto'):
    os.environ[f'{tool.upper()}_PATH'] = str(ROOT / 'Tools' / 'bin' / tool)
os.environ['PATH'] = str(ROOT / 'Tools' / 'bin') + os.pathsep + os.environ.get('PATH', '')
sys.path.insert(0, str(BACKEND))

import httpx
from sqlalchemy.orm import Session

from app.core.database import Base, SessionLocal, engine
from app.models import Assessment, AuditEvent, Finding, Target, ToolExecution, User
from app.services.assessment_runner import run_step
from app.services.audit import record_event
from app.services.evaluation import CONFIGURATIONS
from app.services.lab import DeterministicBaselinePlanner, OrderedPlanner, RiskGuidedPlanner
from app.services.orchestrator import AssessmentOrchestrator, ADAPTERS

TARGET_URL = 'http://127.0.0.1:3000'
SCOPE = 'allowlisted'
TOOLS = 'nmap,ffuf,gobuster,nikto'
ACTION_BUDGET = 4
REPETITIONS = 5
RANDOM_SEED = 20261030
REFERENCE_PATHS = ['/', '/assets', '/robots.txt', '/api']


def load_backend_env() -> dict[str, str]:
    env_path = BACKEND / '.env'
    values: dict[str, str] = {}
    if env_path.is_file():
        for raw in env_path.read_text(encoding='utf-8').splitlines():
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip().strip('"\'')
    return values


def provider_state() -> dict[str, Any]:
    file_values = load_backend_env()
    provider = os.getenv('LLM_PROVIDER') or file_values.get('LLM_PROVIDER', 'rule-based')
    provider = provider.strip().lower()
    if provider == 'ollama':
        model = os.getenv('OLLAMA_MODEL') or file_values.get('OLLAMA_MODEL', 'llama3.2')
        try:
            response = httpx.get('http://127.0.0.1:11434/api/tags', timeout=3)
            response.raise_for_status()
            models = [item.get('name') for item in response.json().get('models', [])]
            available = any(name and name.split(':')[0] == model.split(':')[0] for name in models)
            return {'provider': provider, 'model': model, 'configured': True, 'connectivity_verified': True, 'model_available': available, 'llm_available': available}
        except Exception as error:
            return {'provider': provider, 'model': model, 'configured': True, 'connectivity_verified': False, 'model_available': False, 'llm_available': False, 'error': str(error)}
    if provider == 'openai':
        api_key = os.getenv('OPENAI_API_KEY') or file_values.get('OPENAI_API_KEY', '')
        model = os.getenv('OPENAI_MODEL') or file_values.get('OPENAI_MODEL', 'gpt-4o-mini')
        return {'provider': provider, 'model': model, 'configured': bool(api_key), 'connectivity_verified': False, 'model_available': None, 'llm_available': False, 'notes': 'Connectivity is not claimed without an executed model request.'}
    return {'provider': provider, 'configured': False, 'connectivity_verified': False, 'model_available': False, 'llm_available': False, 'notes': 'No model provider is configured; B is a deterministic baseline.'}


def capture_reference() -> dict[str, Any]:
    probes = []
    for path in REFERENCE_PATHS:
        started = datetime.now(timezone.utc)
        try:
            response = httpx.get(TARGET_URL + path, timeout=10, follow_redirects=False)
            probes.append({
                'path': path,
                'status_code': response.status_code,
                'response_bytes': len(response.content),
                'elapsed_ms': round(response.elapsed.total_seconds() * 1000, 3),
                'observed_at': started.isoformat(),
                'endpoint_observed': response.status_code != 404,
                'source': 'independent direct HTTP probe performed by experiment runner',
            })
        except httpx.HTTPError as error:
            probes.append({'path': path, 'error': str(error), 'observed_at': started.isoformat(), 'endpoint_observed': False, 'source': 'independent direct HTTP probe performed by experiment runner'})
    return {'target': TARGET_URL, 'probes': probes, 'endpoints': [item['path'] for item in probes if item.get('endpoint_observed')]}


def planner_for(configuration: str) -> tuple[Any, str]:
    if configuration == 'A':
        return OrderedPlanner(CONFIGURATIONS['A']['sequence']), 'fixed-sequential'
    if configuration == 'B':
        # B is intentionally labelled as a deterministic non-risk fallback unless a real provider request is implemented and recorded.
        return DeterministicBaselinePlanner(CONFIGURATIONS['B']['sequence']), 'deterministic-baseline-no-risk'
    return RiskGuidedPlanner(), 'risk-guided-adaptive'


def ensure_records(db: Session) -> tuple[User, Target]:
    user = db.query(User).filter(User.username == 'experiment_operator').first()
    if user is None:
        user = User(username='experiment_operator', email='experiment_operator@localhost.invalid', hashed_password='not-used-by-benchmark', role='security_operator')
        db.add(user)
        db.flush()
    target = db.query(Target).filter(Target.target_url == TARGET_URL, Target.owner_id == user.id).first()
    if target is None:
        target = Target(name='Loopback Juice Shop research target', target_url=TARGET_URL, scope=SCOPE, allowed_tools=TOOLS, owner_id=user.id, description='Authorized loopback-only research lab')
        db.add(target)
        db.flush()
    db.commit()
    return user, target


def extract_paths(observations: list[Any]) -> list[str]:
    paths: set[str] = set()
    for observation in observations:
        if not isinstance(observation, dict) or observation.get('type') not in {'path', 'url'}:
            continue
        for key in ('url', 'value'):
            value = observation.get(key)
            if not isinstance(value, str):
                continue
            if value.startswith(('http://', 'https://')):
                parsed = httpx.URL(value)
                candidate = parsed.path
            else:
                candidate = value.strip().split()[0] if value.strip() else ''
                match = re.match(r'^(/[^\s(]*)', candidate)
                candidate = match.group(1) if match else ''
            if candidate.startswith('/'):
                paths.add(candidate.rstrip('/') or '/')
    return sorted(paths)


def run_one(db: Session, user: User, target: Target, configuration: str, repetition: int, order_number: int, strategy_planner: Any, strategy_name: str) -> dict[str, Any]:
    assessment = Assessment(
        name=f'Empirical {configuration} repetition {repetition} {uuid.uuid4().hex[:8]}',
        status='initialized',
        budget=ACTION_BUDGET,
        target_id=target.id,
        owner_id=user.id,
        summary='Loopback-only empirical experiment; fresh assessment state.',
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    record_event(db, 'experiment_run_created', user_id=user.id, assessment_id=assessment.id, outcome=f'configuration={configuration}; repetition={repetition}', current_state={'configuration': configuration, 'strategy': strategy_name, 'budget': ACTION_BUDGET, 'execution_order': order_number})
    db.commit()
    orchestrator = AssessmentOrchestrator(planner=strategy_planner, selection_strategy=strategy_name)
    for _ in range(ACTION_BUDGET):
        db.expire(assessment, ['findings', 'tool_executions'])
        run_step(db, assessment, user.id, orchestrator=orchestrator)
        db.refresh(assessment)
    db.expire(assessment, ['findings', 'tool_executions'])
    try:
        run_step(db, assessment, user.id, orchestrator=orchestrator)
    except RuntimeError as error:
        if 'budget exhausted' not in str(error).lower():
            raise
    db.refresh(assessment)
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment.id).order_by(ToolExecution.id).all()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment.id).order_by(Finding.id).all()
    audit_events = db.query(AuditEvent).filter(AuditEvent.assessment_id == assessment.id, AuditEvent.event_type == 'tool_execution').order_by(AuditEvent.id).all()
    audit_by_execution = {str((event.current_state or {}).get('execution_id')): event for event in audit_events}
    records = []
    for execution in executions:
        event = audit_by_execution.get(str(execution.id))
        state = (event.current_state or {}) if event else {}
        records.append({
            'assessment_id': assessment.id,
            'execution_id': execution.id,
            'audit_event_id': event.id if event else None,
            'finding_ids': [finding.id for finding in findings if finding.source_tool == execution.tool],
            'tool': execution.tool,
            'tool_version': state.get('tool_version'),
            'command_args': state.get('command_args'),
            'target': execution.target,
            'status': execution.status,
            'mode': execution.mode,
            'started_at': state.get('started_at') or (execution.started_at.isoformat() if execution.started_at else None),
            'finished_at': state.get('finished_at') or (execution.finished_at.isoformat() if execution.finished_at else None),
            'duration_ms': execution.duration_ms,
            'return_code': execution.return_code,
            'request_budget': execution.request_budget,
            'requests_made': execution.requests_made,
            'observations': execution.observations or [],
            'output': execution.output,
            'stderr': execution.stderr,
            'selection': state.get('selection'),
            'assessment_budget': assessment.budget,
        })
    run_findings = [{
        'finding_id': finding.id,
        'title': finding.title,
        'source_tool': finding.source_tool,
        'status': finding.status,
        'severity': finding.severity,
        'confidence': finding.confidence,
        'evidence': finding.evidence,
        'observations': finding.observations or [],
        'simulated': finding.simulated,
    } for finding in findings]
    all_observations = [observation for record in records for observation in record['observations']]
    endpoints = sorted({path for path in extract_paths(all_observations)})
    services = sorted({
        f"{item.get('name')}:{item.get('port')}"
        for item in all_observations
        if isinstance(item, dict) and item.get('type') == 'service' and item.get('name')
    })
    durations = [record['duration_ms'] for record in records if isinstance(record.get('duration_ms'), (int, float))]
    return {
        'assessment_id': assessment.id,
        'assessment_status': assessment.status,
        'configuration': configuration,
        'configuration_name': CONFIGURATIONS[configuration]['name'],
        'strategy': strategy_name,
        'repetition': repetition,
        'execution_order': order_number,
        'assessment_budget': assessment.budget,
        'tool_actions': len(records),
        'selected_actions': [record['tool'] for record in records],
        'selection_trace': [record.get('selection') for record in records],
        'execution_records': records,
        'findings': run_findings,
        'discovered_endpoints': endpoints,
        'discovered_services': services,
        'total_measured_duration_ms': sum(durations) if len(durations) == len(records) else None,
        'measured_action_durations_ms': durations,
    }


def numeric_summary(values: list[float]) -> dict[str, Any]:
    clean = [float(value) for value in values if isinstance(value, (int, float))]
    if not clean:
        return {'n': 0, 'mean': None, 'median': None, 'standard_deviation': None, 'minimum': None, 'maximum': None}
    return {
        'n': len(clean),
        'mean': round(statistics.mean(clean), 6),
        'median': round(statistics.median(clean), 6),
        'standard_deviation': round(statistics.stdev(clean), 6) if len(clean) >= 2 else None,
        'minimum': round(min(clean), 6),
        'maximum': round(max(clean), 6),
    }


def metric_summary(runs: list[dict[str, Any]], reference: dict[str, Any]) -> dict[str, Any]:
    expected = set(reference['endpoints'])
    endpoint_coverages = []
    for run in runs:
        found = set(run['discovered_endpoints'])
        endpoint_coverages.append(len(found & expected) / len(expected) if expected else None)
    return {
        'validated_vulnerability_coverage': {
            'value': None,
            'availability': 'unavailable: independently verified confirmed-vulnerability ground truth is empty',
            'numerator': None,
            'denominator': None,
            'formula': 'confirmed vulnerabilities detected / independently verified confirmed vulnerabilities',
        },
        'endpoint_coverage': {
            **numeric_summary([value for value in endpoint_coverages if value is not None]),
            'availability': 'measured per run against endpoints verified by independent direct HTTP probes',
            'numerator_denominator_per_run': 'intersection(discovered endpoints, responsive reference endpoints) / responsive reference endpoints',
            'reference_endpoints': sorted(expected),
        },
        'false_positive_rate': {
            'value': None,
            'availability': 'unavailable: candidates have not been independently labeled as true/false vulnerabilities',
            'numerator': None,
            'denominator': None,
            'formula': 'false positive candidates / all independently adjudicated candidates',
        },
        'execution_time_seconds': {
            **numeric_summary([run['total_measured_duration_ms'] / 1000 for run in runs if run['total_measured_duration_ms'] is not None]),
            'availability': 'measured tool durations from persisted ToolExecution records; run excluded if any action duration is absent',
            'formula': 'sum(actual measured tool duration_ms per run) / 1000',
        },
        'tool_action_count': {
            **numeric_summary([run['tool_actions'] for run in runs]),
            'availability': 'measured from persisted ToolExecution rows',
            'formula': 'count(ToolExecution rows per Assessment)',
        },
        'request_count': {
            'availability': 'partial; only adapter-reported actual counts are included; null means unavailable, never inferred from request budget',
            'per_run': [
                {'assessment_id': run['assessment_id'], 'requests_made': [item['requests_made'] for item in run['execution_records']]}
                for run in runs
            ],
        },
        'risk_prioritisation': {
            'availability': 'audit trace records candidate scores and actual selected action for each step',
            'selected_actions': [run['selected_actions'] for run in runs],
        },
        'evidence_completeness': {
            'per_run': [
                {
                    'assessment_id': run['assessment_id'],
                    'execution_records': len(run['execution_records']),
                    'records_with_timestamp_duration_and_output': sum(bool(item.get('started_at') and item.get('finished_at') and item.get('duration_ms') is not None and item.get('output') is not None) for item in run['execution_records']),
                }
                for run in runs
            ],
            'formula': 'complete execution records / all execution records; completeness does not imply vulnerability confirmation',
        },
        'replanning_frequency': {
            'value_per_run': [max(run['tool_actions'] - 1, 0) for run in runs],
            'formula': 'number of action selections after the initial selection per assessment',
        },
    }


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')


Base.metadata.create_all(bind=engine)
reference = capture_reference()
provider = provider_state()
tool_versions = {name: adapter.check_version() for name, adapter in ADAPTERS.items()}
randomizer = random.Random(RANDOM_SEED)
scheduled = [(configuration, repetition) for repetition in range(1, REPETITIONS + 1) for configuration in ('A', 'B', 'C')]
randomizer.shuffle(scheduled)

all_runs: list[dict[str, Any]] = []
with SessionLocal() as db:
    user, target = ensure_records(db)
    for order_number, (configuration, repetition) in enumerate(scheduled, start=1):
        planner, strategy = planner_for(configuration)
        run = run_one(db, user, target, configuration, repetition, order_number, planner, strategy)
        all_runs.append(run)
        # Flush each completed run to a checkpoint so interruption does not erase the evidence already collected.
        checkpoint = OUTPUT / f'checkpoint_assessment_{run["assessment_id"]}.json'
        write_json(checkpoint, run)

by_configuration: dict[str, list[dict[str, Any]]] = defaultdict(list)
for run in all_runs:
    by_configuration[run['configuration']].append(run)

configuration_payloads = {}
comparison = {}
for configuration in ('A', 'B', 'C'):
    runs = sorted(by_configuration[configuration], key=lambda item: item['repetition'])
    configuration_payloads[configuration] = {
        'configuration': configuration,
        'configuration_name': CONFIGURATIONS[configuration]['name'],
        'run_count': len(runs),
        'runs': runs,
        'metrics': metric_summary(runs, reference),
    }
    comparison[configuration] = {
        'run_count': len(runs),
        'assessment_ids': [run['assessment_id'] for run in runs],
        'metrics': configuration_payloads[configuration]['metrics'],
    }

confirmed_vulnerabilities = []
findings_by_title: dict[str, list[dict[str, Any]]] = defaultdict(list)
for run in all_runs:
    for finding in run['findings']:
        findings_by_title[finding['title']].append(finding)
        if finding['status'] == 'confirmed':
            confirmed_vulnerabilities.append(finding)
ground_truth = {
    'target': TARGET_URL,
    'scope': SCOPE,
    'independent_http_reference': reference,
    'confirmed_vulnerabilities': [],
    'potential_vulnerabilities': sorted(findings_by_title),
    'informational_observations': [
        'HTTP 500 responses and stack traces, if observed, are recorded as evidence and are not automatically treated as exploitable vulnerabilities.',
        'Missing HTTP security headers are informational hardening observations, not confirmed vulnerabilities.',
        'Discovered endpoints and services are coverage observations, not vulnerabilities.',
    ],
    'false_positive_candidates': [],
    'unverified_candidates': sorted(findings_by_title),
    'adjudication_note': 'No confirmed vulnerability ground truth is asserted. Scanner findings remain candidates unless independently validated.',
}

experiment_id = f"loopback-real-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
master = {
    'experiment_id': experiment_id,
    'status': 'genuine execution records; empirical metrics limited to measured quantities',
    'target': TARGET_URL,
    'scope': SCOPE,
    'project_root': str(PROJECT),
    'python_executable': sys.executable,
    'database': str(OUTPUT / 'experiment_records.sqlite3'),
    'random_seed': RANDOM_SEED,
    'randomized_execution_order': [{'configuration': config, 'repetition': rep} for config, rep in scheduled],
    'action_budget': ACTION_BUDGET,
    'timeout_seconds': 35,
    'tool_versions': tool_versions,
    'llm_provider_verification': provider,
    'configurations': {key: {'name': CONFIGURATIONS[key]['name'], 'strategy': planner_for(key)[1], 'run_count': len(by_configuration[key])} for key in ('A', 'B', 'C')},
    'comparison': comparison,
    'all_assessment_ids': [run['assessment_id'] for run in all_runs],
    'source_of_truth': 'experiment_records.sqlite3 Assessment, ToolExecution, Finding, and AuditEvent records; JSON outputs preserve the source rows and IDs',
}

write_json(MASTER_PATH, master)
write_json(OUTPUT / 'ground_truth.json', ground_truth)
write_json(OUTPUT / 'comparison_summary.json', {'experiment_id': experiment_id, 'configurations': comparison, 'statistics_note': 'Descriptive statistics only. No significance tests are reported.'})
for configuration in ('A', 'B', 'C'):
    write_json(OUTPUT / f'configuration_{configuration}_results.json', configuration_payloads[configuration])

csv_path = OUTPUT / 'experiment_results.csv'
with csv_path.open('w', newline='', encoding='utf-8') as file_handle:
    fieldnames = ['configuration', 'repetition', 'execution_order', 'assessment_id', 'assessment_status', 'tool_actions', 'selected_actions', 'discovered_endpoints', 'discovered_services', 'total_measured_duration_ms']
    writer = csv.DictWriter(file_handle, fieldnames=fieldnames)
    writer.writeheader()
    for run in all_runs:
        writer.writerow({
            'configuration': run['configuration'],
            'repetition': run['repetition'],
            'execution_order': run['execution_order'],
            'assessment_id': run['assessment_id'],
            'assessment_status': run['assessment_status'],
            'tool_actions': run['tool_actions'],
            'selected_actions': '|'.join(run['selected_actions']),
            'discovered_endpoints': '|'.join(run['discovered_endpoints']),
            'discovered_services': '|'.join(run['discovered_services']),
            'total_measured_duration_ms': run['total_measured_duration_ms'],
        })

charts = OUTPUT / 'comparison_charts'
charts.mkdir(exist_ok=True)
for metric, title in [('execution_time_seconds', 'Measured execution time (seconds)'), ('tool_action_count', 'Actual tool actions')]:
    values = {}
    for configuration in ('A', 'B', 'C'):
        values[configuration] = configuration_payloads[configuration]['metrics'][metric].get('mean')
    available = {key: value for key, value in values.items() if isinstance(value, (int, float))}
    if not available:
        continue
    top = max(max(available.values()), 0.01)
    colors = {'A': '#527da8', 'B': '#ca9b3d', 'C': '#388c70'}
    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="480" height="220" viewBox="0 0 480 220">', '<rect width="100%" height="100%" fill="#f5f6f7"/>', f'<text x="240" y="22" text-anchor="middle" fill="#202833" font-size="14">{title}</text>']
    for index, configuration in enumerate(('A', 'B', 'C')):
        value = values.get(configuration)
        if value is None:
            continue
        height = 120 * value / top
        x = 95 + index * 120
        y = 165 - height
        svg.extend([f'<rect x="{x}" y="{y:.2f}" width="60" height="{height:.2f}" fill="{colors[configuration]}"/>', f'<text x="{x + 30}" y="185" text-anchor="middle" fill="#202833" font-size="12">{configuration}</text>', f'<text x="{x + 30}" y="{y - 7:.2f}" text-anchor="middle" fill="#202833" font-size="11">{value:.3f}</text>'])
    svg.append('</svg>')
    (charts / f'{metric}.svg').write_text('\n'.join(svg), encoding='utf-8')

(OUTPUT / 'experiment_methodology.md').write_text(
    '# Experiment methodology\n\n'
    'The benchmark invokes the project assessment runner against the authorized loopback target at http://127.0.0.1:3000. Each repetition creates a new database-backed Assessment with an empty finding state and a four-action budget. Each ToolExecution, Finding, and selection/audit trace is persisted to the isolated experiment database under this directory.\n\n'
    'The three configurations share the same target, scope, installed scanner suite, adapter options, wordlist configuration, timeout, budget, and stopping rule. Configuration order is shuffled using the recorded seed. A uses a fixed sequential order; B uses a deterministic no-risk baseline because no live model provider is verified; C selects by the project risk engine and records candidate scores and the chosen action after every observation.\n\n'
    'Execution duration and scanner output are copied from persisted records. Request counts are included only when the adapter reports an actual count. Missing measurements remain null. Ground-truth endpoint references are collected by independent direct HTTP probes. No vulnerability coverage or false-positive score is reported without independently adjudicated vulnerability ground truth.\n',
    encoding='utf-8',
)
(OUTPUT / 'limitations.md').write_text(
    '# Limitations\n\n'
    f"- Provider status: {json.dumps(provider, ensure_ascii=False)}\n"
    '- Configuration B is not an LLM result unless a real model request is implemented and recorded; current B is explicitly a deterministic baseline.\n'
    '- The local project validator classifies tool observations as candidates; it does not independently confirm exploitability. Confirmed vulnerability coverage and false-positive rate are therefore unavailable.\n'
    '- Request counts are unavailable for tools whose output does not report actual counts. Configured request budgets are not substituted.\n'
    '- The results describe one loopback Juice Shop deployment and do not establish generalization to other applications.\n'
    '- Descriptive statistics are reported; no significance tests are run from five repetitions.\n',
    encoding='utf-8',
)
(OUTPUT / 'validation_report.md').write_text(
    '# Validation report\n\n'
    f"- Experiment database: `{OUTPUT / 'experiment_records.sqlite3'}`\n"
    f"- Actual assessment IDs: {', '.join(str(run['assessment_id']) for run in all_runs)}\n"
    f"- Persisted executions: {sum(len(run['execution_records']) for run in all_runs)}\n"
    f"- Run counts: {json.dumps({key: len(by_configuration[key]) for key in ('A', 'B', 'C')})}\n"
    f"- Target HTTP reference probes: {json.dumps(reference['probes'], ensure_ascii=False)}\n"
    '- Each JSON run references database assessment IDs, execution IDs, finding IDs, audit event IDs, actual output, status, timestamps, measured durations, and action-selection trace.\n'
    '- Synthetic historical outputs remain under the separate `final/` directory, marked `SYNTHETIC — NOT VALID EXPERIMENTAL RESULTS`, and are not read by this runner.\n',
    encoding='utf-8',
)

# Remove per-assessment checkpoints only after all durable aggregate outputs exist; retain them for traceability.
print(json.dumps({'experiment_id': experiment_id, 'assessments': master['all_assessment_ids'], 'executions': sum(len(run['execution_records']) for run in all_runs), 'output': str(OUTPUT)}, indent=2))
