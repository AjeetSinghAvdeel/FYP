#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import sqlite3
import statistics
from pathlib import Path
from typing import Any

OUTPUT = Path('/Volumes/FYP-DEV/Reports/experiments/real')


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8'))


def save_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')


def summarize(values: list[float]) -> dict[str, Any]:
    if not values:
        return {'n': 0, 'mean': None, 'median': None, 'standard_deviation': None, 'minimum': None, 'maximum': None}
    return {
        'n': len(values),
        'mean': round(statistics.mean(values), 6),
        'median': round(statistics.median(values), 6),
        'standard_deviation': round(statistics.stdev(values), 6) if len(values) > 1 else None,
        'minimum': round(min(values), 6),
        'maximum': round(max(values), 6),
    }


master_path = OUTPUT / 'experiment_master.json'
master = load_json(master_path)
summary_path = OUTPUT / 'comparison_summary.json'
summary = load_json(summary_path)
all_runs: list[dict[str, Any]] = []
for configuration in 'ABC':
    path = OUTPUT / f'configuration_{configuration}_results.json'
    payload = load_json(path)
    runs = payload['runs']
    efficiencies = []
    efficiency_details = []
    for run in runs:
        endpoint_count = len(set(run.get('discovered_endpoints', [])))
        action_count = run.get('tool_actions', 0)
        value = endpoint_count / action_count if action_count else None
        if value is not None:
            efficiencies.append(value)
        efficiency_details.append({
            'assessment_id': run['assessment_id'],
            'numerator_unique_discovered_endpoints': endpoint_count,
            'denominator_tool_actions': action_count,
            'value': round(value, 6) if value is not None else None,
        })
    metrics = payload['metrics']
    metrics['service_coverage'] = {
        'value': None,
        'availability': 'unavailable: no independently verified service inventory was established before tool execution',
        'numerator': None,
        'denominator': None,
        'formula': 'independently verified services detected / independently verified services in ground truth',
    }
    metrics['action_efficiency'] = {
        **summarize(efficiencies),
        'availability': 'measured from actual execution records and parsed observations',
        'formula': 'unique discovered endpoints / actual tool actions per assessment',
        'per_run': efficiency_details,
    }
    payload['metrics'] = metrics
    save_json(path, payload)
    summary['configurations'][configuration]['metrics'] = metrics
    all_runs.extend(runs)

save_json(summary_path, summary)

csv_path = OUTPUT / 'experiment_results.csv'
with csv_path.open('r', newline='', encoding='utf-8') as input_file:
    rows = list(csv.DictReader(input_file))
for row in rows:
    configuration = row['configuration']
    run = next(run for run in all_runs if run['configuration'] == configuration and str(run['repetition']) == row['repetition'])
    row['execution_ids'] = '|'.join(str(item['execution_id']) for item in run['execution_records'])
    row['audit_event_ids'] = '|'.join(str(item['audit_event_id']) for item in run['execution_records'])
    row['action_efficiency'] = f"{len(set(run['discovered_endpoints'])) / run['tool_actions']:.6f}" if run['tool_actions'] else ''
    row['service_coverage'] = 'unavailable'
fieldnames = list(rows[0].keys()) if rows else []
with csv_path.open('w', newline='', encoding='utf-8') as output_file:
    writer = csv.DictWriter(output_file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

included_assessment_ids = set(master.get('all_assessment_ids', []))
with sqlite3.connect(OUTPUT / 'experiment_records.sqlite3') as connection:
    rows = connection.execute(
        'SELECT a.id, a.status, a.last_error, COUNT(te.id) '
        'FROM assessments a LEFT JOIN tool_executions te ON te.assessment_id = a.id '
        'GROUP BY a.id ORDER BY a.id'
    ).fetchall()
excluded = [
    {'assessment_id': row[0], 'status': row[1], 'execution_count': row[3], 'exclusion_reason': 'assessment has no persisted tool executions and is not included in the empirical run set'}
    for row in rows if row[0] not in included_assessment_ids
]
master['excluded_database_assessments'] = excluded
save_json(master_path, master)

validation_path = OUTPUT / 'validation_report.md'
validation = validation_path.read_text(encoding='utf-8')
validation = validation.split('\n## Reporting integrity follow-up\n', 1)[0]
validation += '\n\n## Reporting integrity follow-up\n\n'
validation += '- `experiment_results.csv` now contains actual assessment, execution, and audit event IDs for each run.\n'
validation += '- Service coverage is explicitly unavailable because no independent service inventory was established.\n'
validation += '- Action efficiency is calculated per assessment as unique discovered endpoints divided by persisted tool actions; numerator and denominator are included.\n'
validation += f'- Database assessments excluded from the empirical dataset because they have no persisted tool executions: `{json.dumps(excluded)}`.\n'
validation += '- Assessment IDs are scoped to the isolated `experiment_records.sqlite3`; the application database and its historical assessment 7 were not modified.\n'
validation_path.write_text(validation, encoding='utf-8')

limitations_path = OUTPUT / 'limitations.md'
limitations = limitations_path.read_text(encoding='utf-8')
if 'Service coverage is unavailable' not in limitations:
    limitations += '\n- Service coverage is unavailable because the experiment did not establish an independent reference inventory of services.\n'
limitations_path.write_text(limitations, encoding='utf-8')

chart_dir = OUTPUT / 'comparison_charts'
chart_dir.mkdir(exist_ok=True)
efficiency_values = {key: summary['configurations'][key]['metrics']['action_efficiency']['mean'] for key in 'ABC'}
if all(isinstance(value, (int, float)) for value in efficiency_values.values()):
    maximum = max(max(efficiency_values.values()), 0.01)
    colors = {'A': '#527da8', 'B': '#ca9b3d', 'C': '#388c70'}
    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="480" height="220" viewBox="0 0 480 220">', '<rect width="100%" height="100%" fill="#f5f6f7"/>', '<text x="240" y="22" text-anchor="middle" fill="#202833" font-size="14">Unique endpoints per tool action</text>']
    for index, key in enumerate('ABC'):
        value = efficiency_values[key]
        height = 120 * value / maximum
        x = 95 + index * 120
        y = 165 - height
        svg.extend([f'<rect x="{x}" y="{y:.2f}" width="60" height="{height:.2f}" fill="{colors[key]}"/>', f'<text x="{x + 30}" y="185" text-anchor="middle" fill="#202833" font-size="12">{key}</text>', f'<text x="{x + 30}" y="{y - 7:.2f}" text-anchor="middle" fill="#202833" font-size="11">{value:.3f}</text>'])
    svg.append('</svg>')
    (chart_dir / 'action_efficiency.svg').write_text('\n'.join(svg), encoding='utf-8')

print(json.dumps({'csv_fields': fieldnames, 'excluded_database_assessments': excluded, 'action_efficiency': {key: summary['configurations'][key]['metrics']['action_efficiency'] for key in 'ABC'}}, indent=2))
