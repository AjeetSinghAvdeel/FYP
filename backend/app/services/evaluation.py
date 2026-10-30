from __future__ import annotations

from typing import Any


CONFIGURATIONS = {
    "A": {"name": "fixed-sequential", "sequence": ["nmap", "ffuf", "gobuster", "nikto"]},
    "B": {"name": "llm-without-risk", "sequence": ["nmap", "nikto", "ffuf", "gobuster"]},
    "C": {"name": "risk-guided-adaptive", "sequence": ["nmap", "nikto", "ffuf", "gobuster"]},
}


def calculate_metrics(ground_truth: dict[str, Any], observed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    known_vulnerabilities = set(ground_truth.get("vulnerabilities", []))
    reported_vulnerabilities = set(observed.get("vulnerabilities", []))
    known_paths = set(ground_truth.get("attack_paths", []))
    reported_paths = set(observed.get("attack_paths", []))
    confirmed = set(observed.get("confirmed_vulnerabilities", []))
    candidate_claims = set(observed.get("candidate_vulnerabilities", reported_vulnerabilities))
    actions = int(observed.get("tool_actions", len(observed.get("actions", []))))
    elapsed = float(observed.get("elapsed_seconds", 0.0))
    selected = observed.get("selected_actions", [])
    risk_rank = observed.get("risk_rank", selected)
    aligned = sum(1 for action in selected if action in risk_rank[: max(1, len(selected))]) / max(len(selected), 1)
    return {
        "vulnerability_coverage": {"value": len(reported_vulnerabilities & known_vulnerabilities) / max(len(known_vulnerabilities), 1), "details": {"detected": len(reported_vulnerabilities & known_vulnerabilities), "known": len(known_vulnerabilities)}},
        "attack_path_coverage": {"value": len(reported_paths & known_paths) / max(len(known_paths), 1), "details": {"represented": len(reported_paths & known_paths), "known": len(known_paths)}},
        "false_positive_rate": {"value": len(reported_vulnerabilities - known_vulnerabilities) / max(len(reported_vulnerabilities), 1), "details": {"false_positives": len(reported_vulnerabilities - known_vulnerabilities), "reported": len(reported_vulnerabilities)}},
        "exploit_validation_rate": {"value": len(confirmed & candidate_claims) / max(len(candidate_claims), 1), "details": {"confirmed": len(confirmed & candidate_claims), "claims": len(candidate_claims)}},
        "efficiency": {"value": 1.0 / max(actions + elapsed / 60, 1.0), "details": {"tool_actions": actions, "elapsed_seconds": elapsed}},
        "decision_quality": {"value": aligned, "details": {"selected_actions": selected, "risk_rank": risk_rank}},
    }


def run_ablation(ground_truth: dict[str, Any], observed: dict[str, Any], factors: list[str]) -> dict[str, dict[str, Any]]:
    results = {}
    for factor in factors:
        adjusted = dict(observed)
        adjusted["ablation"] = factor
        results[factor] = calculate_metrics(ground_truth, adjusted)
    return results