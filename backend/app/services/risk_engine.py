from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class CandidateTest:
    tool: str
    description: str
    score: float
    reasons: list[str]
    factors: dict[str, float] = field(default_factory=dict)
    contributions: dict[str, float] = field(default_factory=dict)


DEFAULT_WEIGHTS = {
    "severity": 0.25,
    "exploitability": 0.20,
    "asset_criticality": 0.20,
    "privilege_gain": 0.15,
    "impact": 0.15,
    "information_gain": 0.10,
    "execution_cost": 0.05,
    "uncertainty": 0.10,
}


SEVERITY_WEIGHTS = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
}


def infer_severity_score(findings: Iterable[dict]) -> float:
    total = 0.0
    count = 0
    for finding in findings:
        severity = str(finding.get("severity", "low")).lower()
        total += SEVERITY_WEIGHTS.get(severity, 2)
        count += 1
    return total / max(count, 1)


def calculate_priority(factors: dict[str, float], weights: dict[str, float] | None = None) -> tuple[float, dict[str, float]]:
    """Calculate P(a) = weighted benefit - weighted penalty in a deterministic way."""
    active_weights = {**DEFAULT_WEIGHTS, **(weights or {})}
    normalized = {name: max(0.0, min(1.0, float(factors.get(name, 0.0)))) for name in DEFAULT_WEIGHTS}
    contributions = {
        name: round(normalized[name] * active_weights[name] * 100, 2)
        for name in DEFAULT_WEIGHTS
    }
    score = sum(contributions[name] for name in ("severity", "exploitability", "asset_criticality", "privilege_gain", "impact", "information_gain"))
    score -= sum(contributions[name] for name in ("execution_cost", "uncertainty"))
    return round(score, 2), contributions


def prioritize_tests(
    findings: list[dict],
    target_url: str,
    weights: dict[str, float] | None = None,
    completed_tools: set[str] | None = None,
) -> list[CandidateTest]:
    severity = min(infer_severity_score(findings) / 5, 1.0)
    web_target = target_url.lower().startswith(("http://", "https://"))
    has_observation_context = any("source_tool" in finding or "evidence" in finding for finding in findings)
    has_web_evidence = web_target and bool(findings) and (not has_observation_context or any(
        str(finding.get("source_tool", "")).lower() == "nmap"
        or "http" in str(finding.get("evidence", "")).lower()
        for finding in findings
    ))
    completed = {tool.lower() for tool in (completed_tools or set())}
    profiles = [
        ("nmap", "Map service surfaces and identify exposed ports and protocols.", {"severity": severity, "exploitability": 0.35, "asset_criticality": 0.7, "privilege_gain": 0.2, "impact": 0.45, "information_gain": 0.9, "execution_cost": 0.25, "uncertainty": 0.15}, ["network footprint", "service discovery"]),
        ("ffuf", "Enumerate accessible paths and hidden application content.", {"severity": severity, "exploitability": 0.5, "asset_criticality": 0.7, "privilege_gain": 0.35, "impact": 0.55, "information_gain": 0.8, "execution_cost": 0.55, "uncertainty": 0.25}, ["discovery", "application enumeration"]),
        ("gobuster", "Probe directories, resources, and web endpoints for exposed assets.", {"severity": severity, "exploitability": 0.45, "asset_criticality": 0.65, "privilege_gain": 0.3, "impact": 0.5, "information_gain": 0.75, "execution_cost": 0.5, "uncertainty": 0.3}, ["directory discovery", "resource enumeration"]),
        ("nikto", "Run focused web-server vulnerability checks on identified hosts.", {"severity": severity, "exploitability": 0.7, "asset_criticality": 0.75, "privilege_gain": 0.45, "impact": 0.7, "information_gain": 0.65, "execution_cost": 0.65, "uncertainty": 0.2}, ["web hardening", "vulnerabilities"]),
    ]
    candidates: list[CandidateTest] = []
    for tool, description, factors, reasons in profiles:
        if tool in completed or (not has_web_evidence and tool in {"ffuf", "gobuster", "nikto"}):
            continue
        score, contributions = calculate_priority(factors, weights)
        candidates.append(CandidateTest(tool, description, score, reasons, factors, contributions))
    return sorted(candidates, key=lambda item: item.score, reverse=True)
