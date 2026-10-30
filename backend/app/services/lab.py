from __future__ import annotations

from typing import Any

from app.services.evaluation import CONFIGURATIONS
from app.services.orchestrator import AssessmentOrchestrator
from app.services.evaluation import calculate_metrics
from app.services.risk_engine import prioritize_tests


class RiskGuidedPlanner:
    def choose(self, candidates: list[Any], target_url: str) -> dict[str, Any]:
        best = candidates[0]
        return {
            "provider": "risk-guided",
            "tool": best.tool,
            "recommendation": f"Use the risk engine to prioritize {best.tool} because it has the highest score against {target_url}.",
            "threat_score": best.score,
            "score_breakdown": best.contributions,
        }


class DeterministicBaselinePlanner:
    def __init__(self, order: list[str], provider: str = "deterministic-baseline") -> None:
        self.order = order
        self.provider = provider

    def choose(self, candidates: list[Any], target_url: str) -> dict[str, Any]:
        candidate_by_tool = {candidate.tool: candidate for candidate in candidates}
        for tool in self.order:
            if tool in candidate_by_tool:
                chosen = candidate_by_tool[tool]
                return {
                    "provider": self.provider,
                    "tool": chosen.tool,
                    "recommendation": f"Select {chosen.tool} according to the configured baseline order for {target_url}.",
                    "threat_score": chosen.score,
                    "score_breakdown": chosen.contributions,
                }
        fallback = candidates[0]
        return {
            "provider": self.provider,
            "tool": fallback.tool,
            "recommendation": f"Fallback to {fallback.tool} because no ordered baseline entry matched the candidate pool.",
            "threat_score": fallback.score,
            "score_breakdown": fallback.contributions,
        }


class OrderedPlanner:
    def __init__(self, order: list[str]) -> None:
        self.order = order

    def choose(self, candidates: list[Any], target_url: str) -> dict[str, Any]:
        selected = next((candidate for tool in self.order for candidate in candidates if candidate.tool == tool), candidates[0])
        return {"provider": "fixed-sequence", "tool": selected.tool, "recommendation": f"Select {selected.tool} according to the configured experiment order.", "threat_score": selected.score, "score_breakdown": selected.contributions}


def execute_configuration(target_url: str, allowed_tools: str, scope: str, ground_truth: dict[str, Any], configuration: str, mode: str = "mock", budget: int = 4) -> dict[str, Any]:
    """Execute a real bench run for each configuration against the loopback target."""
    import os

    previous_mode = os.environ.get("PENTEST_EXECUTION_MODE")
    os.environ["PENTEST_EXECUTION_MODE"] = mode
    findings: list[dict[str, Any]] = []
    actions: list[str] = []
    selection_trace: list[dict[str, Any]] = []
    if configuration == "A":
        planner = OrderedPlanner(CONFIGURATIONS[configuration]["sequence"])
        strategy = "fixed-sequential"
    elif configuration == "B":
        planner = DeterministicBaselinePlanner(CONFIGURATIONS[configuration]["sequence"], provider="deterministic-baseline")
        strategy = "llm-without-risk"
    else:
        planner = RiskGuidedPlanner()
        strategy = "risk-guided-adaptive"

    orchestrator = AssessmentOrchestrator(planner=planner, selection_strategy=strategy)
    try:
        for step in range(budget):
            completed_tools = {str(item.get("source_tool", "")).lower() for item in findings}
            candidates = prioritize_tests(findings, target_url, completed_tools=completed_tools)
            chosen = planner.choose(candidates, target_url)
            selection_trace.append({
                "step": step + 1,
                "configuration": configuration,
                "strategy": strategy,
                "candidate_order": [item.tool for item in candidates],
                "selected_action": chosen["tool"],
                "selection_reason": chosen["recommendation"],
                "provider": chosen.get("provider", "unknown"),
                "scores": {item.tool: item.score for item in candidates},
            })
            result = orchestrator.run_next_step(target_url, allowed_tools, scope, findings)
            actions.append(result.tool_name)
            findings.append(result.finding)
        observed = {
            "vulnerabilities": [item["title"] for item in findings],
            "candidate_vulnerabilities": [item["title"] for item in findings],
            "confirmed_vulnerabilities": [item["title"] for item in findings if item.get("status") == "confirmed"],
            "attack_paths": [],
            "tool_actions": len(actions),
            "elapsed_seconds": 0.0,
            "selected_actions": actions,
            "risk_rank": actions,
            "selection_trace": selection_trace,
        }
        return {"configuration": configuration, "configuration_name": CONFIGURATIONS[configuration]["name"], "observed": observed, "metrics": calculate_metrics(ground_truth, observed), "mode": mode}
    finally:
        if previous_mode is None:
            os.environ.pop("PENTEST_EXECUTION_MODE", None)
        else:
            os.environ["PENTEST_EXECUTION_MODE"] = previous_mode
