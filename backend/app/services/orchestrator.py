from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Callable

from app.services.attack_graph import AttackGraphEngine
from app.services.llm_agent import LLMPlanner
from app.services.policy import PolicyEngine
from app.services.risk_engine import prioritize_tests
from app.services.tool_adapters import FFUFAdapter, GobusterAdapter, NiktoAdapter, NmapAdapter
from app.services.validation import EvidenceValidator

ADAPTERS = {
    "nmap": NmapAdapter(),
    "ffuf": FFUFAdapter(),
    "gobuster": GobusterAdapter(),
    "nikto": NiktoAdapter(),
}


@dataclass
class ExecutionResult:
    tool_name: str
    decision: dict[str, Any]
    evidence: dict[str, Any]
    finding: dict[str, Any]
    graph: dict[str, Any]


class AssessmentOrchestrator:
    def __init__(self, planner: Any | None = None, selection_strategy: str = "risk-guided", on_action_selected: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.planner = planner or LLMPlanner()
        self.selection_strategy = (selection_strategy or "risk-guided").lower()
        self.on_action_selected = on_action_selected

    def _candidate_order(self, candidates: list[Any], strategy: str) -> list[Any]:
        fixed_sequences = {
            "fixed-sequential": ["nmap", "ffuf", "gobuster", "nikto"],
            "llm-without-risk": ["nmap", "nikto", "ffuf", "gobuster"],
            "risk-guided-adaptive": None,
        }
        preferred = fixed_sequences.get(strategy)
        if not preferred:
            return candidates
        order_map = {tool: index for index, tool in enumerate(preferred)}
        return sorted(candidates, key=lambda item: (order_map.get(getattr(item, "tool", ""), len(preferred)), -float(getattr(item, "score", 0.0))))

    def _candidate_pool(self, findings: list[dict[str, Any]], target_url: str, completed_tools: set[str]) -> list[Any]:
        ranked = prioritize_tests(findings, target_url, completed_tools=completed_tools)
        return self._candidate_order(ranked, self.selection_strategy)

    def run_next_step(
        self,
        target_url: str,
        allowed_tools: str,
        target_scope: str,
        findings: list[dict[str, Any]],
    ) -> ExecutionResult:
        completed_tools = {str(item.get("source_tool", "")).lower() for item in findings}
        candidates = self._candidate_pool(findings, target_url, completed_tools)
        if not candidates:
            raise RuntimeError("No eligible actions remain for this target and evidence state.")
        recommendation = self.planner.choose(candidates, target_url)
        target_allowed, target_reason = PolicyEngine.target_is_allowed(target_url)
        if not target_allowed:
            return self._blocked_result(target_url, recommendation, target_reason, findings)
        decision = PolicyEngine.check_tool(target_scope, allowed_tools, recommendation["tool"])
        if not decision.allowed:
            return self._blocked_result(target_url, recommendation, decision.reason, findings)
        if self.on_action_selected:
            self.on_action_selected({
                "strategy": self.selection_strategy,
                "selected_action": recommendation["tool"],
                "selection_reason": recommendation.get("recommendation", ""),
                "provider": recommendation.get("provider", "unknown"),
                "risk_score": recommendation.get("threat_score"),
                "risk_breakdown": recommendation.get("score_breakdown", {}),
                "candidate_order": [candidate.tool for candidate in candidates],
                "candidate_scores": {candidate.tool: candidate.score for candidate in candidates},
            })
        adapter = ADAPTERS.get(recommendation["tool"], NmapAdapter())
        tool_started_at = datetime.now(timezone.utc)
        tool_started_clock = perf_counter()
        runner = adapter.execute(target_url, timeout=35)
        tool_finished_at = datetime.now(timezone.utc)
        runner.setdefault("started_at", tool_started_at.isoformat())
        runner.setdefault("finished_at", tool_finished_at.isoformat())
        runner.setdefault("duration_ms", int((perf_counter() - tool_started_clock) * 1000))
        runner.setdefault("command_args", adapter.build_command(target_url, []))
        runner.setdefault("tool_version", adapter.check_version())
        validated = EvidenceValidator.evaluate(runner, target_url)
        observations = runner.get("observations", [])
        title = {
            "nmap": "Service discovery evidence",
            "ffuf": "Web path discovery evidence",
            "gobuster": "Directory discovery evidence",
            "nikto": "Web server check evidence",
        }.get(recommendation["tool"], f"{recommendation['tool'].upper()} evidence")
        finding = {
            "source_tool": recommendation["tool"],
            "title": title,
            "severity": "low",
            "confidence": validated["confidence"],
            "asset": target_url,
            "vector": recommendation["recommendation"],
            "evidence": runner.get("output") or runner.get("message") or validated["finding"],
            "status": validated["status"],
            "score": recommendation.get("threat_score", 0.0),
            "score_breakdown": recommendation.get("score_breakdown", {}),
            "observations": observations,
        }
        graph = AttackGraphEngine.build_snapshot([*findings, finding])
        return ExecutionResult(
            tool_name=recommendation["tool"],
            decision={
                "allowed": decision.allowed,
                "reason": decision.reason,
                "strategy": self.selection_strategy,
                "selected_action": recommendation["tool"],
                "selection_reason": recommendation.get("recommendation", ""),
                "provider": recommendation.get("provider", "unknown"),
                "risk_score": recommendation.get("threat_score"),
                "risk_breakdown": recommendation.get("score_breakdown", {}),
                "candidate_order": [candidate.tool for candidate in candidates],
                "candidate_scores": {candidate.tool: candidate.score for candidate in candidates},
            },
            evidence=runner,
            finding=finding,
            graph=graph,
        )

    @staticmethod
    def _blocked_result(target_url: str, recommendation: dict[str, Any], reason: str, findings: list[dict[str, Any]]) -> ExecutionResult:
        tool = recommendation["tool"]
        return ExecutionResult(
            tool_name=tool,
            decision={"allowed": False, "reason": reason},
            evidence={"status": "blocked", "tool": tool, "target": target_url, "output": "", "stderr": reason},
            finding={
                "source_tool": tool,
                "title": "Policy blocked candidate action",
                "severity": "low",
                "confidence": 0,
                "asset": target_url,
                "vector": recommendation["recommendation"],
                "evidence": reason,
                "status": "inconclusive",
                "score": recommendation.get("threat_score", 0.0),
                "score_breakdown": recommendation.get("score_breakdown", {}),
            },
            graph=AttackGraphEngine.build_snapshot(findings),
        )
