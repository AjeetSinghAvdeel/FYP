from __future__ import annotations

from typing import Any


class EvidenceValidator:
    @staticmethod
    def evaluate(tool_result: dict[str, Any], target_url: str) -> dict[str, Any]:
        output = str(tool_result.get("output", "")).lower()
        result_status = str(tool_result.get("status", "unknown"))
        if result_status in {"missing", "timeout", "error", "invalid", "blocked"}:
            return {"status": "inconclusive", "finding": tool_result.get("message") or tool_result.get("stderr") or f"Tool execution status: {result_status}.", "confidence": 0}
        observations = tool_result.get("observations") or []
        if observations:
            return {"status": "candidate", "finding": f"Recorded {len(observations)} tool observations for {target_url}; these are not confirmed vulnerabilities.", "confidence": 5}
        if output:
            return {"status": "candidate", "finding": f"Tool output was captured for review on {target_url}; no vulnerability was independently confirmed.", "confidence": 3}
        return {"status": "inconclusive", "finding": f"No parseable evidence was produced for {target_url}.", "confidence": 0}
