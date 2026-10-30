from __future__ import annotations

import json
import os
from typing import Any

import httpx

from app.services.risk_engine import CandidateTest


class LLMPlanner:
    def __init__(self, provider: str | None = None) -> None:
        self.provider = provider or os.getenv("LLM_PROVIDER", "rule-based")

    def choose(self, candidates: list[CandidateTest], target_url: str) -> dict[str, Any]:
        if self.provider == "openai" and os.getenv("OPENAI_API_KEY"):
            return self._request_openai(candidates, target_url)
        if self.provider == "ollama":
            return self._request_ollama(candidates, target_url)
        return self._rule_based(candidates, target_url)

    def _rule_based(self, candidates: list[CandidateTest], target_url: str) -> dict[str, Any]:
        best = candidates[0]
        return {
            "provider": "rule-based",
            "tool": best.tool,
            "recommendation": f"Prioritize {best.description} because it has the strongest risk score against {target_url}.",
            "threat_score": best.score,
            "score_breakdown": best.contributions,
            "selected_action_id": f"{best.tool}-assessment",
            "requires_human_approval": False,
        }

    def _request_ollama(self, candidates: list[CandidateTest], target_url: str) -> dict[str, Any]:
        payload = {
            "model": os.getenv("OLLAMA_MODEL", "llama3.2"),
            "prompt": f"Choose the next authorized pentest action for {target_url} considering: {json.dumps([c.__dict__ for c in candidates])}",
            "stream": False,
        }
        try:
            response = httpx.post("http://localhost:11434/api/generate", json=payload, timeout=10)
            response.raise_for_status()
            data = response.json()
            return {"provider": "ollama", "tool": candidates[0].tool, "recommendation": data.get("response", "Fallback to rule-based selection."), "threat_score": candidates[0].score}
        except Exception:
            return self._rule_based(candidates, target_url)

    def _request_openai(self, candidates: list[CandidateTest], target_url: str) -> dict[str, Any]:
        try:
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise RuntimeError("No API key")
            url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions")
            system = "You are a risk-guided pentest coordinator. Recommend the next authorized security test with a brief rationale."
            user_prompt = f"Target: {target_url}; candidates: {json.dumps([c.__dict__ for c in candidates])}"
            response = httpx.post(
                url,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user_prompt}],
                    "temperature": 0.2,
                },
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            return {"provider": "openai", "tool": candidates[0].tool, "recommendation": content, "threat_score": candidates[0].score}
        except Exception:
            return self._rule_based(candidates, target_url)
