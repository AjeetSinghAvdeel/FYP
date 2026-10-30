from __future__ import annotations

import hashlib
from typing import Any


class AttackGraphEngine:
    @staticmethod
    def build_snapshot(findings: list[dict[str, Any]]) -> dict[str, Any]:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        targets: dict[str, str] = {}

        def stable_id(prefix: str, value: str) -> str:
            digest = hashlib.sha1(value.encode("utf-8", errors="replace")).hexdigest()[:12]
            return f"{prefix}-{digest}"

        for finding_index, finding in enumerate(findings):
            asset = str(finding.get("asset", "unknown target"))
            target_id = targets.get(asset)
            if target_id is None:
                target_id = stable_id("target", asset)
                targets[asset] = target_id
                nodes.append({"id": target_id, "position": {"x": 0, "y": len(targets) * 120}, "type": "input", "data": {"label": asset, "kind": "target", "validation_status": "authorized scope"}})

            for observation_index, observation in enumerate(finding.get("observations", [])):
                kind = str(observation.get("type", "observation"))
                if kind == "service":
                    label = f"{observation.get('port')}/{observation.get('protocol')} {observation.get('name') or 'service'}"
                    if observation.get("product"):
                        label += f" {observation['product']}"
                    if observation.get("version"):
                        label += f" {observation['version']}"
                    status = observation.get("state", "observed")
                elif kind == "path":
                    label = str(observation.get("url") or observation.get("value") or "discovered path")
                    status = "candidate path"
                elif kind == "potential_server_issue":
                    label = str(observation.get("value") or "server observation")
                    status = "candidate evidence"
                elif kind == "wildcard_preflight":
                    label = f"Wildcard baseline: HTTP {observation.get('status_code')} / {observation.get('wildcard_length')} bytes"
                    status = "preflight evidence"
                else:
                    label = str(observation.get("value") or kind)
                    status = "observed"
                observation_id = stable_id("evidence", f"{asset}:{finding.get('source_tool')}:{finding_index}:{observation_index}:{label}")
                nodes.append({"id": observation_id, "position": {"x": 320, "y": (finding_index + observation_index + 1) * 90}, "type": "default", "data": {"label": label, "kind": kind, "source": finding.get("source_tool"), "validation_status": status, "confidence": finding.get("confidence", 0)}})
                edge_id = stable_id("edge", f"{target_id}:{observation_id}")
                edges.append({"id": edge_id, "source": target_id, "target": observation_id, "label": "observed on", "data": {"validation_status": status}})

            severity = str(finding.get("severity", "low")).lower()
            risk = {"critical": 5, "high": 4, "moderate": 3, "medium": 3, "low": 2}.get(severity, 2)
            finding_id = stable_id("finding", f"{asset}:{finding.get('source_tool')}:{finding.get('title')}:{finding_index}")
            nodes.append({"id": finding_id, "position": {"x": 640, "y": (finding_index + 1) * 110}, "type": "output", "data": {"label": finding.get("title", "Assessment evidence"), "kind": "finding", "source": finding.get("source_tool"), "severity": severity, "risk": risk, "risk_score": finding.get("score", 0), "validation_status": finding.get("status", "candidate"), "confidence": finding.get("confidence", 0), "evidence": finding.get("evidence", "")}})
            edges.append({"id": stable_id("edge", f"{target_id}:{finding_id}"), "source": target_id, "target": finding_id, "label": "evidence from", "data": {"validation_status": finding.get("status", "candidate")}})
        return {"nodes": nodes, "edges": edges}
