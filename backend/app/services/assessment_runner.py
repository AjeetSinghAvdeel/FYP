from __future__ import annotations

from datetime import datetime
from time import perf_counter
from typing import Any

from sqlalchemy.orm import Session

from app.models import Assessment, Finding, ToolExecution
from app.services.attack_graph import AttackGraphEngine
from app.services.audit import record_event
from app.services.orchestrator import AssessmentOrchestrator


def _complete_without_action(db: Session, assessment: Assessment, user_id: int, reason: str) -> dict[str, Any]:
    assessment.status = "completed"
    assessment.current_phase = "completed"
    assessment.progress = 100
    assessment.completed_at = datetime.utcnow()
    record_event(
        db,
        "assessment_completed",
        user_id=user_id,
        assessment_id=assessment.id,
        outcome=reason,
        current_state={"status": assessment.status, "requests_used": assessment.requests_used, "budget": assessment.budget},
    )
    db.commit()
    return {
        "assessment_id": assessment.id,
        "tool": "none",
        "recommendation": reason,
        "threat_score": float(assessment.risk_score or 0.0),
        "authorization": "completed",
        "score_breakdown": {},
        "mode": "not_applicable",
        "status": assessment.status,
    }


def run_step(db: Session, assessment: Assessment, user_id: int, orchestrator: AssessmentOrchestrator | None = None) -> dict[str, Any]:
    target = assessment.target
    findings = [
        {
            "severity": item.severity,
            "asset": item.asset,
            "confidence": item.confidence,
            "source_tool": item.source_tool,
            "title": item.title,
            "evidence": item.evidence,
            "observations": item.observations or [],
        }
        for item in assessment.findings
    ]
    if assessment.status in {"paused", "stopped", "failed", "completed"}:
        raise RuntimeError(f"Assessment is {assessment.status} and cannot execute.")
    if assessment.budget <= len(findings):
        return _complete_without_action(db, assessment, user_id, "Assessment action budget exhausted.")

    assessment.current_phase = "planning"
    assessment.status = "running"
    record_event(db, "candidate_planning", user_id=user_id, assessment_id=assessment.id, current_state={"phase": assessment.current_phase, "finding_count": len(findings)})
    db.commit()

    def record_selection(selection: dict[str, Any]) -> None:
        assessment.current_phase = "executing"
        record_event(
            db,
            "action_selected",
            user_id=user_id,
            assessment_id=assessment.id,
            action=selection.get("selected_action"),
            decision="approved",
            outcome=selection.get("selection_reason"),
            current_state=selection,
        )
        db.commit()

    started = perf_counter()
    active_orchestrator = orchestrator or AssessmentOrchestrator(on_action_selected=record_selection)
    try:
        result = active_orchestrator.run_next_step(target.target_url, target.allowed_tools, target.scope, findings)
    except RuntimeError as error:
        if "No eligible actions remain" not in str(error):
            raise
        return _complete_without_action(db, assessment, user_id, "No eligible authorized actions remain.")
    elapsed_ms = int((perf_counter() - started) * 1000)
    record_event(
        db,
        "policy_decision",
        user_id=user_id,
        assessment_id=assessment.id,
        action=result.tool_name,
        decision="approved" if result.decision["allowed"] else "denied",
        outcome=result.decision["reason"],
    )

    evidence = result.evidence
    execution = ToolExecution(
        assessment_id=assessment.id,
        tool=result.tool_name,
        status=evidence.get("status", "unknown"),
        mode=evidence.get("mode", "real"),
        target=target.target_url,
        return_code=evidence.get("return_code"),
        output=evidence.get("output") or evidence.get("message"),
        stderr=evidence.get("stderr"),
        request_budget=evidence.get("request_budget"),
        requests_made=evidence.get("requests_made"),
        observations=evidence.get("observations", []),
        duration_ms=evidence.get("duration_ms"),
        started_at=datetime.fromisoformat(evidence["started_at"]) if evidence.get("started_at") else datetime.utcnow(),
        finished_at=datetime.fromisoformat(evidence["finished_at"]) if evidence.get("finished_at") else datetime.utcnow(),
    )
    db.add(execution)

    new_finding = Finding(
        assessment_id=assessment.id,
        source_tool=result.finding["source_tool"],
        title=result.finding["title"],
        severity=result.finding["severity"],
        confidence=result.finding["confidence"],
        asset=result.finding["asset"],
        vector=result.finding["vector"],
        evidence=result.finding["evidence"],
        status=result.finding["status"],
        risk_score=float(result.finding.get("score", 0.0)),
        risk_breakdown=result.finding.get("score_breakdown", {}),
        observations=result.finding.get("observations", []),
        simulated=evidence.get("mode") == "mock",
    )
    db.add(new_finding)
    db.flush()
    record_event(
        db,
        "tool_execution",
        user_id=user_id,
        assessment_id=assessment.id,
        action=result.tool_name,
        outcome=evidence.get("status", "unknown"),
        evidence_reference=evidence.get("mode", "real"),
        current_state={
            "assessment_id": assessment.id,
            "execution_id": execution.id,
            "finding_id": new_finding.id,
            "tool_version": evidence.get("tool_version"),
            "command_args": evidence.get("command_args"),
            "started_at": evidence.get("started_at"),
            "finished_at": evidence.get("finished_at"),
            "duration_ms": evidence.get("duration_ms"),
            "requests_made": evidence.get("requests_made"),
            "request_budget": evidence.get("request_budget"),
            "return_code": evidence.get("return_code"),
            "observations": evidence.get("observations", []),
            "selection": result.decision,
        },
    )
    assessment.next_action = result.tool_name
    assessment.requests_used += 1
    assessment.progress = min(100, round((assessment.requests_used / assessment.budget) * 100))
    assessment.risk_score = max(assessment.risk_score, new_finding.risk_score)
    assessment.graph_snapshot = result.graph
    assessment.current_phase = "updating_graph"
    assessment.status = "running" if result.decision["allowed"] else "awaiting_approval"
    record_event(db, "validation_result", user_id=user_id, assessment_id=assessment.id, action=result.tool_name, decision=new_finding.status, outcome=f"confidence={new_finding.confidence}")
    record_event(db, "graph_update", user_id=user_id, assessment_id=assessment.id, outcome=f"nodes={len(result.graph.get('nodes', []))}")
    db.commit()
    db.refresh(new_finding)
    return {
        "assessment_id": assessment.id,
        "tool": result.tool_name,
        "recommendation": result.decision["reason"],
        "threat_score": max(10.0, new_finding.risk_score),
        "authorization": "approved" if result.decision["allowed"] else "denied",
        "score_breakdown": new_finding.risk_breakdown or {},
        "mode": evidence.get("mode", "real"),
        "status": assessment.status,
        "execution_id": execution.id,
        "finding_id": new_finding.id,
        "selection": result.decision,
    }