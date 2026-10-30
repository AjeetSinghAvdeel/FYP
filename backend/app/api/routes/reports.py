from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_model
from app.core.database import get_db
from app.models import Assessment, AuditEvent, Finding, Target, ToolExecution
from app.services.audit import verify_chain
from app.services.reporting import build_report, render_pdf
from app.services.orchestrator import ADAPTERS

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/dashboard/summary")
def dashboard_summary(current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> dict:
    assessments = db.query(Assessment).filter(Assessment.owner_id == current_user.id).all()
    targets = db.query(Target).filter(Target.owner_id == current_user.id).count()
    total_findings = db.query(Finding).join(Assessment).filter(Assessment.owner_id == current_user.id).count()
    high_risk = db.query(Finding).join(Assessment).filter(Assessment.owner_id == current_user.id, Finding.severity.in_(["critical", "high"])).count()
    return {
        "targets": targets,
        "assessments": len(assessments),
        "findings": total_findings,
        "high_risk_findings": high_risk,
        "risk_trend": [
            {"label": "Recon", "score": 25},
            {"label": "Enumeration", "score": 50},
            {"label": "Validation", "score": 72},
            {"label": "Assessment", "score": 86},
        ],
    }


@router.get("/assessments/{assessment_id}/report")
def assessment_report(assessment_id: int, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> dict:
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.owner_id == current_user.id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return _report_for(assessment, db)


@router.get("/assessments/{assessment_id}/report.pdf")
def assessment_report_pdf(assessment_id: int, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> Response:
    assessment = _owned_assessment(assessment_id, current_user.id, db)
    try:
        content = render_pdf(_report_for(assessment, db))
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Install reportlab to enable PDF reports.") from exc
    return Response(content=content, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="assessment-{assessment.id}.pdf"'})


@router.get("/assessments/{assessment_id}/audit")
def assessment_audit(assessment_id: int, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> dict:
    _owned_assessment(assessment_id, current_user.id, db)
    events = db.query(AuditEvent).filter(AuditEvent.assessment_id == assessment_id).order_by(AuditEvent.id.asc()).all()
    return {"events": [{"id": item.id, "event_type": item.event_type, "action": item.action, "decision": item.decision, "outcome": item.outcome, "event_hash": item.event_hash, "created_at": item.created_at} for item in events], "chain": verify_chain(db)}


@router.get("/tools/health")
def tool_health(current_user: object = Depends(get_current_user_model)) -> dict:
    return {name: {"installed": adapter.is_available(), "version": adapter.check_version(), "install_hint": adapter.install_hint} for name, adapter in ADAPTERS.items()}


def _owned_assessment(assessment_id: int, user_id: int, db: Session) -> Assessment:
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.owner_id == user_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment


def _report_for(assessment: Assessment, db: Session) -> dict:
    findings = db.query(Finding).filter(Finding.assessment_id == assessment.id).all()
    executions = db.query(ToolExecution).filter(ToolExecution.assessment_id == assessment.id).order_by(ToolExecution.id.asc()).all()
    events = db.query(AuditEvent).filter(AuditEvent.assessment_id == assessment.id).order_by(AuditEvent.id.asc()).all()
    report = build_report(assessment, findings, executions, events)
    report["graph"] = report["attack_graph"]
    return report
