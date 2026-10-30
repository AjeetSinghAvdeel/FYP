from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_model
from app.core.database import SessionLocal, get_db
from app.models import Assessment, AuditEvent, Target
from app.schemas.assessment import AssessmentCreate, AssessmentOut, AssessmentStep
from app.services.assessment_runner import run_step
from app.services.audit import record_event
from app.services.jobs import is_active, start_job

router = APIRouter(prefix="/api/assessments", tags=["assessments"])


@router.get("", response_model=list[AssessmentOut])
def list_assessments(current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> list[Assessment]:
    return db.query(Assessment).filter(Assessment.owner_id == current_user.id).order_by(Assessment.created_at.desc()).all()


@router.post("", response_model=AssessmentOut)
def create_assessment(payload: AssessmentCreate, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> Assessment:
    target = db.query(Target).filter(Target.id == payload.target_id, Target.owner_id == current_user.id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    assessment = Assessment(
        name=payload.name,
        status="initialized",
        budget=payload.budget,
        target_id=target.id,
        owner_id=current_user.id,
        summary=f"Assessment started for {target.name}.",
        risk_score=0.0,
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    record_event(db, "assessment_created", user_id=current_user.id, assessment_id=assessment.id, outcome=assessment.name, current_state={"status": assessment.status})
    db.commit()
    return assessment


@router.post("/{assessment_id}/run", response_model=AssessmentStep)
def run_assessment_step(assessment_id: int, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> dict:
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.owner_id == current_user.id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    try:
        return run_step(db, assessment, current_user.id)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post("/{assessment_id}/start")
def start_assessment(assessment_id: int, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> dict:
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.owner_id == current_user.id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    try:
        job_id = start_job(assessment.id, current_user.id)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"assessment_id": assessment.id, "job_id": job_id, "status": "running"}


@router.post("/{assessment_id}/pause")
def pause_assessment(assessment_id: int, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> dict:
    return _set_lifecycle_state(assessment_id, current_user.id, "paused", db)


@router.post("/{assessment_id}/resume")
def resume_assessment(assessment_id: int, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> dict:
    result = _set_lifecycle_state(assessment_id, current_user.id, "running", db)
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if assessment and not is_active(assessment.id):
        try:
            result["job_id"] = start_job(assessment.id, current_user.id)
        except RuntimeError:
            pass
    return result


@router.post("/{assessment_id}/stop")
def stop_assessment(assessment_id: int, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> dict:
    return _set_lifecycle_state(assessment_id, current_user.id, "stopped", db)


def _set_lifecycle_state(assessment_id: int, user_id: int, state: str, db: Session) -> dict:
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.owner_id == user_id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    assessment.status = state
    assessment.current_phase = state
    if state == "stopped":
        assessment.completed_at = __import__("datetime").datetime.utcnow()
    record_event(db, f"assessment_{state}", user_id=user_id, assessment_id=assessment_id, current_state={"status": state})
    db.commit()
    return {"assessment_id": assessment_id, "status": state}


@router.get("/{assessment_id}", response_model=AssessmentOut)
def get_assessment(assessment_id: int, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> Assessment:
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.owner_id == current_user.id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    return assessment

@router.get("/{assessment_id}/events")
async def assessment_events(assessment_id: int, after_event_id: int = 0, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> StreamingResponse:
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.owner_id == current_user.id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    async def stream():
        session = SessionLocal()
        try:
            last_state = None
            last_event_id = max(after_event_id, 0)
            idle_polls = 0
            for _ in range(400):
                current = session.query(Assessment).filter(Assessment.id == assessment_id, Assessment.owner_id == current_user.id).first()
                if not current:
                    break
                events = session.query(AuditEvent).filter(
                    AuditEvent.assessment_id == assessment_id,
                    AuditEvent.id > last_event_id,
                ).order_by(AuditEvent.id.asc()).limit(100).all()
                activity = []
                for event in events:
                    activity.append({
                        "id": event.id,
                        "assessment_id": event.assessment_id,
                        "event_type": event.event_type,
                        "action": event.action,
                        "decision": event.decision,
                        "outcome": event.outcome,
                        "current_state": event.current_state or {},
                        "created_at": event.created_at.isoformat(),
                    })
                    last_event_id = event.id
                state = {"assessment_id": current.id, "status": current.status, "phase": current.current_phase, "progress": current.progress, "requests_used": current.requests_used, "risk_score": current.risk_score, "next_action": current.next_action}
                current_status = current.status
                session.rollback()
                for payload in activity:
                    yield f"event: activity\ndata: {json.dumps(payload)}\n\n"
                if state != last_state:
                    yield f"event: assessment\ndata: {json.dumps(state)}\n\n"
                    last_state = state
                if current_status in {"completed", "failed", "stopped", "awaiting_approval"}:
                    break
                idle_polls = 0 if activity else idle_polls + 1
                if idle_polls >= 70:
                    break
                await asyncio.sleep(0.75)
        finally:
            session.close()

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "Connection": "keep-alive"})
