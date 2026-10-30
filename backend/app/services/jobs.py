from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from uuid import uuid4

from app.core.database import SessionLocal
from app.models import Assessment
from app.services.assessment_runner import run_step
from app.services.audit import record_event

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="assessment")
_active: set[int] = set()
_lock = Lock()


def start_job(assessment_id: int, user_id: int) -> str:
    with _lock:
        if assessment_id in _active:
            raise RuntimeError("Assessment already has an active background job.")
        _active.add(assessment_id)
    job_id = str(uuid4())
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.owner_id == user_id).first()
        if not assessment:
            raise RuntimeError("Assessment not found")
        assessment.job_id = job_id
        assessment.status = "running"
        record_event(db, "assessment_started", user_id=user_id, assessment_id=assessment_id, outcome="background job", current_state={"status": assessment.status, "job_id": job_id})
        db.commit()
    finally:
        db.close()
    _executor.submit(_worker, assessment_id, user_id, job_id)
    return job_id


def _worker(assessment_id: int, user_id: int, job_id: str) -> None:
    try:
        while True:
            db = SessionLocal()
            try:
                assessment = db.query(Assessment).filter(Assessment.id == assessment_id, Assessment.owner_id == user_id, Assessment.job_id == job_id).first()
                if not assessment or assessment.status in {"paused", "stopped", "failed", "completed", "awaiting_approval"}:
                    return
                run_step(db, assessment, user_id)
            except RuntimeError:
                return
            except Exception as exc:
                if assessment:
                    assessment.status = "failed"
                    assessment.current_phase = "failed"
                    assessment.last_error = str(exc)
                    record_event(db, "assessment_failed", user_id=user_id, assessment_id=assessment_id, outcome=str(exc), current_state={"status": assessment.status})
                    db.commit()
                return
            finally:
                db.close()
    finally:
        with _lock:
            _active.discard(assessment_id)


def is_active(assessment_id: int) -> bool:
    with _lock:
        return assessment_id in _active