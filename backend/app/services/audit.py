from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditEvent


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def record_event(
    db: Session,
    event_type: str,
    *,
    user_id: int | None = None,
    assessment_id: int | None = None,
    action: str | None = None,
    decision: str | None = None,
    outcome: str | None = None,
    evidence_reference: str | None = None,
    previous_state: dict[str, Any] | None = None,
    current_state: dict[str, Any] | None = None,
) -> AuditEvent:
    previous = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    previous_hash = previous.event_hash if previous else "GENESIS"
    created_at = datetime.utcnow()
    body = {
        "event_type": event_type,
        "user_id": user_id,
        "assessment_id": assessment_id,
        "action": action,
        "decision": decision,
        "outcome": outcome,
        "evidence_reference": evidence_reference,
        "previous_state": previous_state,
        "current_state": current_state,
        "previous_hash": previous_hash,
        "created_at": created_at.isoformat(),
    }
    event_hash = hashlib.sha256(_canonical(body).encode()).hexdigest()
    event = AuditEvent(
        event_type=event_type,
        user_id=user_id,
        assessment_id=assessment_id,
        action=action,
        decision=decision,
        outcome=outcome,
        evidence_reference=evidence_reference,
        previous_state=previous_state,
        current_state=current_state,
        previous_hash=previous_hash,
        event_hash=event_hash,
        created_at=created_at,
    )
    db.add(event)
    db.flush()
    return event


def verify_chain(db: Session) -> dict[str, Any]:
    events = db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()
    previous_hash = "GENESIS"
    for event in events:
        body = {
            "event_type": event.event_type,
            "user_id": event.user_id,
            "assessment_id": event.assessment_id,
            "action": event.action,
            "decision": event.decision,
            "outcome": event.outcome,
            "evidence_reference": event.evidence_reference,
            "previous_state": event.previous_state,
            "current_state": event.current_state,
            "previous_hash": event.previous_hash,
            "created_at": event.created_at.isoformat(),
        }
        expected = hashlib.sha256(_canonical(body).encode()).hexdigest()
        if event.previous_hash != previous_hash or event.event_hash != expected:
            return {"valid": False, "checked": event.id - 1, "failed_event_id": event.id}
        previous_hash = event.event_hash
    return {"valid": True, "checked": len(events), "failed_event_id": None}