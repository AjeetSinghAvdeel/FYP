from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_model
from app.core.database import get_db
from app.models import Target
from app.schemas.target import TargetCreate, TargetRead
from app.services.policy import PolicyEngine

router = APIRouter(prefix="/api/targets", tags=["targets"])


@router.get("", response_model=list[TargetRead])
def list_targets(current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> list[Target]:
    return db.query(Target).filter(Target.owner_id == current_user.id).order_by(Target.created_at.desc()).all()


@router.post("", response_model=TargetRead)
def create_target(payload: TargetCreate, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> Target:
    allowed, reason = PolicyEngine.target_is_allowed(payload.target_url)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)
    target = Target(
        name=payload.name,
        target_url=payload.target_url,
        network_range=payload.network_range,
        description=payload.description,
        scope=payload.scope,
        allowed_tools=payload.allowed_tools,
        owner_id=current_user.id,
        status="registered",
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target
