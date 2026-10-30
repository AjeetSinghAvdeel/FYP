from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.database import get_db
from app.models import User

router = APIRouter(prefix="/api/admin", tags=["administration"])


class RoleUpdate(BaseModel):
    role: str = Field(..., pattern="^(administrator|security_operator)$")


@router.get("/users")
def list_users(current_user: User = Depends(require_admin), db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": user.id, "username": user.username, "email": user.email, "role": user.role, "created_at": user.created_at} for user in db.query(User).order_by(User.created_at.asc()).all()]


@router.patch("/users/{user_id}/role")
def update_role(user_id: int, payload: RoleUpdate, current_user: User = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = payload.role
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role}