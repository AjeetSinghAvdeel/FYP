from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_model
from app.core.database import get_db
from app.core.security import create_access_token, hash_password, verify_password
from app.models import User
from app.schemas.auth import TokenResponse, UserLogin, UserRegister

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse)
def register(user: UserRegister, db: Session = Depends(get_db)) -> TokenResponse:
    if db.query(User).filter((User.username == user.username) | (User.email == user.email)).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    new_user = User(username=user.username, email=user.email, hashed_password=hash_password(user.password), role="security_operator")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    token = create_access_token(new_user.username)
    return TokenResponse(access_token=token, username=new_user.username)


@router.post("/login", response_model=TokenResponse)
def login(payload: UserLogin, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    token = create_access_token(user.username)
    return TokenResponse(access_token=token, username=user.username)


@router.get("/me")
def me(current_user: User = Depends(get_current_user_model)) -> dict:
    return {"username": current_user.username, "email": current_user.email, "role": current_user.role}
