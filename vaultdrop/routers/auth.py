from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..auth import hash_password, sign_session, verify_password
from ..database import session_scope
from ..models import User
from ..services import audit

router = APIRouter(prefix="/v1/auth", tags=["auth"])


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=12, max_length=256)


@router.post("/register")
def register(body: Credentials, response: Response) -> dict[str, str]:
    with session_scope() as db:
        if db.scalar(select(User).where(User.username == body.username)):
            raise HTTPException(status_code=409, detail="Username already exists")
        user = User(username=body.username, password_hash=hash_password(body.password))
        db.add(user)
        db.flush()
        audit(db, user.id, "auth.registered", user.id, "User registered")
    token = sign_session(user.id)
    response.set_cookie("vaultdrop_session", token, httponly=True, samesite="strict", secure=False, max_age=7 * 86400)
    return {"user_id": user.id, "username": user.username}


@router.post("/login")
def login(body: Credentials, response: Response) -> dict[str, str]:
    with session_scope() as db:
        user = db.scalar(select(User).where(User.username == body.username))
        if not user or not verify_password(user.password_hash, body.password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        audit(db, user.id, "auth.login", user.id, "Local session issued")
    token = sign_session(user.id)
    response.set_cookie("vaultdrop_session", token, httponly=True, samesite="strict", secure=False, max_age=7 * 86400)
    return {"user_id": user.id, "username": user.username}


@router.post("/logout")
def logout(response: Response) -> dict[str, str]:
    response.delete_cookie("vaultdrop_session")
    return {"status": "logged out"}
