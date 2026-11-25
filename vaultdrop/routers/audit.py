from fastapi import APIRouter, Cookie, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import verify_session
from ..database import session_scope
from ..models import AuditEvent, User

router = APIRouter(prefix="/v1/audit", tags=["audit"])


def actor(db: Session, session_cookie: str | None) -> User:
    user_id = verify_session(session_cookie or "")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


@router.get("")
def audit_list(vaultdrop_session: str | None = Cookie(default=None)) -> list[dict[str, object]]:
    with session_scope() as db:
        user = actor(db, vaultdrop_session)
        rows = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.actor_id.in_([user.id, "anonymous"]))
            .order_by(AuditEvent.created_at.desc())
            .limit(500)
        )
        return [
            {"id": r.id, "action": r.action, "resource_id": r.resource_id, "detail": r.detail, "created_at": r.created_at.isoformat()}
            for r in rows
        ]
