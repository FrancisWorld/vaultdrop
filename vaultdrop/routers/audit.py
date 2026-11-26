from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import select

from ..deps import ContainerDep, CurrentUser
from ..models import AuditEvent

router = APIRouter(prefix="/v1/audit", tags=["audit"])


@router.get("")
def audit_list(
    user: CurrentUser,
    container: ContainerDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict[str, Any]]:
    with container.database.session() as db:
        rows = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.actor_id == user.id)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id)
            .limit(limit)
            .offset(offset)
        )
        return [
            {
                "id": r.id,
                "action": r.action,
                "resource_id": r.resource_id,
                "detail": r.detail,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]
