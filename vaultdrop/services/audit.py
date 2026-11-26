from sqlalchemy.orm import Session

from ..models import AuditEvent


def audit(db: Session, actor_id: str, action: str, resource_id: str, detail: str) -> None:
    db.add(AuditEvent(actor_id=actor_id, action=action, resource_id=resource_id, detail=detail))
