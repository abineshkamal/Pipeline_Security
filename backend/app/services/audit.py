from __future__ import annotations

import logging

from ..models import AuditLog

log = logging.getLogger("pipelinetrust.audit")


def record(db, org_id: str | None, user, action: str, target: str = "", details: dict | None = None, ip: str = "") -> None:
    """Append an audit event. Never stores secrets - callers pass only identifiers / metadata."""
    try:
        db.add(AuditLog(organization_id=org_id, user_id=getattr(user, "id", None), user_email=getattr(user, "email", "") or "system",
                        action=action, target=target[:300], details=details or {}, ip=ip[:64]))
        db.commit()
    except Exception:  # noqa: BLE001 - auditing failure must not break the request
        db.rollback()
        log.exception("audit write failed")
