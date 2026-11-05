"""Request dependencies: authentication, organization (tenant) context and role-based access control.

Tenant isolation: every data route resolves an OrgContext from the authenticated user's membership. All queries
for tenant data filter on ctx.org_id, and object lookups go through `get_owned`, which returns 404 (not 403) for
objects belonging to another organization so their existence is not disclosed.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import Membership, User
from .security import decode_access_token

bearer = HTTPBearer(auto_error=False)
ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass
class OrgContext:
    user: User
    org_id: str
    role: str
    ip: str

    def can(self, minimum: str) -> bool:
        return ROLE_RANK.get(self.role, 0) >= ROLE_RANK[minimum]


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if not creds or creds.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required", headers={"WWW-Authenticate": "Bearer"})
    uid = decode_access_token(creds.credentials)
    user = db.get(User, uid) if uid else None
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    return user


def org_context(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db),
                x_org_id: str | None = Header(default=None)) -> OrgContext:
    q = select(Membership).where(Membership.user_id == user.id)
    if x_org_id:
        q = q.where(Membership.organization_id == x_org_id)
    m = db.execute(q.order_by(Membership.id)).scalars().first()
    if not m:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of this organization")
    return OrgContext(user=user, org_id=m.organization_id, role=m.role, ip=client_ip(request))


def require(minimum: str):
    def dep(ctx: OrgContext = Depends(org_context)) -> OrgContext:
        if not ctx.can(minimum):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"requires {minimum} role")
        return ctx
    return dep


def get_owned(db: Session, model, obj_id: str, ctx: OrgContext):
    obj = db.get(model, obj_id)
    if obj is None or getattr(obj, "organization_id", None) != ctx.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{model.__name__.lower()} not found")
    return obj
