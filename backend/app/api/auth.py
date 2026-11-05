from __future__ import annotations

import threading
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import OrgContext, client_ip, current_user, org_context, require
from ..models import ROLES, AuditLog, Membership, Organization, User
from ..security import create_access_token, hash_password, verify_password
from ..services.audit import record

router = APIRouter(prefix="/api", tags=["auth"])

# naive in-memory brute-force throttle: 10 failed logins per (ip,email) per 15 minutes
_fails: dict[tuple[str, str], list[float]] = {}
_lock = threading.Lock()
WINDOW, MAX_FAILS = 900, 10


def _throttled(key) -> bool:
    now = time.time()
    with _lock:
        hits = [t for t in _fails.get(key, []) if now - t < WINDOW]
        _fails[key] = hits
        return len(hits) >= MAX_FAILS


def _fail(key):
    with _lock:
        _fails.setdefault(key, []).append(time.time())


class Password(BaseModel):
    password: str = Field(min_length=10, max_length=128)


class RegisterIn(Password):
    email: EmailStr
    full_name: str = Field(default="", max_length=200)
    organization_name: str = Field(min_length=2, max_length=200)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=128)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


def _strong(pw: str):
    classes = sum(any(f(c) for c in pw) for f in (str.islower, str.isupper, str.isdigit, lambda c: not c.isalnum()))
    if classes < 3:
        raise HTTPException(422, "password must contain at least 3 of: lowercase, uppercase, digit, symbol")


@router.post("/auth/register", response_model=TokenOut, status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    _strong(body.password)
    email = body.email.lower()
    if db.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none():
        raise HTTPException(409, "an account with this email already exists")
    org = Organization(name=body.organization_name.strip())
    user = User(email=email, full_name=body.full_name.strip(), password_hash=hash_password(body.password))
    db.add_all([org, user])
    db.flush()
    db.add(Membership(user_id=user.id, organization_id=org.id, role="admin"))
    db.commit()
    record(db, org.id, user, "auth.register", f"user:{user.id}", {"organization": org.name}, client_ip(request))
    return TokenOut(access_token=create_access_token(user.id))


@router.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    key = (ip, body.email.lower())
    if _throttled(key):
        raise HTTPException(429, "too many failed attempts; try again later")
    user = db.execute(select(User).where(func.lower(User.email) == body.email.lower())).scalar_one_or_none()
    if not user or not user.is_active or not verify_password(body.password, user.password_hash):
        _fail(key)
        record(db, None, None, "auth.login_failed", f"email:{body.email.lower()}", {}, ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid email or password")
    m = db.execute(select(Membership).where(Membership.user_id == user.id)).scalars().first()
    record(db, m.organization_id if m else None, user, "auth.login", f"user:{user.id}", {}, ip)
    return TokenOut(access_token=create_access_token(user.id))


@router.get("/auth/me")
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    ms = db.execute(select(Membership, Organization).join(Organization, Organization.id == Membership.organization_id)
                    .where(Membership.user_id == user.id)).all()
    return {"id": user.id, "email": user.email, "full_name": user.full_name,
            "organizations": [{"id": o.id, "name": o.name, "role": m.role} for m, o in ms]}


# ---------------------------------------------------------------- organization members

class MemberIn(Password):
    email: EmailStr
    full_name: str = Field(default="", max_length=200)
    role: str = Field(pattern="^(admin|analyst|viewer)$")


class RoleIn(BaseModel):
    role: str = Field(pattern="^(admin|analyst|viewer)$")


@router.get("/org")
def get_org(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    org = db.get(Organization, ctx.org_id)
    return {"id": org.id, "name": org.name, "role": ctx.role}


@router.get("/org/members")
def list_members(ctx: OrgContext = Depends(org_context), db: Session = Depends(get_db)):
    rows = db.execute(select(Membership, User).join(User, User.id == Membership.user_id)
                      .where(Membership.organization_id == ctx.org_id).order_by(User.email)).all()
    return [{"user_id": u.id, "email": u.email, "full_name": u.full_name, "role": m.role, "active": u.is_active} for m, u in rows]


@router.post("/org/members", status_code=201)
def add_member(body: MemberIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    _strong(body.password)
    email = body.email.lower()
    user = db.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()
    if user:
        # do not attach existing accounts from other orgs silently (prevents account takeover/enumeration games)
        raise HTTPException(409, "an account with this email already exists")
    user = User(email=email, full_name=body.full_name, password_hash=hash_password(body.password))
    db.add(user)
    db.flush()
    db.add(Membership(user_id=user.id, organization_id=ctx.org_id, role=body.role))
    db.commit()
    record(db, ctx.org_id, ctx.user, "member.add", f"user:{user.id}", {"email": email, "role": body.role}, ctx.ip)
    return {"user_id": user.id, "email": email, "role": body.role}


@router.patch("/org/members/{user_id}")
def change_role(user_id: str, body: RoleIn, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    m = db.execute(select(Membership).where(Membership.organization_id == ctx.org_id, Membership.user_id == user_id)).scalar_one_or_none()
    if not m:
        raise HTTPException(404, "member not found")
    if m.role == "admin" and body.role != "admin":
        admins = db.execute(select(func.count()).select_from(Membership).where(Membership.organization_id == ctx.org_id, Membership.role == "admin")).scalar()
        if admins <= 1:
            raise HTTPException(400, "cannot demote the last admin")
    old, m.role = m.role, body.role
    db.commit()
    record(db, ctx.org_id, ctx.user, "member.role_change", f"user:{user_id}", {"from": old, "to": body.role}, ctx.ip)
    return {"user_id": user_id, "role": m.role}


@router.delete("/org/members/{user_id}", status_code=204)
def remove_member(user_id: str, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    if user_id == ctx.user.id:
        raise HTTPException(400, "you cannot remove yourself")
    m = db.execute(select(Membership).where(Membership.organization_id == ctx.org_id, Membership.user_id == user_id)).scalar_one_or_none()
    if not m:
        raise HTTPException(404, "member not found")
    db.delete(m)
    db.commit()
    record(db, ctx.org_id, ctx.user, "member.remove", f"user:{user_id}", {}, ctx.ip)


@router.get("/org/audit")
def audit_log(limit: int = 200, ctx: OrgContext = Depends(require("admin")), db: Session = Depends(get_db)):
    rows = db.execute(select(AuditLog).where(AuditLog.organization_id == ctx.org_id).order_by(AuditLog.id.desc()).limit(min(limit, 1000))).scalars()
    return [{"id": r.id, "at": r.created_at.isoformat(), "user": r.user_email, "action": r.action, "target": r.target,
             "details": r.details, "ip": r.ip} for r in rows]


assert set(ROLES) == {"admin", "analyst", "viewer"}
