# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Secure SaaS Starter, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP API: sign-up, login with MFA, roles, tenant data and the audit log."""
import secrets
from datetime import timedelta
from typing import Annotated

import pyotp
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from . import __author__, security
from .db import AuditEvent, Base, Project, Role, Tenant, User, utcnow
from .settings import Settings
from .tenancy import TenantScope

SESSION_COOKIE = "session"
CSRF_COOKIE = "csrf"
RANK = {Role.VIEWER: 1, Role.MEMBER: 2, Role.ADMIN: 3, Role.OWNER: 4}
BAD_LOGIN = "Email or password is incorrect."


class SignUp(BaseModel):
    company: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)


class Login(BaseModel):
    email: EmailStr
    password: str = Field(max_length=256)


class MfaCode(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class MfaLogin(MfaCode):
    ticket: str


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class Invite(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    role: Role


class RoleChange(BaseModel):
    role: Role


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    is_memory = settings.database_url.endswith(":memory:")
    engine = create_engine(settings.database_url, **({"poolclass": StaticPool, "connect_args": {"check_same_thread": False}} if is_memory else {}))
    Base.metadata.create_all(engine)
    Sessions = sessionmaker(engine, expire_on_commit=False)

    app = FastAPI(title="akeju-secure-saas-starter", description=f"Created by {__author__}.", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(CORSMiddleware, allow_origins=[settings.allowed_origin], allow_credentials=True,
                       allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token"])

    @app.middleware("http")
    async def harden(request: Request, call_next):
        unsafe = request.method not in ("GET", "HEAD", "OPTIONS")
        if unsafe and request.cookies.get(SESSION_COOKIE):
            sent, expected = request.headers.get("x-csrf-token", ""), request.cookies.get(CSRF_COOKIE, "")
            if not expected or not secrets.compare_digest(sent, expected):
                response = Response('{"detail":"CSRF check failed."}', 403, media_type="application/json")
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers.update({
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store", "X-Powered-By": f"akeju-secure-saas-starter by {__author__}",
        })
        return response

    def get_db():
        with Sessions() as db:
            yield db

    Db = Annotated[Session, Depends(get_db)]

    def audit(db: Session, request: Request, action: str, tenant_id: str | None, actor_id: str | None, **detail):
        db.add(AuditEvent(tenant_id=tenant_id, actor_id=actor_id, action=action, detail=detail, ip=request.client.host if request.client else None))

    def start_session(response: Response, user: User) -> None:
        token = security.make_token(settings.secret, "session", user.id, settings.session_minutes, user.token_version)
        options = {"secure": settings.cookie_secure, "samesite": "strict", "max_age": settings.session_minutes * 60, "path": "/"}
        response.set_cookie(SESSION_COOKIE, token, httponly=True, **options)
        response.set_cookie(CSRF_COOKIE, secrets.token_urlsafe(32), httponly=False, **options)

    def current_user(db: Db, session: Annotated[str | None, Cookie()] = None) -> User:
        claims = security.read_token(settings.secret, session, "session") if session else None
        user = db.get(User, claims["sub"]) if claims else None
        if not user or claims["ver"] != user.token_version:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue.")
        return user

    CurrentUser = Annotated[User, Depends(current_user)]

    def require(minimum: Role):
        def check(user: CurrentUser) -> User:
            if RANK[user.role] < RANK[minimum]:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this.")
            return user
        return check

    def scope(user: CurrentUser, db: Db) -> TenantScope:
        return TenantScope(db, user.tenant_id)

    Scope = Annotated[TenantScope, Depends(scope)]

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/auth/signup", status_code=201)
    def signup(body: SignUp, request: Request, response: Response, db: Db):
        email = body.email.lower()
        if db.scalar(select(User).where(User.email == email)):
            raise HTTPException(status.HTTP_409_CONFLICT, "Could not create this account.")
        tenant = Tenant(name=body.company)
        db.add(tenant)
        db.flush()
        user = User(tenant_id=tenant.id, email=email, password_hash=security.hash_password(body.password), role=Role.OWNER)
        db.add(user)
        db.flush()
        audit(db, request, "account.created", tenant.id, user.id)
        db.commit()
        start_session(response, user)
        return {"id": user.id, "tenant_id": tenant.id, "role": user.role.value}

    @app.post("/auth/login")
    def login(body: Login, request: Request, response: Response, db: Db):
        email = body.email.lower()
        user = db.scalar(select(User).where(User.email == email))
        now = utcnow()
        if not user:
            security.burn_password_check(body.password)
            audit(db, request, "login.failed", None, None, reason="unknown_email")
            db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, BAD_LOGIN)
        if user.locked_until and user.locked_until > now:
            security.burn_password_check(body.password)
            audit(db, request, "login.locked", user.tenant_id, user.id)
            db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, BAD_LOGIN)
        if not security.verify_password(body.password, user.password_hash):
            user.failed_logins += 1
            if user.failed_logins >= settings.max_failed_logins:
                user.locked_until, user.failed_logins = now + timedelta(minutes=settings.lockout_minutes), 0
                audit(db, request, "account.locked", user.tenant_id, user.id)
            audit(db, request, "login.failed", user.tenant_id, user.id, reason="bad_password")
            db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, BAD_LOGIN)
        user.failed_logins, user.locked_until = 0, None
        if user.mfa_enabled:
            db.commit()
            return {"mfa_required": True, "ticket": security.make_token(settings.secret, "mfa", user.id, settings.mfa_ticket_minutes, user.token_version)}
        audit(db, request, "login.success", user.tenant_id, user.id)
        db.commit()
        start_session(response, user)
        return {"mfa_required": False}

    @app.post("/auth/mfa/login")
    def mfa_login(body: MfaLogin, request: Request, response: Response, db: Db):
        claims = security.read_token(settings.secret, body.ticket, "mfa")
        user = db.get(User, claims["sub"]) if claims else None
        if not user or not user.mfa_enabled or claims["ver"] != user.token_version or (user.locked_until and user.locked_until > utcnow()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in again.")
        step = security.verify_totp(user.mfa_secret, body.code, user.mfa_last_step)
        if step is None:
            user.failed_logins += 1
            if user.failed_logins >= settings.max_failed_logins:
                user.locked_until, user.failed_logins = utcnow() + timedelta(minutes=settings.lockout_minutes), 0
                audit(db, request, "account.locked", user.tenant_id, user.id)
            audit(db, request, "mfa.failed", user.tenant_id, user.id)
            db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "That code is not valid.")
        user.mfa_last_step, user.failed_logins = step, 0
        audit(db, request, "login.success", user.tenant_id, user.id, mfa=True)
        db.commit()
        start_session(response, user)
        return {"ok": True}

    @app.post("/auth/logout")
    def logout(user: CurrentUser, request: Request, response: Response, db: Db):
        user.token_version += 1
        audit(db, request, "logout", user.tenant_id, user.id)
        db.commit()
        response.delete_cookie(SESSION_COOKIE, path="/")
        response.delete_cookie(CSRF_COOKIE, path="/")
        return {"ok": True}

    @app.get("/me")
    def me(user: CurrentUser):
        return {"id": user.id, "email": user.email, "tenant_id": user.tenant_id, "role": user.role.value, "mfa_enabled": user.mfa_enabled}

    @app.post("/auth/mfa/setup")
    def mfa_setup(user: CurrentUser, db: Db):
        if user.mfa_enabled:
            raise HTTPException(status.HTTP_409_CONFLICT, "Two-step sign-in is already on.")
        user.mfa_secret = security.new_mfa_secret()
        db.commit()
        return {"secret": user.mfa_secret, "uri": pyotp.TOTP(user.mfa_secret).provisioning_uri(user.email, issuer_name="Akeju Secure SaaS")}

    @app.post("/auth/mfa/enable")
    def mfa_enable(body: MfaCode, user: CurrentUser, request: Request, response: Response, db: Db):
        step = security.verify_totp(user.mfa_secret, body.code, user.mfa_last_step) if user.mfa_secret else None
        if step is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code is not valid.")
        user.mfa_enabled, user.mfa_last_step = True, step
        user.token_version += 1
        audit(db, request, "mfa.enabled", user.tenant_id, user.id)
        db.commit()
        start_session(response, user)
        return {"ok": True}

    @app.get("/projects")
    def list_projects(_: Annotated[User, Depends(require(Role.VIEWER))], tenant: Scope):
        return [{"id": p.id, "name": p.name} for p in tenant.list(Project)]

    @app.post("/projects", status_code=201)
    def create_project(body: ProjectIn, user: Annotated[User, Depends(require(Role.MEMBER))], tenant: Scope, request: Request):
        project = tenant.add(Project(name=body.name))
        tenant.db.flush()
        audit(tenant.db, request, "project.created", user.tenant_id, user.id, project_id=project.id)
        tenant.db.commit()
        return {"id": project.id, "name": project.name}

    @app.delete("/projects/{project_id}", status_code=204)
    def delete_project(project_id: str, user: Annotated[User, Depends(require(Role.ADMIN))], tenant: Scope, request: Request):
        project = tenant.get(Project, project_id)
        if not project:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found.")
        tenant.db.delete(project)
        audit(tenant.db, request, "project.deleted", user.tenant_id, user.id, project_id=project_id)
        tenant.db.commit()

    @app.post("/members", status_code=201)
    def add_member(body: Invite, admin: Annotated[User, Depends(require(Role.ADMIN))], request: Request, db: Db):
        if RANK[body.role] >= RANK[admin.role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only add roles below your own.")
        email = body.email.lower()
        if db.scalar(select(User).where(User.email == email)):
            raise HTTPException(status.HTTP_409_CONFLICT, "Could not add this member.")
        member = User(tenant_id=admin.tenant_id, email=email, password_hash=security.hash_password(body.password), role=body.role)
        db.add(member)
        db.flush()
        audit(db, request, "member.added", admin.tenant_id, admin.id, member_id=member.id, role=body.role.value)
        db.commit()
        return {"id": member.id, "role": member.role.value}

    @app.patch("/members/{member_id}")
    def change_role(member_id: str, body: RoleChange, admin: Annotated[User, Depends(require(Role.ADMIN))], tenant: Scope, request: Request):
        member = tenant.get(User, member_id)
        if not member:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found.")
        if member.id == admin.id or RANK[member.role] >= RANK[admin.role] or RANK[body.role] >= RANK[admin.role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only change roles below your own.")
        old = member.role.value
        member.role = body.role
        member.token_version += 1
        audit(tenant.db, request, "member.role_changed", admin.tenant_id, admin.id, member_id=member.id, old=old, new=body.role.value)
        tenant.db.commit()
        return {"id": member.id, "role": member.role.value}

    @app.get("/audit")
    def audit_log(user: Annotated[User, Depends(require(Role.ADMIN))], db: Db):
        rows = db.scalars(select(AuditEvent).where(AuditEvent.tenant_id == user.tenant_id).order_by(AuditEvent.created_at.desc()).limit(200))
        return [{"action": e.action, "actor_id": e.actor_id, "detail": e.detail, "ip": e.ip, "at": e.created_at.isoformat()} for e in rows]

    return app
