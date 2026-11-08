# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Secure SaaS Starter, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
import time

import jwt
import pyotp
import pytest
from fastapi.testclient import TestClient

from app import security
from app.main import create_app
from app.settings import Settings

SECRET = "t" * 40
PASSWORD = "correct-horse-battery"


@pytest.fixture
def app():
    return create_app(Settings(secret=SECRET, database_url="sqlite:///:memory:", cookie_secure=False))


class Api:
    def __init__(self, app):
        self.c = TestClient(app)

    def _csrf(self):
        token = self.c.cookies.get("csrf")
        return {"X-CSRF-Token": token} if token else {}

    def post(self, url, **body):
        return self.c.post(url, json=body, headers=self._csrf())

    def patch(self, url, **body):
        return self.c.patch(url, json=body, headers=self._csrf())

    def delete(self, url):
        return self.c.delete(url, headers=self._csrf())

    def get(self, url):
        return self.c.get(url)

    def signup(self, email="owner@a.com", company="A"):
        r = self.post("/auth/signup", company=company, email=email, password=PASSWORD)
        assert r.status_code == 201
        return r.json()

    def login(self, email):
        r = self.post("/auth/login", email=email, password=PASSWORD)
        assert r.status_code == 200
        return r


def member(app, owner, role, email):
    r = owner.post("/members", email=email, password=PASSWORD, role=role)
    assert r.status_code == 201
    user = Api(app)
    user.login(email)
    return user, r.json()["id"]


def enable_mfa(api):
    secret = api.post("/auth/mfa/setup").json()["secret"]
    r = api.post("/auth/mfa/enable", code=pyotp.TOTP(secret).at(time.time() - 30))
    assert r.status_code == 200
    return secret


def test_signup_sets_hardened_cookie_and_returns_no_secrets(app):
    secure = create_app(Settings(secret=SECRET, database_url="sqlite:///:memory:", cookie_secure=True))
    api = Api(secure)
    r = api.post("/auth/signup", company="A", email="a@a.com", password=PASSWORD)
    cookie = next(h for h in r.headers.get_list("set-cookie") if h.startswith("session="))
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=strict" in cookie
    assert "password" not in r.text


def test_short_password_rejected(app):
    assert Api(app).post("/auth/signup", company="A", email="a@a.com", password="short").status_code == 422


def test_password_is_hashed_and_long_passwords_differ():
    stored = security.hash_password("a" * 100)
    assert stored.startswith("$2b$12$")
    assert security.verify_password("a" * 100, stored)
    assert not security.verify_password("a" * 99, stored)


def test_login_messages_do_not_reveal_accounts(app):
    api = Api(app)
    api.signup()
    other = Api(app)
    known = other.post("/auth/login", email="owner@a.com", password="wrong-password-123")
    unknown = other.post("/auth/login", email="nobody@a.com", password="wrong-password-123")
    assert known.status_code == unknown.status_code == 401 and known.json() == unknown.json()


def test_lockout_blocks_correct_password(app):
    Api(app).signup()
    other = Api(app)
    for _ in range(5):
        other.post("/auth/login", email="owner@a.com", password="wrong-password-123")
    assert other.post("/auth/login", email="owner@a.com", password=PASSWORD).status_code == 401


def test_csrf_required_with_session(app):
    api = Api(app)
    api.signup()
    assert api.c.post("/projects", json={"name": "x"}).status_code == 403
    assert api.c.post("/projects", json={"name": "x"}, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert api.post("/projects", name="x").status_code == 201


def test_requires_login(app):
    assert Api(app).get("/projects").status_code == 401


def test_forged_and_expired_tokens_rejected(app):
    api = Api(app)
    user = api.signup()
    forged = jwt.encode({"sub": user["id"], "purpose": "session", "ver": 0, "exp": time.time() + 600}, "x" * 40, algorithm="HS256")
    expired = jwt.encode({"sub": user["id"], "purpose": "session", "ver": 0, "exp": time.time() - 5}, SECRET, algorithm="HS256")
    for token in (forged, expired):
        fresh = Api(app)
        fresh.c.cookies.set("session", token)
        assert fresh.get("/me").status_code == 401


def test_alg_none_rejected(app):
    user = Api(app).signup()
    token = jwt.encode({"sub": user["id"], "purpose": "session", "ver": 0, "exp": time.time() + 600}, None, algorithm="none")
    fresh = Api(app)
    fresh.c.cookies.set("session", token)
    assert fresh.get("/me").status_code == 401


def test_mfa_ticket_cannot_be_used_as_session(app):
    api = Api(app)
    api.signup()
    enable_mfa(api)
    other = Api(app)
    ticket = other.login("owner@a.com").json()["ticket"]
    other.c.cookies.set("session", ticket)
    assert other.get("/me").status_code == 401


def test_logout_invalidates_old_token(app):
    api = Api(app)
    api.signup()
    token = api.c.cookies.get("session")
    assert api.post("/auth/logout").status_code == 200
    replay = Api(app)
    replay.c.cookies.set("session", token)
    assert replay.get("/me").status_code == 401


def test_mfa_login_flow_and_replay_blocked(app):
    api = Api(app)
    api.signup()
    secret = enable_mfa(api)
    assert api.get("/me").json()["mfa_enabled"] is True

    other = Api(app)
    first = other.login("owner@a.com").json()
    assert first["mfa_required"] is True and "session" not in other.c.cookies
    code = pyotp.TOTP(secret).now()
    assert other.post("/auth/mfa/login", ticket=first["ticket"], code=code).status_code == 200
    assert other.get("/me").status_code == 200

    replay = Api(app)
    second = replay.login("owner@a.com").json()
    assert replay.post("/auth/mfa/login", ticket=second["ticket"], code=code).status_code == 401


def test_wrong_mfa_codes_lock_the_account(app):
    api = Api(app)
    api.signup()
    secret = enable_mfa(api)
    other = Api(app)
    ticket = other.login("owner@a.com").json()["ticket"]
    for _ in range(5):
        assert other.post("/auth/mfa/login", ticket=ticket, code="000000").status_code == 401
    assert other.post("/auth/mfa/login", ticket=ticket, code=pyotp.TOTP(secret).now()).status_code == 401


def test_totp_rejects_outside_window():
    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret).at(1000000)
    assert security.verify_totp(secret, code, 0, now=1000000 + 300) is None
    assert security.verify_totp(secret, code, 0, now=1000000) is not None


def test_tenants_are_isolated(app):
    a, b = Api(app), Api(app)
    a.signup("a@a.com", "A")
    b.signup("b@b.com", "B")
    project = a.post("/projects", name="secret").json()
    assert b.get("/projects").json() == []
    assert b.delete(f"/projects/{project['id']}").status_code == 404
    assert len(a.get("/projects").json()) == 1


def test_cross_tenant_member_change_is_hidden(app):
    a, b = Api(app), Api(app)
    a.signup("a@a.com", "A")
    b.signup("b@b.com", "B")
    _, member_id = member(app, a, "viewer", "v@a.com")
    assert b.patch(f"/members/{member_id}", role="admin").status_code == 404


def test_audit_log_is_tenant_scoped(app):
    a, b = Api(app), Api(app)
    a.signup("a@a.com", "A")
    b.signup("b@b.com", "B")
    a.post("/projects", name="x")
    assert "project.created" in [e["action"] for e in a.get("/audit").json()]
    assert "project.created" not in [e["action"] for e in b.get("/audit").json()]


@pytest.mark.parametrize("role,create,delete,audit", [
    ("viewer", 403, 403, 403), ("member", 201, 403, 403), ("admin", 201, 204, 200),
])
def test_role_matrix(app, role, create, delete, audit):
    owner = Api(app)
    owner.signup()
    pid = owner.post("/projects", name="p").json()["id"]
    user, _ = member(app, owner, role, f"{role}@a.com")
    assert user.get("/projects").status_code == 200
    assert user.post("/projects", name="n").status_code == create
    assert user.delete(f"/projects/{pid}").status_code == delete
    assert user.get("/audit").status_code == audit


def test_admin_cannot_escalate(app):
    owner = Api(app)
    owner.signup()
    admin, admin_id = member(app, owner, "admin", "admin@a.com")
    _, viewer_id = member(app, owner, "viewer", "v@a.com")
    assert admin.post("/members", email="o@a.com", password=PASSWORD, role="owner").status_code == 403
    assert admin.post("/members", email="o@a.com", password=PASSWORD, role="admin").status_code == 403
    assert admin.patch(f"/members/{viewer_id}", role="owner").status_code == 403
    assert admin.patch(f"/members/{admin_id}", role="owner").status_code == 403


def test_role_change_ends_old_session(app):
    owner = Api(app)
    owner.signup()
    user, uid = member(app, owner, "member", "m@a.com")
    assert owner.patch(f"/members/{uid}", role="viewer").status_code == 200
    assert user.get("/me").status_code == 401


def test_security_headers_and_attribution(app):
    r = Api(app).get("/health")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert "Adekunle Akeju" in r.headers["x-powered-by"]


def test_missing_secret_refuses_to_start(monkeypatch):
    monkeypatch.setenv("APP_SECRET", "short")
    with pytest.raises(RuntimeError):
        Settings()
