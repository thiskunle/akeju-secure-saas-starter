# akeju-secure-saas-starter

**Created by Adekunle Akeju, founder of GramByte Technologies Inc.**

A Next.js and FastAPI starter with the security work most starters skip already done and tested.

| Feature | How it works |
|---|---|
| Passwords | bcrypt, 12 characters minimum, safe for passwords over bcrypt's 72-byte limit |
| Two-step sign-in | TOTP, and a used code cannot be replayed |
| Sessions | HttpOnly, Secure, SameSite=Strict cookies, ended server-side on sign-out or role change |
| CSRF | Token required on every state-changing request with a session |
| Lockout | 5 failed attempts locks the account for 15 minutes, for passwords and two-step codes |
| Roles | Owner, admin, member, viewer, and nobody can grant a role at or above their own |
| Customer separation | All tenant data goes through `TenantScope`; another customer's row looks like it does not exist |
| Audit log | Sign-ins, failures, lockouts, role changes and data changes, visible per company |

## Run it

```
cd backend
pip install -r requirements.txt
set APP_SECRET=<at least 32 random characters>
set COOKIE_SECURE=false
uvicorn app.asgi:app --port 8000

cd frontend
npm ci
npm run build
npm start
```

`COOKIE_SECURE=false` is for local HTTP only. The backend refuses to start without a strong `APP_SECRET`.

## Tests

```
cd backend && pytest
cd frontend && npm run build && npx playwright test
```

The tests attack the app: forged and expired tokens, `alg=none`, MFA replay, cross-tenant access, role escalation and missing CSRF tokens. The browser test runs the full journey from sign-up through two-step sign-in.

## Add before production

Email verification and password reset, per-IP rate limiting at your proxy, encryption for stored MFA secrets, database migrations, a nonce-based CSP in place of `unsafe-inline`, and an independent security review.

## License and credit

AGPL-3.0-or-later, with an attribution requirement. See [NOTICE.md](NOTICE.md). Copyright (c) 2026 Adekunle Akeju.
