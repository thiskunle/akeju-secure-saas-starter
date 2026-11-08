# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Secure SaaS Starter, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""Password hashing, TOTP with replay protection, and signed tokens."""
import hashlib
import base64
import time
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import pyotp

ALGORITHM = "HS256"
# Spent on unknown emails so response time does not reveal whether an account exists.
_DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt(12))


def _prehash(password: str) -> bytes:
    """bcrypt silently stops at 72 bytes, so long passwords are condensed first."""
    return base64.b64encode(hashlib.sha256(password.encode()).digest())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(12)).decode()


def verify_password(password: str, stored: str) -> bool:
    return bcrypt.checkpw(_prehash(password), stored.encode())


def burn_password_check(password: str) -> None:
    bcrypt.checkpw(_prehash(password), _DUMMY_HASH)


def new_mfa_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Return the accepted time step, or None. A step already used cannot be used again."""
    now = time.time() if now is None else now
    totp = pyotp.TOTP(secret)
    current = int(now) // totp.interval
    for step in (current - 1, current, current + 1):
        if step > last_step and pyotp.utils.strings_equal(totp.at(step * totp.interval), code):
            return step
    return None


def make_token(secret: str, purpose: str, subject: str, minutes: int, version: int = 0) -> str:
    now = datetime.now(timezone.utc)
    claims = {"sub": subject, "purpose": purpose, "ver": version, "iat": now, "exp": now + timedelta(minutes=minutes)}
    return jwt.encode(claims, secret, algorithm=ALGORITHM)


def read_token(secret: str, token: str, purpose: str) -> dict | None:
    try:
        claims = jwt.decode(token, secret, algorithms=[ALGORITHM], options={"require": ["exp", "sub", "purpose"]})
    except jwt.PyJWTError:
        return None
    return claims if claims["purpose"] == purpose else None
