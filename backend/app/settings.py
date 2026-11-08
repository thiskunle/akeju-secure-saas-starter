# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Secure SaaS Starter, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
import os
from dataclasses import dataclass, field


def _secret() -> str:
    value = os.environ.get("APP_SECRET", "")
    if len(value) < 32:
        raise RuntimeError("Set APP_SECRET to a random value of at least 32 characters.")
    return value


@dataclass(frozen=True)
class Settings:
    secret: str = field(default_factory=_secret)
    database_url: str = field(default_factory=lambda: os.environ.get("DATABASE_URL", "sqlite:///./app.db"))
    allowed_origin: str = field(default_factory=lambda: os.environ.get("ALLOWED_ORIGIN", "http://localhost:3000"))
    cookie_secure: bool = field(default_factory=lambda: os.environ.get("COOKIE_SECURE", "true") != "false")
    session_minutes: int = 30
    mfa_ticket_minutes: int = 5
    max_failed_logins: int = 5
    lockout_minutes: int = 15
