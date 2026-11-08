# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Secure SaaS Starter, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""Tenant isolation in one place, so a route cannot forget it.

TenantScope is the only way routes read or write tenant-owned rows. It adds the tenant filter to
every query. A row from another tenant looks exactly like a row that does not exist.
"""
from typing import TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

T = TypeVar("T")


class TenantScope:
    def __init__(self, db: Session, tenant_id: str):
        self.db = db
        self.tenant_id = tenant_id

    def list(self, model: type[T]) -> list[T]:
        return list(self.db.scalars(select(model).where(model.tenant_id == self.tenant_id)))

    def get(self, model: type[T], row_id: str) -> T | None:
        return self.db.scalar(select(model).where(model.id == row_id, model.tenant_id == self.tenant_id))

    def add(self, row: T) -> T:
        row.tenant_id = self.tenant_id
        self.db.add(row)
        return row
