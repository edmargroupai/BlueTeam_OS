from __future__ import annotations

from blueteam_common.errors import UnauthorizedError
from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.services.auth import (
    Actor,
    TenantActor,
    actor_from_api_key,
    actor_from_bearer,
    bind_tenant,
    require_permission,
)


def get_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "unknown")


def get_actor(
    request: Request,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Actor:
    request_id = get_request_id(request)
    if x_api_key:
        return actor_from_api_key(db, x_api_key, request_id)
    if authorization and authorization.lower().startswith("bearer "):
        return actor_from_bearer(db, authorization.split(" ", 1)[1], request_id)
    raise UnauthorizedError("Authentication required")


def get_tenant_actor(
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> TenantActor:
    tenant_id = x_tenant_id
    if not tenant_id:
        if len(actor.tenant_ids) == 1:
            tenant_id = actor.tenant_ids[0]
        else:
            raise UnauthorizedError("X-Tenant-ID is required")
    return bind_tenant(db, actor, tenant_id)


class Permission:
    def __init__(self, permission: str) -> None:
        self.permission = permission

    def __call__(self, actor: TenantActor = Depends(get_tenant_actor)) -> TenantActor:
        require_permission(actor, self.permission)
        return actor
