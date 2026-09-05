from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission, get_actor
from app.domain.permissions import ROLE_CATALOG
from app.models.identity import Membership, Tenant, User
from app.services.auth import Actor, TenantActor

router = APIRouter(tags=["tenants"])


@router.get("/tenants")
def list_tenants(actor: Actor = Depends(get_actor), db: Session = Depends(get_db)) -> dict:
    stmt = select(Tenant)
    if not actor.is_platform_admin:
        stmt = stmt.where(Tenant.id.in_(actor.tenant_ids or ["__none__"]))
    rows = db.execute(stmt.order_by(Tenant.name.asc())).scalars().all()
    return {
        "items": [
            {"id": row.id, "slug": row.slug, "name": row.name, "status": row.status} for row in rows
        ]
    }


@router.get("/roles")
def list_roles(_: TenantActor = Depends(Permission("roles:read"))) -> dict:
    return {
        "items": [
            {
                "key": role.key,
                "name": role.name,
                "description": role.description,
                "permissions": list(role.permissions),
            }
            for role in ROLE_CATALOG.values()
        ]
    }


@router.get("/users")
def list_users(
    actor: TenantActor = Depends(Permission("users:read")),
    db: Session = Depends(get_db),
) -> dict:
    memberships = db.execute(select(Membership).where(Membership.tenant_id == actor.tenant_id)).scalars().all()
    users = []
    for membership in memberships:
        user = db.get(User, membership.user_id)
        if user:
            users.append(
                {
                    "id": user.id,
                    "email": user.email,
                    "display_name": user.display_name,
                    "role_key": membership.role_key,
                    "status": user.status,
                }
            )
    return {"items": users}
