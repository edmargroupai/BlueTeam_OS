from __future__ import annotations

from dataclasses import dataclass

from blueteam_common.errors import PermissionDeniedError, UnauthorizedError
from blueteam_common.hashing import sha256_hex
from jwt import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, decode_token, verify_password
from app.domain.permissions import permissions_for_roles
from app.models.identity import ApiKey, Membership, User


@dataclass
class Actor:
    user_id: str
    email: str | None
    display_name: str
    is_platform_admin: bool
    tenant_ids: list[str]
    actor_type: str
    request_id: str


@dataclass
class TenantActor(Actor):
    tenant_id: str
    role_keys: list[str]
    permissions: set[str]


def authenticate_password(db: Session, email: str, password: str) -> User:
    user = db.execute(select(User).where(User.email == email.lower())).scalar_one_or_none()
    if user is None or user.status != "active" or not verify_password(password, user.password_hash):
        raise UnauthorizedError("Invalid credentials")
    return user


def issue_token(db: Session, user: User) -> str:
    memberships = db.execute(select(Membership).where(Membership.user_id == user.id)).scalars().all()
    tenant_ids = sorted({item.tenant_id for item in memberships})
    return create_access_token(
        subject=user.id,
        tenant_ids=tenant_ids,
        is_platform_admin=user.is_platform_admin,
    )


def actor_from_bearer(db: Session, token: str, request_id: str) -> Actor:
    try:
        payload = decode_token(token)
    except InvalidTokenError as exc:
        raise UnauthorizedError("Invalid token") from exc
    user = db.get(User, payload.get("sub"))
    if user is None or user.status != "active":
        raise UnauthorizedError("Invalid token subject")
    memberships = db.execute(select(Membership).where(Membership.user_id == user.id)).scalars().all()
    return Actor(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        is_platform_admin=user.is_platform_admin,
        tenant_ids=sorted({item.tenant_id for item in memberships}),
        actor_type="user",
        request_id=request_id,
    )


def actor_from_api_key(db: Session, raw_key: str, request_id: str) -> Actor:
    digest = sha256_hex(raw_key)
    key = db.execute(select(ApiKey).where(ApiKey.key_hash == digest, ApiKey.status == "active")).scalar_one_or_none()
    if key is None:
        raise UnauthorizedError("Invalid API key")
    return Actor(
        user_id=key.id,
        email=None,
        display_name=key.name,
        is_platform_admin=False,
        tenant_ids=[key.tenant_id],
        actor_type="api_key",
        request_id=request_id,
    )


def bind_tenant(db: Session, actor: Actor, tenant_id: str) -> TenantActor:
    if tenant_id not in actor.tenant_ids and not actor.is_platform_admin:
        raise PermissionDeniedError("Cross-tenant access denied")
    memberships = db.execute(
        select(Membership).where(Membership.user_id == actor.user_id, Membership.tenant_id == tenant_id)
    ).scalars().all()
    if actor.actor_type == "api_key":
        role_keys = ["detection_engineer"]
    elif actor.is_platform_admin and not memberships:
        role_keys = ["platform_super_admin"]
    else:
        role_keys = [item.role_key for item in memberships]
    if not role_keys and not actor.is_platform_admin:
        raise PermissionDeniedError("No membership in tenant")
    return TenantActor(
        user_id=actor.user_id,
        email=actor.email,
        display_name=actor.display_name,
        is_platform_admin=actor.is_platform_admin,
        tenant_ids=actor.tenant_ids,
        actor_type=actor.actor_type,
        request_id=actor.request_id,
        tenant_id=tenant_id,
        role_keys=role_keys,
        permissions=permissions_for_roles(role_keys),
    )


def require_permission(actor: TenantActor, permission: str) -> None:
    if actor.is_platform_admin:
        return
    if permission not in actor.permissions:
        raise PermissionDeniedError(f"Missing permission {permission}")
