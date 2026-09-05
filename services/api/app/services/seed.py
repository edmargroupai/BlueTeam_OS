from __future__ import annotations

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import hash_password
from app.models.identity import Membership, Tenant, User
from app.services.audit import write_audit

PLATFORM_TENANT_ID = "ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DEMO_TENANT_ID = "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def seed_if_empty(db: Session) -> None:
    settings = get_settings()
    if settings.is_production or not settings.dev_seed:
        return
    if db.execute(select(Tenant).limit(1)).scalar_one_or_none():
        return

    now = utcnow()
    platform = Tenant(id=PLATFORM_TENANT_ID, slug="platform", name="Platform", status="active", created_at=now)
    demo = Tenant(id=DEMO_TENANT_ID, slug="demo", name="Demo SOC", status="active", created_at=now)
    db.add_all([platform, demo])

    operator_email = settings.dev_operator_email.strip().lower()
    users = [
        (operator_email, "Primary Operator", True, [(PLATFORM_TENANT_ID, "platform_super_admin"), (DEMO_TENANT_ID, "tenant_owner")]),
        ("platform@blueteam.local", "Platform Admin", True, [(PLATFORM_TENANT_ID, "platform_super_admin")]),
        ("owner@demo.blueteam.local", "Demo Owner", False, [(DEMO_TENANT_ID, "tenant_owner")]),
        ("analyst@demo.blueteam.local", "Demo Analyst", False, [(DEMO_TENANT_ID, "analyst")]),
        ("hunter@demo.blueteam.local", "Demo Hunter", False, [(DEMO_TENANT_ID, "threat_hunter")]),
        ("detector@demo.blueteam.local", "Demo Detection Engineer", False, [(DEMO_TENANT_ID, "detection_engineer")]),
        ("auditor@demo.blueteam.local", "Demo Auditor", False, [(DEMO_TENANT_ID, "auditor")]),
    ]
    # Avoid duplicate rows if operator email collides with a demo account.
    seen: set[str] = set()
    password_hash = hash_password(settings.dev_password)
    for email, name, is_admin, roles in users:
        if email in seen:
            continue
        seen.add(email)
        user = User(
            id=new_id("usr"),
            email=email,
            display_name=name,
            password_hash=password_hash,
            status="active",
            is_platform_admin=is_admin,
            created_at=now,
        )
        db.add(user)
        db.flush()
        for tenant_id, role_key in roles:
            db.add(
                Membership(
                    id=new_id("mem"),
                    tenant_id=tenant_id,
                    user_id=user.id,
                    role_key=role_key,
                    created_at=now,
                )
            )
    write_audit(
        db,
        tenant_id=DEMO_TENANT_ID,
        actor_type="system",
        actor_id="seed",
        request_id="req_seed",
        action="platform.seed",
        target_type="tenant",
        target_id=DEMO_TENANT_ID,
        reason="Development seed",
        result="success",
    )
    db.flush()


def ensure_dev_credentials(db: Session) -> None:
    """Keep local operator email/password in sync when the DB was already seeded."""
    settings = get_settings()
    if settings.is_production or not settings.dev_seed:
        return

    email = settings.dev_operator_email.strip().lower()
    if not email:
        return

    now = utcnow()
    password_hash = hash_password(settings.dev_password)
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is None:
        user = User(
            id=new_id("usr"),
            email=email,
            display_name="Primary Operator",
            password_hash=password_hash,
            status="active",
            is_platform_admin=True,
            created_at=now,
        )
        db.add(user)
        db.flush()
        demo = db.execute(select(Tenant).where(Tenant.id == DEMO_TENANT_ID)).scalar_one_or_none()
        platform = db.execute(select(Tenant).where(Tenant.id == PLATFORM_TENANT_ID)).scalar_one_or_none()
        if demo is not None:
            db.add(
                Membership(
                    id=new_id("mem"),
                    tenant_id=DEMO_TENANT_ID,
                    user_id=user.id,
                    role_key="tenant_owner",
                    created_at=now,
                )
            )
        if platform is not None:
            db.add(
                Membership(
                    id=new_id("mem"),
                    tenant_id=PLATFORM_TENANT_ID,
                    user_id=user.id,
                    role_key="platform_super_admin",
                    created_at=now,
                )
            )
    else:
        user.password_hash = password_hash
        user.status = "active"
        user.is_platform_admin = True

    # Align all active local seed users to the configured dev password.
    for existing in db.execute(select(User)).scalars().all():
        existing.password_hash = password_hash

    db.flush()
