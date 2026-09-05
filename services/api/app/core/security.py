from __future__ import annotations

from datetime import timedelta
from typing import Any

import bcrypt
import jwt
from blueteam_common.time import utcnow

from app.core.config import get_settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(
    *,
    subject: str,
    tenant_ids: list[str],
    is_platform_admin: bool,
    extra: dict[str, Any] | None = None,
) -> str:
    settings = get_settings()
    now = utcnow()
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_minutes)).timestamp()),
        "tenant_ids": tenant_ids,
        "is_platform_admin": is_platform_admin,
        "typ": "access",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])
