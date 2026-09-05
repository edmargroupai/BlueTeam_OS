from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_actor
from app.models.identity import Membership
from app.services.audit import write_audit
from app.services.auth import Actor, authenticate_password, issue_token

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1)


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    try:
        user = authenticate_password(db, body.email, body.password)
    except Exception:
        write_audit(
            db,
            tenant_id=None,
            actor_type="user",
            actor_id=body.email,
            request_id=getattr(request.state, "request_id", "unknown"),
            action="auth.login",
            target_type="user",
            result="denied",
            reason="invalid credentials",
        )
        raise
    token = issue_token(db, user)
    tenant_ids = [
        row.tenant_id
        for row in db.execute(select(Membership).where(Membership.user_id == user.id)).scalars().all()
    ]
    if not tenant_ids:
        tenant_ids = [None]
    for tenant_id in tenant_ids:
        write_audit(
            db,
            tenant_id=tenant_id,
            actor_type="user",
            actor_id=user.id,
            request_id=getattr(request.state, "request_id", "unknown"),
            action="auth.login",
            target_type="user",
            target_id=user.id,
            result="success",
        )
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "is_platform_admin": user.is_platform_admin,
        },
    }


@router.get("/me")
def me(actor: Actor = Depends(get_actor)) -> dict:
    return {
        "id": actor.user_id,
        "email": actor.email,
        "display_name": actor.display_name,
        "is_platform_admin": actor.is_platform_admin,
        "tenant_ids": actor.tenant_ids,
        "actor_type": actor.actor_type,
    }
