from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class Tenant(BaseModel):
    id: str
    slug: str
    name: str
    status: str
    created_at: datetime


class User(BaseModel):
    id: str
    email: EmailStr
    display_name: str
    status: str
    is_platform_admin: bool = False
    created_at: datetime


class Permission(BaseModel):
    key: str
    description: str


class Role(BaseModel):
    key: str
    name: str
    description: str
    permissions: list[str] = Field(default_factory=list)


class Membership(BaseModel):
    id: str
    tenant_id: str
    user_id: str
    role_key: str
    created_at: datetime
