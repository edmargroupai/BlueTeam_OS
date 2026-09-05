"""Canonical security event schema. Every source maps here before detection."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "1.0.0"

Severity = Literal["informational", "low", "medium", "high", "critical"]
Outcome = Literal["success", "failure", "unknown"]


class CanonicalUser(BaseModel):
    name: str | None = None
    id: str | None = None
    email: str | None = None
    domain: str | None = None


class CanonicalHost(BaseModel):
    name: str | None = None
    id: str | None = None
    os: str | None = None
    ip: str | None = None


class CanonicalProcess(BaseModel):
    name: str | None = None
    pid: int | None = None
    command_line: str | None = None
    hash: str | None = None
    path: str | None = None


class CanonicalFile(BaseModel):
    name: str | None = None
    path: str | None = None
    hash_md5: str | None = None
    hash_sha1: str | None = None
    hash_sha256: str | None = None
    size: int | None = None


class CanonicalIdentity(BaseModel):
    id: str | None = None
    type: str | None = None
    provider: str | None = None


class CanonicalCloudResource(BaseModel):
    provider: str | None = None
    account_id: str | None = None
    resource_id: str | None = None
    resource_type: str | None = None
    region: str | None = None


class CanonicalEvent(BaseModel):
    id: str
    tenant_id: str
    timestamp: datetime
    ingested_at: datetime
    source: str
    source_type: str
    event_type: str
    category: str
    user: CanonicalUser | None = None
    host: CanonicalHost | None = None
    process: CanonicalProcess | None = None
    parent_process: CanonicalProcess | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    domain: str | None = None
    url: str | None = None
    file: CanonicalFile | None = None
    hash: str | None = None
    identity: CanonicalIdentity | None = None
    cloud_resource: CanonicalCloudResource | None = None
    action: str | None = None
    outcome: Outcome | None = None
    severity: Severity = "informational"
    confidence: float = 1.0
    risk_score: float = 0.0
    raw_event: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    attributes: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = None
    correlation_id: str | None = None
    trace_id: str | None = None
    raw_hash: str | None = None

    @field_validator("confidence", "risk_score")
    @classmethod
    def _bounded(cls, value: float) -> float:
        if value < 0 or value > 100:
            raise ValueError("score must be between 0 and 100")
        return value

    @field_validator("tenant_id")
    @classmethod
    def _tenant_required(cls, value: str) -> str:
        if not value or not value.startswith("ten_"):
            raise ValueError("tenant_id must be a ten_ prefixed identifier")
        return value
