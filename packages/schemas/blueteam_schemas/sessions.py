"""First-class network session used by investigation and correlation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class NetworkSession(BaseModel):
    session_id: str
    tenant_id: str
    src: str
    dst: str
    protocol: str
    start: datetime
    end: datetime
    duration_ms: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    packets: int = 0
    dns: list[str] = Field(default_factory=list)
    tls: list[str] = Field(default_factory=list)
    http: list[str] = Field(default_factory=list)
    zeek_refs: list[str] = Field(default_factory=list)
    suricata_refs: list[str] = Field(default_factory=list)
    risk: float = 0.0
    attributes: dict[str, Any] = Field(default_factory=dict)
