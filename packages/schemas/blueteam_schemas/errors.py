from __future__ import annotations

from pydantic import BaseModel, Field


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str
    details: dict[str, str] = Field(default_factory=dict)


class ErrorEnvelope(BaseModel):
    error: ErrorBody
