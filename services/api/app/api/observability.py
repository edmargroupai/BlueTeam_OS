from __future__ import annotations

from blueteam_obs import METRICS
from fastapi import APIRouter, Depends, Response

from app.core.deps import Permission
from app.services.auth import TenantActor

router = APIRouter(prefix="/observability", tags=["observability"])


@router.get("/metrics")
def prometheus_metrics(_: TenantActor = Depends(Permission("quality:read"))) -> Response:
    METRICS.gauge("btos_up", 1)
    return Response(content=METRICS.as_prometheus(), media_type="text/plain; version=0.0.4")


@router.get("/snapshot")
def observability_snapshot(_: TenantActor = Depends(Permission("quality:read"))) -> dict:
    return METRICS.snapshot()
