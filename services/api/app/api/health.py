from __future__ import annotations

from blueteam_dataplane.probes import probe_all
from blueteam_dataplane.retention import RetentionPolicy
from fastapi import APIRouter

from app.core.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    settings = get_settings()
    plane = probe_all(settings)
    postgres = plane["probes"]["postgres"]
    status = "ok" if postgres["connected"] else "degraded"
    policy = RetentionPolicy(
        events_days=settings.retention_events_days,
        dead_letter_days=settings.retention_dead_letter_days,
        findings_days=settings.retention_findings_days,
    )
    return {
        "status": status,
        "service": "blueteam-api",
        "ai_enabled": settings.ai_enabled,
        "ai_required": False,
        "database_backend": postgres["backend"],
        "supabase_configured": bool(settings.supabase_url),
        "data_plane": plane["probes"],
        "data_plane_connected": plane["connected"],
        "all_configured_connected": plane["all_configured_connected"],
        "retention": policy.as_dict(),
    }
