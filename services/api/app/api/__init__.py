from fastapi import APIRouter

from app.api import (
    alerts,
    audit,
    auth,
    blue_range,
    broker,
    command,
    detections,
    events,
    evidence,
    graph,
    health,
    hunts,
    incidents,
    intel,
    investigate,
    languages,
    quality,
    tenants,
)

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(tenants.router)
api_router.include_router(audit.router)
api_router.include_router(events.router)
api_router.include_router(detections.router)
api_router.include_router(alerts.router)
api_router.include_router(evidence.router)
api_router.include_router(quality.router)
api_router.include_router(blue_range.router)
api_router.include_router(command.router)
api_router.include_router(languages.router)
api_router.include_router(hunts.router)
api_router.include_router(intel.router)
api_router.include_router(broker.router)
api_router.include_router(investigate.router)
api_router.include_router(graph.router)
api_router.include_router(incidents.router)
