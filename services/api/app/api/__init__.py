from fastapi import APIRouter

from app.api import (
    ai_analyst,
    alerts,
    architecture,
    attack,
    audit,
    auth,
    blue_range,
    broker,
    command,
    connectors,
    detections,
    dfir,
    events,
    evidence,
    graph,
    health,
    hunts,
    improve,
    incidents,
    intel,
    investigate,
    languages,
    observability,
    playbooks,
    quality,
    readiness,
    replay,
    telemetry,
    tenants,
    vulns,
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
api_router.include_router(attack.router)
api_router.include_router(connectors.router)
api_router.include_router(vulns.router)
api_router.include_router(telemetry.router)
api_router.include_router(playbooks.router)
api_router.include_router(replay.router)
api_router.include_router(improve.router)
api_router.include_router(ai_analyst.router)
api_router.include_router(dfir.router)
api_router.include_router(architecture.router)
api_router.include_router(readiness.router)
api_router.include_router(broker.router)
api_router.include_router(investigate.router)
api_router.include_router(graph.router)
api_router.include_router(incidents.router)
# Observability metrics are mounted at /metrics (and snapshot under /api/v1).
api_router.include_router(observability.router)
