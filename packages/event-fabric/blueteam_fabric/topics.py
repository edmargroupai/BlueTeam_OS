"""Versioned Redpanda/Kafka topics. Do not invent ad-hoc topic names at runtime."""

from __future__ import annotations

RAW = "telemetry.raw.v1"
NORMALIZED = "telemetry.normalized.v1"
FINDINGS = "detections.findings.v1"
CORRELATION = "correlation.candidates.v1"
INCIDENTS = "incidents.events.v1"
EVIDENCE = "evidence.created.v1"
HEALTH = "telemetry.health.v1"
DEADLETTER = "deadletter.events.v1"

ALL_TOPICS: tuple[str, ...] = (
    RAW,
    NORMALIZED,
    FINDINGS,
    CORRELATION,
    INCIDENTS,
    EVIDENCE,
    HEALTH,
    DEADLETTER,
)
