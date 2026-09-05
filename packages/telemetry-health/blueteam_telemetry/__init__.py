"""Telemetry health — silent sensors, lag, volume, drift, stale integrations."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any

from blueteam_common.time import utcnow
from blueteam_schemas.events import CanonicalEvent

EXPECTED_SOURCES = ("identity", "endpoint", "network", "zeek", "suricata", "wazuh", "azure-ad", "cloud")


def evaluate_telemetry_health(
    *,
    events: list[CanonicalEvent],
    dead_letter_count: int,
    dead_letter_reasons: list[str] | None = None,
    expected_sources: list[str] | None = None,
    lag_warn_seconds: int = 900,
    silent_seconds: int = 3600,
    volume_window_minutes: int = 60,
) -> dict[str, Any]:
    now = utcnow()
    expected = list(expected_sources or EXPECTED_SOURCES)
    by_source: dict[str, list[CanonicalEvent]] = defaultdict(list)
    for event in events:
        by_source[event.source].append(event)
        by_source[event.source_type].append(event)

    silent_sensors = []
    stale_integrations = []
    for source in expected:
        rows = by_source.get(source) or []
        if not rows:
            silent_sensors.append({"source": source, "reason": "missing_expected_data_source"})
            continue
        last = max(item.timestamp for item in rows)
        age = (now - last).total_seconds()
        if age > silent_seconds:
            silent_sensors.append({"source": source, "reason": "silent", "age_seconds": int(age)})
            stale_integrations.append({"source": source, "age_seconds": int(age)})

    lags = []
    for event in events:
        lag = (event.ingested_at - event.timestamp).total_seconds()
        if lag > lag_warn_seconds:
            lags.append({"event_id": event.id, "lag_seconds": int(lag), "source": event.source})

    window_start = now - timedelta(minutes=volume_window_minutes)
    recent = [item for item in events if item.timestamp >= window_start]
    prior_start = window_start - timedelta(minutes=volume_window_minutes)
    prior = [item for item in events if prior_start <= item.timestamp < window_start]
    volume_anomaly = None
    if prior:
        ratio = len(recent) / max(len(prior), 1)
        if ratio >= 3.0 or ratio <= 0.25:
            volume_anomaly = {
                "recent": len(recent),
                "prior": len(prior),
                "ratio": round(ratio, 3),
                "window_minutes": volume_window_minutes,
            }

    parser_failures = dead_letter_count
    schema_drift = [
        reason for reason in (dead_letter_reasons or []) if "schema" in reason.lower() or "validation" in reason.lower()
    ]

    warnings: list[dict[str, Any]] = []
    for item in silent_sensors:
        warnings.append({"kind": "silent_sensor", **item})
    if parser_failures:
        warnings.append({"kind": "parser_failures", "count": parser_failures})
    if lags:
        warnings.append({"kind": "ingestion_lag", "count": len(lags), "samples": lags[:5]})
    if volume_anomaly:
        warnings.append({"kind": "event_volume_anomaly", **volume_anomaly})
    if schema_drift:
        warnings.append({"kind": "schema_drift", "samples": schema_drift[:5]})
    for item in stale_integrations:
        warnings.append({"kind": "stale_integration", **item})

    status = "healthy" if not warnings else ("degraded" if silent_sensors or parser_failures else "warn")
    return {
        "status": status,
        "warnings": warnings,
        "counts": {
            "events": len(events),
            "sources_seen": sorted({event.source for event in events}),
            "dead_letter": dead_letter_count,
            "silent_sensors": len(silent_sensors),
            "lagging_events": len(lags),
        },
        "source_volume": dict(Counter(event.source for event in events)),
        "note": "Platform warns when required telemetry is absent or unhealthy.",
    }
