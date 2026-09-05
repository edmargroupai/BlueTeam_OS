"""Route raw payloads to the correct source adapter. Generic JSON remains the default."""

from __future__ import annotations

from typing import Any

from blueteam_schemas.events import CanonicalEvent


def normalize_payload(payload: dict[str, Any], tenant_id: str) -> CanonicalEvent:
    adapter = str(payload.get("adapter") or "").lower()
    if payload.get("syslog_raw") or adapter == "syslog":
        from blueteam_ingest.syslog import parse_syslog_line

        raw = str(payload.get("syslog_raw") or payload.get("message") or "")
        return parse_syslog_line(raw, tenant_id)
    if adapter == "zeek" or payload.get("_path"):
        from blueteam_network.normalize import normalize_zeek

        return normalize_zeek(payload, tenant_id)
    if adapter == "suricata":
        from blueteam_network.normalize import normalize_suricata

        return normalize_suricata(payload, tenant_id)
    if adapter in {"sysmon", "wazuh", "osquery", "linux-audit", "audit", "auditd"}:
        from blueteam_endpoint.normalize import normalize_endpoint

        stamped = dict(payload)
        stamped.setdefault("source", adapter)
        return normalize_endpoint(stamped, tenant_id)

    from app.services.normalizer import normalize_generic

    return normalize_generic(payload, tenant_id)
