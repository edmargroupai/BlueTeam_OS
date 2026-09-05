"""Zeek JSON and Suricata EVE → CanonicalEvent. Raw reference is preserved."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from blueteam_common.hashing import canonical_json, sha256_hex
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_schemas.events import CanonicalEvent, CanonicalFile, CanonicalHost
from blueteam_schemas.sessions import NetworkSession

ZEEK_SOURCES = ("conn", "dns", "http", "ssl", "tls", "files", "notice")
SURICATA_SOURCES = ("alert", "flow", "dns", "http", "tls", "fileinfo")


def _ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=UTC)
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _event(
    tenant_id: str,
    source: str,
    source_type: str,
    event_type: str,
    category: str,
    raw: dict[str, Any],
    **fields: Any,
) -> CanonicalEvent:
    event_id = str(raw.get("uid") or raw.get("flow_id") or raw.get("id") or new_id("evt"))
    if not event_id.startswith("evt_"):
        event_id = new_id("evt")
    timestamp = _ts(raw.get("ts") or raw.get("timestamp") or utcnow())
    payload = CanonicalEvent(
        id=event_id,
        tenant_id=tenant_id,
        timestamp=timestamp,
        ingested_at=utcnow(),
        source=source,
        source_type=source_type,
        event_type=event_type,
        category=category,
        schema_version="1.0.0",
        raw_event=raw,
        raw_hash=sha256_hex(canonical_json(raw)),
        **fields,
    )
    return payload


def normalize_zeek(raw: dict[str, Any], tenant_id: str, *, log_type: str | None = None) -> CanonicalEvent:
    kind = (log_type or raw.get("_path") or raw.get("log_type") or "conn").lower()
    if kind not in ZEEK_SOURCES:
        raise ValueError(f"unsupported Zeek log type {kind}")
    src = raw.get("id.orig_h") or raw.get("orig_h") or (raw.get("id") or {}).get("orig_h")
    dst = raw.get("id.resp_h") or raw.get("resp_h") or (raw.get("id") or {}).get("resp_h")
    sport = raw.get("id.orig_p") or raw.get("orig_p") or (raw.get("id") or {}).get("orig_p")
    dport = raw.get("id.resp_p") or raw.get("resp_p") or (raw.get("id") or {}).get("resp_p")
    proto = raw.get("proto") or raw.get("protocol")
    category = {
        "conn": "network",
        "dns": "dns",
        "http": "http",
        "ssl": "tls",
        "tls": "tls",
        "files": "file",
        "notice": "notice",
    }[kind]
    file_obj = None
    if kind == "files":
        hashes = raw.get("sha256") or raw.get("md5")
        file_obj = CanonicalFile(path=raw.get("filename"), hash_sha256=raw.get("sha256"), hash_md5=raw.get("md5"))
        raw = {**raw, "file_hash": hashes}
    return _event(
        tenant_id,
        f"zeek.{kind}",
        "zeek",
        kind,
        category,
        raw,
        src_ip=src,
        dst_ip=dst,
        src_port=int(sport) if sport else None,
        dst_port=int(dport) if dport else None,
        protocol=str(proto) if proto else None,
        domain=raw.get("query") or raw.get("server_name") or raw.get("host"),
        url=raw.get("uri"),
        file=file_obj,
        host=CanonicalHost(ip=src) if src else None,
        action=raw.get("note") or raw.get("method") or kind,
        outcome="failure" if raw.get("rcode_name") in {"NXDOMAIN", "SERVFAIL"} else "success",
        attributes={
            "zeek_uid": str(raw.get("uid") or ""),
            "bytes_out": str(raw.get("orig_bytes") or raw.get("request_body_len") or ""),
            "bytes_in": str(raw.get("resp_bytes") or raw.get("response_body_len") or ""),
            "raw_reference": sha256_hex(canonical_json(raw)),
        },
    )


def normalize_suricata(raw: dict[str, Any], tenant_id: str) -> CanonicalEvent:
    kind = str(raw.get("event_type") or "").lower()
    if kind not in SURICATA_SOURCES:
        raise ValueError(f"unsupported Suricata event_type {kind}")
    src = raw.get("src_ip")
    dst = raw.get("dest_ip")
    alert = raw.get("alert") or {}
    category = "alert" if kind == "alert" else ("network" if kind == "flow" else kind)
    severity = {1: "high", 2: "medium", 3: "low"}.get(int(alert.get("severity") or 3), "low")
    fileinfo = raw.get("fileinfo") or {}
    file_obj = None
    if kind == "fileinfo" or fileinfo:
        file_obj = CanonicalFile(
            path=fileinfo.get("filename"),
            size=fileinfo.get("size"),
            hash_sha256=fileinfo.get("sha256"),
            hash_md5=fileinfo.get("md5"),
        )
    return _event(
        tenant_id,
        f"suricata.{kind}",
        "suricata",
        kind,
        category,
        raw,
        src_ip=src,
        dst_ip=dst,
        src_port=raw.get("src_port"),
        dst_port=raw.get("dest_port"),
        protocol=raw.get("proto"),
        domain=(
            (raw.get("dns") or {}).get("rrname")
            or (raw.get("tls") or {}).get("sni")
            or (raw.get("http") or {}).get("hostname")
        ),
        url=(raw.get("http") or {}).get("url"),
        file=file_obj,
        host=CanonicalHost(ip=src) if src else None,
        action=alert.get("signature") or kind,
        severity=severity if kind == "alert" else "informational",
        confidence=70 if kind == "alert" else 100,
        attributes={
            "suricata_flow_id": str(raw.get("flow_id") or ""),
            "signature": str(alert.get("signature") or ""),
            "signature_id": str(alert.get("signature_id") or ""),
            "category": str(alert.get("category") or ""),
            "confirmed_compromise": "false",
            "raw_reference": sha256_hex(canonical_json(raw)),
        },
    )


def parse_json_lines(text: str, tenant_id: str, *, source: str) -> list[CanonicalEvent]:
    events: list[CanonicalEvent] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        if source == "zeek":
            events.append(normalize_zeek(raw, tenant_id))
        else:
            events.append(normalize_suricata(raw, tenant_id))
    return events


def sessions_from_events(events: list[CanonicalEvent]) -> list[NetworkSession]:
    buckets: dict[str, list[CanonicalEvent]] = {}
    for event in events:
        if not event.src_ip or not event.dst_ip:
            continue
        key = "|".join(
            [
                event.tenant_id,
                event.src_ip,
                event.dst_ip,
                event.protocol or "",
                str(event.dst_port or ""),
            ]
        )
        buckets.setdefault(key, []).append(event)
    sessions: list[NetworkSession] = []
    for key, group in buckets.items():
        group = sorted(group, key=lambda item: item.timestamp)
        first, last = group[0], group[-1]
        duration = int((last.timestamp - first.timestamp).total_seconds() * 1000)
        zeek_refs = [item.id for item in group if item.source_type == "zeek"]
        suricata_refs = [item.id for item in group if item.source_type == "suricata"]
        sessions.append(
            NetworkSession(
                session_id=f"ses_{sha256_hex(key)[:24]}",
                tenant_id=first.tenant_id,
                src=first.src_ip or "",
                dst=first.dst_ip or "",
                protocol=first.protocol or "",
                start=first.timestamp,
                end=last.timestamp,
                duration_ms=max(duration, 0),
                bytes_out=sum(int(item.attributes.get("bytes_out") or 0) for item in group),
                bytes_in=sum(int(item.attributes.get("bytes_in") or 0) for item in group),
                packets=len(group),
                dns=sorted({item.domain for item in group if item.domain and item.category == "dns"}),
                tls=sorted({item.domain for item in group if item.domain and item.category == "tls"}),
                http=sorted({item.url for item in group if item.url}),
                zeek_refs=zeek_refs,
                suricata_refs=suricata_refs,
                risk=80 if any(item.category == "alert" for item in group) else 10,
            )
        )
    return sessions
