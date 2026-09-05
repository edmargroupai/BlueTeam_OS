"""DFIR workbench helpers — timelines, artefacts, export manifests."""

from __future__ import annotations

from typing import Any

from blueteam_schemas.events import CanonicalEvent


def host_timeline(events: list[CanonicalEvent], host: str | None = None) -> list[dict]:
    rows = []
    for event in events:
        host_name = event.host.name if event.host else None
        if host and host_name != host and event.src_ip != host:
            continue
        rows.append(
            {
                "event_id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "category": event.category,
                "action": event.action,
                "host": host_name,
                "user": event.user.name if event.user else None,
                "file_hash": event.file.hash_sha256 if event.file else None,
            }
        )
    return sorted(rows, key=lambda item: item["timestamp"])


def network_timeline(events: list[CanonicalEvent]) -> list[dict]:
    rows = []
    for event in events:
        if event.source_type not in {"zeek", "suricata", "network"} and event.category not in {
            "dns",
            "http",
            "tls",
            "network",
            "alert",
        }:
            continue
        rows.append(
            {
                "event_id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "category": event.category,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "domain": event.domain,
                "url": event.url,
            }
        )
    return sorted(rows, key=lambda item: item["timestamp"])


def file_artefacts(events: list[CanonicalEvent]) -> list[dict]:
    seen: dict[str, dict[str, Any]] = {}
    for event in events:
        if not event.file:
            continue
        key = event.file.hash_sha256 or event.file.path or event.id
        seen[str(key)] = {
            "path": event.file.path,
            "hash_sha256": event.file.hash_sha256,
            "hash_md5": event.file.hash_md5,
            "size": event.file.size,
            "event_id": event.id,
            "timestamp": event.timestamp.isoformat(),
        }
    return list(seen.values())


def browser_artefact_contract() -> dict:
    return {
        "adapter": "browser",
        "status": "contract_only",
        "fields": ["url", "title", "visit_time", "profile"],
        "note": "No live browser collector in this slice.",
    }


def memory_artefact_contract() -> dict:
    return {
        "adapter": "memory",
        "status": "contract_only",
        "interfaces": ["volatility", "velociraptor"],
        "note": "Memory analysis is an adapter contract only — no kernel agent.",
    }
