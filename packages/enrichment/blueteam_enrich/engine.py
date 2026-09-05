"""Deterministic enrichment. No live vendor lookups. Unknown stays unknown."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Any

from blueteam_schemas.events import CanonicalEvent, CanonicalHost, CanonicalIdentity, CanonicalUser

PRIVATE_NETS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
)

# Fixture GeoIP only. This is not MaxMind and must not be treated as a live feed.
GEOIP_FIXTURES: dict[str, dict[str, str]] = {
    "8.8.8.8": {"country": "US", "asn": "AS15169", "org": "Google"},
    "1.1.1.1": {"country": "AU", "asn": "AS13335", "org": "Cloudflare"},
    "203.0.113.77": {"country": "ZZ", "asn": "AS64500", "org": "TEST-NET-3"},
    "198.51.100.10": {"country": "ZZ", "asn": "AS64500", "org": "TEST-NET-2"},
}

DEFAULT_ASSETS: dict[str, dict[str, str]] = {
    "ws-office-01": {"criticality": "high", "owner": "finance", "role": "workstation"},
    "dc-01": {"criticality": "critical", "owner": "identity", "role": "domain-controller"},
}

DEFAULT_DIRECTORY: dict[str, dict[str, str]] = {
    "alice": {"id": "usr_alice", "department": "finance", "type": "human"},
    "bob": {"id": "usr_bob", "department": "engineering", "type": "human"},
    "svc-backup": {"id": "usr_svc_backup", "department": "platform", "type": "service"},
}

DEFAULT_INTEL: dict[str, dict[str, str]] = {
    "198.51.100.10": {"rule_id": "intel.known_c2", "type": "ip", "confidence": "high"},
    "evil.example": {"rule_id": "intel.known_c2", "type": "domain", "confidence": "high"},
}


@dataclass
class EnrichmentResult:
    applied: list[str] = field(default_factory=list)
    geo: dict[str, str] = field(default_factory=dict)
    asset: dict[str, str] = field(default_factory=dict)
    identity: dict[str, str] = field(default_factory=dict)
    intel: dict[str, str] = field(default_factory=dict)


def _geo_for(ip: str | None) -> dict[str, str]:
    if not ip:
        return {}
    if ip in GEOIP_FIXTURES:
        return dict(GEOIP_FIXTURES[ip])
    try:
        addr = ip_address(ip)
    except ValueError:
        return {"country": "unknown", "reason": "unparseable_ip"}
    if any(addr in net for net in PRIVATE_NETS):
        return {"country": "private", "asn": "RFC1918", "org": "private"}
    return {"country": "unknown"}


def enrich_event(
    event: CanonicalEvent,
    *,
    assets: dict[str, dict[str, str]] | None = None,
    directory: dict[str, dict[str, str]] | None = None,
    intel: dict[str, dict[str, str]] | None = None,
) -> tuple[CanonicalEvent, EnrichmentResult]:
    result = EnrichmentResult()
    assets = assets if assets is not None else DEFAULT_ASSETS
    directory = directory if directory is not None else DEFAULT_DIRECTORY
    intel = intel if intel is not None else DEFAULT_INTEL

    geo = _geo_for(event.src_ip) or _geo_for(event.dst_ip)
    if geo:
        result.geo = geo
        result.applied.append("geoip")
        event.attributes["geoip"] = geo

    host_key = (event.host.name if event.host else None) or event.src_ip
    if host_key and host_key in assets:
        result.asset = dict(assets[host_key])
        result.applied.append("asset")
        event.attributes["asset"] = result.asset
        if event.host is None:
            event.host = CanonicalHost(name=host_key)
        if not event.host.os and result.asset.get("role"):
            event.attributes["asset_role"] = result.asset["role"]

    user_name = event.user.name if event.user and event.user.name else None
    if user_name and user_name in directory:
        result.identity = dict(directory[user_name])
        result.applied.append("identity")
        event.attributes["identity_enrichment"] = result.identity
        event.identity = CanonicalIdentity(
            id=result.identity.get("id"),
            type=result.identity.get("type"),
            provider="directory-fixture",
        )
        if event.user is None:
            event.user = CanonicalUser(name=user_name)
        event.user.id = result.identity.get("id")

    indicators = [event.src_ip, event.dst_ip, event.domain, event.hash]
    for indicator in indicators:
        if indicator and indicator in intel:
            result.intel = dict(intel[indicator])
            result.intel["indicator"] = indicator
            result.applied.append("intel")
            event.attributes["intel"] = result.intel
            break

    event.attributes["enrichment_applied"] = ",".join(result.applied)
    return event, result


def schema_drift(payload: dict[str, Any], event: CanonicalEvent) -> list[str]:
    """Fields present on the raw payload that did not map onto canonical columns."""

    mapped = {
        "id",
        "tenant_id",
        "timestamp",
        "time",
        "@timestamp",
        "event_time",
        "source",
        "source_type",
        "event_type",
        "type",
        "category",
        "user",
        "username",
        "src_ip",
        "dst_ip",
        "action",
        "outcome",
        "adapter",
        "schema_version",
        "raw_event",
    }
    return [key for key in payload if key not in mapped and key not in event.attributes]
