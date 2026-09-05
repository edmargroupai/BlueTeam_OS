"""Sysmon, Wazuh, osquery, and Linux audit → CanonicalEvent. No kernel driver."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from blueteam_common.hashing import canonical_json, sha256_hex
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_schemas.events import CanonicalEvent, CanonicalFile, CanonicalHost, CanonicalProcess, CanonicalUser

ENDPOINT_TYPES = {
    "process_creation",
    "process_termination",
    "file_creation",
    "registry",
    "network",
    "service",
    "scheduled_task",
    "authentication",
    "privilege",
    "module_load",
}


def _ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _canonical(
    tenant_id: str,
    source: str,
    event_type: str,
    category: str,
    raw: dict[str, Any],
    **fields: Any,
) -> CanonicalEvent:
    return CanonicalEvent(
        id=str(raw.get("id") or new_id("evt")),
        tenant_id=tenant_id,
        timestamp=_ts(raw.get("UtcTime") or raw.get("timestamp") or raw.get("TimeCreated") or utcnow()),
        ingested_at=utcnow(),
        source=source,
        source_type="endpoint",
        event_type=event_type,
        category=category,
        schema_version="1.0.0",
        raw_event=raw,
        raw_hash=sha256_hex(canonical_json(raw)),
        **fields,
    )


def normalize_sysmon(raw: dict[str, Any], tenant_id: str) -> CanonicalEvent:
    event_id = int(raw.get("EventID") or raw.get("event_id") or 0)
    mapping = {
        1: ("process_creation", "process"),
        5: ("process_termination", "process"),
        11: ("file_creation", "file"),
        13: ("registry", "registry"),
        3: ("network", "network"),
        7: ("module_load", "module"),
    }
    event_type, category = mapping.get(event_id, ("process_creation", "process"))
    parent = CanonicalProcess(
        name=raw.get("ParentImage") or raw.get("parent_image"),
        pid=int(raw["ParentProcessId"]) if raw.get("ParentProcessId") else None,
        command_line=raw.get("ParentCommandLine"),
        path=raw.get("ParentImage"),
    )
    process = CanonicalProcess(
        name=_basename(raw.get("Image") or raw.get("process_name")),
        pid=int(raw["ProcessId"]) if raw.get("ProcessId") else None,
        command_line=raw.get("CommandLine") or raw.get("command_line"),
        path=raw.get("Image"),
        hash=raw.get("Hashes") or raw.get("hash"),
    )
    return _canonical(
        tenant_id,
        "sysmon",
        event_type,
        category,
        raw,
        process=process,
        parent_process=parent if parent.name or parent.pid else None,
        user=CanonicalUser(name=raw.get("User") or raw.get("user")),
        host=CanonicalHost(name=raw.get("Computer") or raw.get("hostname"), id=raw.get("host_id")),
        src_ip=raw.get("SourceIp") or raw.get("src_ip"),
        dst_ip=raw.get("DestinationIp") or raw.get("dst_ip"),
        src_port=raw.get("SourcePort"),
        dst_port=raw.get("DestinationPort"),
        protocol=raw.get("Protocol"),
        file=CanonicalFile(path=raw.get("TargetFilename") or raw.get("Image"), hash_sha256=raw.get("sha256")),
        action=event_type,
        attributes={
            "sysmon_event_id": str(event_id),
            "parent_pid": str(raw.get("ParentProcessId") or ""),
            "pid": str(raw.get("ProcessId") or ""),
            "raw_reference": sha256_hex(canonical_json(raw)),
        },
    )


def normalize_wazuh(raw: dict[str, Any], tenant_id: str) -> CanonicalEvent:
    data = raw.get("data") or raw
    rule = raw.get("rule") or {}
    return _canonical(
        tenant_id,
        "wazuh",
        str(data.get("event_type") or "process_creation"),
        str(data.get("category") or "process"),
        raw,
        process=CanonicalProcess(
            name=data.get("process_name"),
            command_line=data.get("command_line"),
            path=data.get("image"),
        ),
        parent_process=CanonicalProcess(name=data.get("parent_name")),
        user=CanonicalUser(name=data.get("user") or raw.get("agent", {}).get("name")),
        host=CanonicalHost(name=(raw.get("agent") or {}).get("name"), id=(raw.get("agent") or {}).get("id")),
        action=str(rule.get("description") or "wazuh"),
        severity="high" if int(rule.get("level") or 0) >= 10 else "medium",
        attributes={"wazuh_rule_id": str(rule.get("id") or ""), "raw_reference": sha256_hex(canonical_json(raw))},
    )


def normalize_osquery(raw: dict[str, Any], tenant_id: str) -> CanonicalEvent:
    name = str(raw.get("name") or raw.get("table") or "processes")
    columns = raw.get("columns") or raw
    event_type = {
        "processes": "process_creation",
        "process_events": "process_creation",
        "socket_events": "network",
        "file_events": "file_creation",
        "scheduled_tasks": "scheduled_task",
        "startup_items": "service",
        "logged_in_users": "authentication",
    }.get(name, "process_creation")
    category = "network" if event_type == "network" else ("file" if "file" in event_type else "process")
    if event_type == "scheduled_task":
        category = "persistence"
    if event_type == "authentication":
        category = "authentication"
    return _canonical(
        tenant_id,
        "osquery",
        event_type,
        category,
        raw,
        process=CanonicalProcess(
            name=columns.get("name") or columns.get("path"),
            path=columns.get("path"),
            pid=int(columns["pid"]) if columns.get("pid") else None,
        ),
        parent_process=CanonicalProcess(pid=int(columns["parent"]) if columns.get("parent") else None),
        user=CanonicalUser(name=columns.get("username") or columns.get("user")),
        host=CanonicalHost(name=raw.get("hostIdentifier") or raw.get("hostname")),
        action=name,
        attributes={"osquery_name": name, "raw_reference": sha256_hex(canonical_json(raw))},
    )


def normalize_linux_audit(raw: dict[str, Any], tenant_id: str) -> CanonicalEvent:
    event_type = str(raw.get("type") or raw.get("event_type") or "SYSCALL").lower()
    mapped = {
        "execve": ("process_creation", "process"),
        "syscall": ("process_creation", "process"),
        "user_login": ("authentication", "authentication"),
        "user_auth": ("authentication", "authentication"),
        "service_start": ("service", "persistence"),
        "user_acct": ("privilege", "identity"),
    }.get(event_type, ("process_creation", "process"))
    return _canonical(
        tenant_id,
        "linux-audit",
        mapped[0],
        mapped[1],
        raw,
        process=CanonicalProcess(
            name=raw.get("exe") or raw.get("comm"),
            command_line=raw.get("cmdline") or raw.get("a0"),
            pid=int(raw["pid"]) if raw.get("pid") else None,
        ),
        parent_process=CanonicalProcess(pid=int(raw["ppid"]) if raw.get("ppid") else None),
        user=CanonicalUser(name=raw.get("uid") or raw.get("acct")),
        host=CanonicalHost(name=raw.get("host") or raw.get("node")),
        action=event_type,
        outcome="success" if str(raw.get("res") or "success").lower() in {"success", "yes"} else "failure",
        attributes={"audit_type": event_type, "raw_reference": sha256_hex(canonical_json(raw))},
    )


def normalize_endpoint(raw: dict[str, Any], tenant_id: str) -> CanonicalEvent:
    source = str(raw.get("source") or raw.get("encoder") or "sysmon").lower()
    if source in {"wazuh"}:
        return normalize_wazuh(raw, tenant_id)
    if source in {"osquery"}:
        return normalize_osquery(raw, tenant_id)
    if source in {"audit", "linux-audit", "auditd"}:
        return normalize_linux_audit(raw, tenant_id)
    return normalize_sysmon(raw, tenant_id)


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("\\", "/").rsplit("/", 1)[-1]
