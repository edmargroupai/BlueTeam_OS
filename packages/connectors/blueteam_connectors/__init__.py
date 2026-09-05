"""Connector framework — vendor adapters behind a policy-aware interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from blueteam_common.errors import BlueTeamError
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_endpoint.normalize import normalize_wazuh
from blueteam_schemas.events import CanonicalEvent


@dataclass
class ConnectorHealth:
    connector_id: str
    name: str
    status: str
    agents_total: int = 0
    agents_active: int = 0
    last_event_at: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "connector_id": self.connector_id,
            "name": self.name,
            "status": self.status,
            "agents_total": self.agents_total,
            "agents_active": self.agents_active,
            "last_event_at": self.last_event_at,
            "details": self.details,
        }


@dataclass
class EndpointActionRequest:
    action: str
    agent_id: str
    params: dict[str, Any] = field(default_factory=dict)
    dry_run: bool = True


@dataclass
class EndpointActionResult:
    action_id: str
    action: str
    agent_id: str
    status: str
    policy: str
    message: str
    outputs: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "action": self.action,
            "agent_id": self.agent_id,
            "status": self.status,
            "policy": self.policy,
            "message": self.message,
            "outputs": self.outputs,
        }


class Connector(Protocol):
    connector_id: str
    name: str

    def normalize_alert(self, raw: dict[str, Any], tenant_id: str) -> CanonicalEvent: ...

    def health(self, events: list[CanonicalEvent]) -> ConnectorHealth: ...

    def inventory(self, events: list[CanonicalEvent]) -> list[dict]: ...

    def request_action(self, request: EndpointActionRequest) -> EndpointActionResult: ...


# High-impact endpoint actions are never executed here — policy engine must approve.
BLOCKED_ACTIONS = frozenset(
    {
        "isolate_host",
        "kill_process",
        "wipe_disk",
        "disable_account",
        "block_ip",
    }
)
READ_ONLY_ACTIONS = frozenset({"collect_processes", "collect_logs", "agent_status", "list_agents"})


class WazuhConnector:
    connector_id = "wazuh"
    name = "Wazuh"

    def normalize_alert(self, raw: dict[str, Any], tenant_id: str) -> CanonicalEvent:
        stamped = dict(raw)
        stamped.setdefault("source", "wazuh")
        return normalize_wazuh(stamped, tenant_id)

    def health(self, events: list[CanonicalEvent]) -> ConnectorHealth:
        wazuh_events = [item for item in events if item.source == "wazuh" or item.attributes.get("wazuh_rule_id")]
        agents = self.inventory(events)
        active = sum(1 for agent in agents if agent.get("status") == "active")
        last = max((item.timestamp for item in wazuh_events), default=None)
        status = "healthy" if wazuh_events else "awaiting_telemetry"
        return ConnectorHealth(
            connector_id=self.connector_id,
            name=self.name,
            status=status,
            agents_total=len(agents),
            agents_active=active,
            last_event_at=last.isoformat() if last else None,
            details={"events_seen": len(wazuh_events)},
        )

    def inventory(self, events: list[CanonicalEvent]) -> list[dict]:
        by_agent: dict[str, dict] = {}
        for event in events:
            if event.source != "wazuh" and not event.attributes.get("wazuh_rule_id"):
                continue
            agent_id = (event.host.id if event.host else None) or (event.host.name if event.host else None) or "unknown"
            agent_name = (event.host.name if event.host else None) or agent_id
            row = by_agent.setdefault(
                str(agent_id),
                {
                    "agent_id": str(agent_id),
                    "name": agent_name,
                    "status": "active",
                    "last_seen": event.timestamp.isoformat(),
                    "event_count": 0,
                    "alerts": 0,
                },
            )
            row["event_count"] += 1
            row["last_seen"] = event.timestamp.isoformat()
            if int(event.attributes.get("wazuh_rule_id") or 0) or event.severity in {"high", "critical"}:
                row["alerts"] += 1
        return sorted(by_agent.values(), key=lambda item: item["name"])

    def alerts(self, events: list[CanonicalEvent]) -> list[dict]:
        items = []
        for event in events:
            if event.source != "wazuh" and not event.attributes.get("wazuh_rule_id"):
                continue
            items.append(
                {
                    "event_id": event.id,
                    "timestamp": event.timestamp.isoformat(),
                    "host": event.host.name if event.host else None,
                    "rule_id": event.attributes.get("wazuh_rule_id"),
                    "action": event.action,
                    "severity": event.severity,
                    "user": event.user.name if event.user else None,
                }
            )
        return items

    def request_action(self, request: EndpointActionRequest) -> EndpointActionResult:
        action_id = new_id("wxa")
        if request.action in BLOCKED_ACTIONS:
            return EndpointActionResult(
                action_id=action_id,
                action=request.action,
                agent_id=request.agent_id,
                status="denied",
                policy="REQUIRE_POLICY_ENGINE",
                message="High-impact endpoint actions require the policy engine; connector refuses direct execution.",
            )
        if request.action not in READ_ONLY_ACTIONS:
            raise BlueTeamError("UNSUPPORTED_ACTION", f"Unknown endpoint action {request.action}", 422)
        if not request.dry_run:
            return EndpointActionResult(
                action_id=action_id,
                action=request.action,
                agent_id=request.agent_id,
                status="awaiting_approval",
                policy="REQUIRE_APPROVAL",
                message="Live endpoint actions are not executed by the connector without broker/policy approval.",
            )
        return EndpointActionResult(
            action_id=action_id,
            action=request.action,
            agent_id=request.agent_id,
            status="planned",
            policy="ALLOW_DRY_RUN",
            message="Dry-run accepted.",
            outputs={"planned_at": utcnow().isoformat(), "params": request.params},
        )


def get_connector(connector_id: str) -> WazuhConnector:
    if connector_id != "wazuh":
        raise BlueTeamError("UNKNOWN_CONNECTOR", f"Connector {connector_id} is not registered", 404)
    return WazuhConnector()
