"""Cloud connector — fixture Azure AD audit adapter (first cloud only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from blueteam_common.hashing import canonical_json, sha256_hex
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_schemas.events import CanonicalEvent, CanonicalHost, CanonicalUser

RISKY_CONFIGS = (
    {
        "id": "cfg_public_storage",
        "asset": "stg-logs-prod",
        "issue": "public_blob_container",
        "severity": "high",
        "mitre": ["T1190"],
    },
    {
        "id": "cfg_admin_no_mfa",
        "asset": "role-global-admin",
        "issue": "privileged_role_without_mfa",
        "severity": "critical",
        "mitre": ["T1078"],
    },
)


@dataclass
class CloudInventory:
    identities: list[dict[str, Any]] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    risky_configs: list[dict[str, Any]] = field(default_factory=list)
    privileged_ops: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "identities": self.identities,
            "assets": self.assets,
            "risky_configs": self.risky_configs,
            "privileged_ops": self.privileged_ops,
            "public_exposure": [item for item in self.risky_configs if "public" in item.get("issue", "")],
        }


class AzureAdFixtureConnector:
    """Synthetic Azure AD / Entra audit connector. No live Microsoft Graph calls."""

    connector_id = "azure_ad"
    name = "Azure AD (fixture)"
    cloud = "azure"

    def normalize_audit(self, raw: dict[str, Any], tenant_id: str) -> CanonicalEvent:
        activity = str(raw.get("activityDisplayName") or raw.get("operationName") or raw.get("action") or "audit")
        user_name = (
            (raw.get("initiatedBy") or {}).get("user", {}).get("userPrincipalName")
            if isinstance(raw.get("initiatedBy"), dict)
            else None
        ) or raw.get("user") or raw.get("caller")
        target = raw.get("targetResources") or raw.get("resource") or {}
        if isinstance(target, list):
            target = target[0] if target else {}
        outcome = "failure" if str(raw.get("result") or "").lower() in {"failure", "failed"} else "success"
        category = "directory" if "role" in activity.lower() or "group" in activity.lower() else "authentication"
        if raw.get("category") == "audit":
            category = "cloud_audit"
        event_type = "group_change" if "Add member" in activity or "add_to_group" in activity.lower() else "login"
        if "Role" in activity or raw.get("privileged"):
            event_type = "privilege_change"
            category = "directory"
        return CanonicalEvent(
            id=str(raw.get("id") or new_id("evt")),
            tenant_id=tenant_id,
            timestamp=utcnow() if not raw.get("activityDateTime") else _parse_ts(raw.get("activityDateTime")),
            ingested_at=utcnow(),
            source="azure-ad",
            source_type="cloud",
            event_type=event_type,
            category=category,
            action=activity,
            outcome=outcome,  # type: ignore[arg-type]
            user=CanonicalUser(name=str(user_name)) if user_name else None,
            host=CanonicalHost(name=str(target.get("displayName") or target.get("id") or "azure-ad")),
            src_ip=raw.get("ipAddress") or raw.get("src_ip"),
            severity="high" if raw.get("privileged") else "informational",
            raw_event=raw,
            raw_hash=sha256_hex(canonical_json(raw)),
            attributes={
                "cloud": "azure",
                "connector": self.connector_id,
                "resource": str(target.get("id") or ""),
                "privileged": str(bool(raw.get("privileged"))).lower(),
                "raw_reference": sha256_hex(canonical_json(raw)),
            },
        )

    def inventory(self, events: list[CanonicalEvent] | None = None) -> CloudInventory:
        events = events or []
        identities = {}
        assets = {}
        privileged = []
        for event in events:
            if event.user and event.user.name:
                identities[event.user.name] = {
                    "id": event.user.id or event.user.name,
                    "name": event.user.name,
                    "source": "azure-ad",
                    "last_seen": event.timestamp.isoformat(),
                }
            if event.host and event.host.name:
                assets[event.host.name] = {
                    "id": event.host.id or event.host.name,
                    "name": event.host.name,
                    "kind": "directory_resource",
                    "cloud": "azure",
                }
            if event.attributes.get("privileged") == "true" or event.event_type == "privilege_change":
                privileged.append(
                    {
                        "event_id": event.id,
                        "action": event.action,
                        "user": event.user.name if event.user else None,
                        "timestamp": event.timestamp.isoformat(),
                    }
                )
        return CloudInventory(
            identities=sorted(identities.values(), key=lambda item: item["name"]),
            assets=sorted(assets.values(), key=lambda item: item["name"]),
            risky_configs=list(RISKY_CONFIGS),
            privileged_ops=privileged,
        )


def _parse_ts(value: Any):
    from datetime import UTC, datetime

    if hasattr(value, "tzinfo"):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def get_cloud_connector(connector_id: str = "azure_ad") -> AzureAdFixtureConnector:
    if connector_id not in {"azure_ad", "azure", "entra"}:
        from blueteam_common.errors import BlueTeamError

        raise BlueTeamError("UNKNOWN_CLOUD", f"Cloud connector {connector_id} not registered", 404)
    return AzureAdFixtureConnector()
