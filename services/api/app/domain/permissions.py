from __future__ import annotations

from dataclasses import dataclass

PERMISSIONS: dict[str, str] = {
    "tenants:read": "Read tenant metadata",
    "tenants:write": "Create or modify tenants",
    "users:read": "Read users",
    "users:write": "Create or modify users and memberships",
    "roles:read": "Read role catalogue",
    "roles:write": "Modify custom roles",
    "audit:read": "Read audit records",
    "events:ingest": "Ingest telemetry",
    "events:read": "Read tenant telemetry metadata",
    "detections:read": "Read detection catalogue and findings",
    "detections:write": "Change detection configuration",
    "alerts:read": "Read alerts",
    "alerts:write": "Update alert status",
    "incidents:read": "Read incidents",
    "incidents:write": "Modify incidents",
    "evidence:read": "Read evidence metadata",
    "evidence:write": "Register evidence",
    "evidence:export": "Export evidence manifests",
    "quality:read": "Read quality index",
    "blue_range:execute": "Execute Blue Range scenarios",
    "hunts:execute": "Execute BlueQL and registered SQL hunts",
    "languages:read": "Read polyglot language catalogue and policy",
    "broker:execute": "Submit registered broker actions",
    "response:tier0": "Execute Tier-0 actions",
    "response:tier1": "Request Tier-1 actions",
    "response:tier2": "Request Tier-2 actions",
    "admin:platform": "Platform super-admin operations",
}

ANALYST_PERMS = [
    "tenants:read",
    "users:read",
    "roles:read",
    "audit:read",
    "events:read",
    "detections:read",
    "alerts:read",
    "incidents:read",
    "incidents:write",
    "evidence:read",
    "quality:read",
    "languages:read",
    "hunts:execute",
]

HUNTER_PERMS = [*ANALYST_PERMS, "events:ingest"]

DETECTION_ENGINEER_PERMS = [
    *ANALYST_PERMS,
    "detections:write",
    "events:ingest",
    "blue_range:execute",
    "quality:read",
]

RESPONDER_PERMS = [
    *ANALYST_PERMS,
    "alerts:write",
    "evidence:write",
    "evidence:export",
    "response:tier0",
    "response:tier1",
    "response:tier2",
    "broker:execute",
]

ADMIN_PERMS = [
    *DETECTION_ENGINEER_PERMS,
    *RESPONDER_PERMS,
    "users:write",
    "tenants:write",
    "roles:write",
]


@dataclass(frozen=True)
class RoleDefinition:
    key: str
    name: str
    description: str
    permissions: tuple[str, ...]


ROLE_CATALOG: dict[str, RoleDefinition] = {
    "platform_super_admin": RoleDefinition(
        "platform_super_admin",
        "Platform Super Admin",
        "Cross-tenant platform administration",
        tuple([*ADMIN_PERMS, "admin:platform"]),
    ),
    "tenant_owner": RoleDefinition(
        "tenant_owner",
        "Tenant Owner",
        "Owns a tenant and its memberships",
        tuple(ADMIN_PERMS),
    ),
    "security_admin": RoleDefinition(
        "security_admin",
        "Security Admin",
        "Security configuration and user administration",
        tuple(ADMIN_PERMS),
    ),
    "soc_manager": RoleDefinition(
        "soc_manager",
        "SOC Manager",
        "Operations management and quality review",
        tuple([*RESPONDER_PERMS, "users:read", "blue_range:execute"]),
    ),
    "senior_analyst": RoleDefinition(
        "senior_analyst",
        "Senior Analyst",
        "Lead investigation and incident ownership",
        tuple(RESPONDER_PERMS),
    ),
    "analyst": RoleDefinition(
        "analyst",
        "Analyst",
        "Investigate alerts and incidents",
        tuple(ANALYST_PERMS),
    ),
    "threat_hunter": RoleDefinition(
        "threat_hunter",
        "Threat Hunter",
        "Search telemetry and develop hunts",
        tuple(HUNTER_PERMS),
    ),
    "detection_engineer": RoleDefinition(
        "detection_engineer",
        "Detection Engineer",
        "Author, test, and promote detections",
        tuple(DETECTION_ENGINEER_PERMS),
    ),
    "incident_responder": RoleDefinition(
        "incident_responder",
        "Incident Responder",
        "Containment and evidence handling",
        tuple(RESPONDER_PERMS),
    ),
    "auditor": RoleDefinition(
        "auditor",
        "Auditor",
        "Read-only access including audit and evidence",
        (
            "tenants:read",
            "users:read",
            "roles:read",
            "audit:read",
            "events:read",
            "detections:read",
            "alerts:read",
            "incidents:read",
            "evidence:read",
            "quality:read",
        ),
    ),
    "read_only": RoleDefinition(
        "read_only",
        "Read Only",
        "Non-sensitive operational read access",
        (
            "tenants:read",
            "alerts:read",
            "incidents:read",
            "detections:read",
            "quality:read",
        ),
    ),
}


def permissions_for_roles(role_keys: list[str]) -> set[str]:
    granted: set[str] = set()
    for key in role_keys:
        role = ROLE_CATALOG.get(key)
        if role:
            granted.update(role.permissions)
    return granted
