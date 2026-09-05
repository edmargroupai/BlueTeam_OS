from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Language = Literal[
    "python",
    "powershell",
    "bash",
    "go",
    "rust",
    "sigma",
    "yara",
    "sql",
    "blueql",
    "rego",
    "ebpf",
    "cpp",
]

REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class ActionSpec:
    action_type: str
    language: Language
    description: str
    tier: int
    read_only: bool
    required_permission: str
    allowed_params: frozenset[str]
    script_path: Path | None = None
    rollback_available: bool = False
    feature_flag: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def default_registry() -> dict[str, ActionSpec]:
    ps = REPO_ROOT / "security-languages" / "powershell"
    sh = REPO_ROOT / "security-languages" / "shell"
    return {
        "collect.windows.processes": ActionSpec(
            action_type="collect.windows.processes",
            language="powershell",
            description="Read-only local process inventory (Windows).",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset({"limit"}),
            script_path=ps / "windows" / "Get-BtosProcesses.ps1",
        ),
        "collect.windows.defender": ActionSpec(
            action_type="collect.windows.defender",
            language="powershell",
            description="Read-only Microsoft Defender status.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset(),
            script_path=ps / "windows" / "Get-BtosDefenderStatus.ps1",
        ),
        "collect.windows.scheduled_tasks": ActionSpec(
            action_type="collect.windows.scheduled_tasks",
            language="powershell",
            description="Read-only scheduled task inventory.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset({"limit"}),
            script_path=ps / "windows" / "Get-BtosScheduledTasks.ps1",
        ),
        "collect.windows.services": ActionSpec(
            action_type="collect.windows.services",
            language="powershell",
            description="Read-only service inventory.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset({"limit"}),
            script_path=ps / "windows" / "Get-BtosServices.ps1",
        ),
        "collect.windows.local_admins": ActionSpec(
            action_type="collect.windows.local_admins",
            language="powershell",
            description="Read-only local Administrators group membership.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset(),
            script_path=ps / "windows" / "Get-BtosLocalAdmins.ps1",
        ),
        "collect.windows.events": ActionSpec(
            action_type="collect.windows.events",
            language="powershell",
            description="Read-only recent Windows Security events.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset({"max_events"}),
            script_path=ps / "windows" / "Get-BtosWindowsEvents.ps1",
        ),
        "collect.windows.auth_events": ActionSpec(
            action_type="collect.windows.auth_events",
            language="powershell",
            description="Read-only authentication event query template.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset({"hours", "max_events"}),
            script_path=ps / "windows" / "Get-BtosAuthEvents.ps1",
        ),
        "collect.linux.processes": ActionSpec(
            action_type="collect.linux.processes",
            language="bash",
            description="Read-only process inventory (Linux/POSIX).",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset({"limit"}),
            script_path=sh / "linux" / "collect_processes.sh",
        ),
        "collect.linux.sessions": ActionSpec(
            action_type="collect.linux.sessions",
            language="bash",
            description="Read-only user session inspection.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset(),
            script_path=sh / "linux" / "collect_sessions.sh",
        ),
        "collect.linux.sockets": ActionSpec(
            action_type="collect.linux.sockets",
            language="bash",
            description="Read-only listening sockets.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset(),
            script_path=sh / "linux" / "collect_sockets.sh",
        ),
        "collect.linux.systemd": ActionSpec(
            action_type="collect.linux.systemd",
            language="bash",
            description="Read-only systemd unit inventory.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset(),
            script_path=sh / "linux" / "collect_systemd.sh",
        ),
        "collect.linux.cron": ActionSpec(
            action_type="collect.linux.cron",
            language="bash",
            description="Read-only crontab listing.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset(),
            script_path=sh / "linux" / "collect_cron.sh",
        ),
        "collect.linux.ssh": ActionSpec(
            action_type="collect.linux.ssh",
            language="bash",
            description="Read-only SSH auth log tail.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset(),
            script_path=sh / "linux" / "collect_ssh.sh",
        ),
        "collect.linux.audit": ActionSpec(
            action_type="collect.linux.audit",
            language="bash",
            description="Read-only audit log tail.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset(),
            script_path=sh / "linux" / "collect_audit.sh",
        ),
        "scan.yara.bytes": ActionSpec(
            action_type="scan.yara.bytes",
            language="yara",
            description="Scan provided bytes with approved YARA rules.",
            tier=0,
            read_only=True,
            required_permission="detections:read",
            allowed_params=frozenset({"rule_id", "content_b64", "filename"}),
        ),
        "hunt.blueql": ActionSpec(
            action_type="hunt.blueql",
            language="blueql",
            description="Compile and execute a BlueQL hunt against provided events.",
            tier=0,
            read_only=True,
            required_permission="hunts:execute",
            allowed_params=frozenset({"query", "dry_run"}),
        ),
        "hunt.sql": ActionSpec(
            action_type="hunt.sql",
            language="sql",
            description="Execute a registered, parameterized SQL hunt.",
            tier=0,
            read_only=True,
            required_permission="hunts:execute",
            allowed_params=frozenset({"query_id", "params"}),
        ),
        "policy.evaluate": ActionSpec(
            action_type="policy.evaluate",
            language="rego",
            description="Evaluate a proposed response against Rego policy.",
            tier=0,
            read_only=True,
            required_permission="response:tier0",
            allowed_params=frozenset({"proposed_action", "environment", "confidence", "auto_containment"}),
        ),
        "isolate.host": ActionSpec(
            action_type="isolate.host",
            language="python",
            description="Host isolation request. Always policy-gated.",
            tier=2,
            read_only=False,
            required_permission="response:tier2",
            allowed_params=frozenset({"host_id", "environment", "confidence", "auto_containment"}),
            rollback_available=True,
        ),
        "identity.disable_user": ActionSpec(
            action_type="identity.disable_user",
            language="python",
            description="Disable a user account. Policy-gated identity action.",
            tier=2,
            read_only=False,
            required_permission="response:tier2",
            allowed_params=frozenset({"user_id", "environment", "confidence", "auto_containment"}),
        ),
        "identity.revoke_token": ActionSpec(
            action_type="identity.revoke_token",
            language="python",
            description="Revoke an access token. Policy-gated identity action.",
            tier=2,
            read_only=False,
            required_permission="response:tier2",
            allowed_params=frozenset({"token_id", "environment", "confidence", "auto_containment"}),
        ),
        "network.block_ioc": ActionSpec(
            action_type="network.block_ioc",
            language="python",
            description="Block an IOC. Policy-gated network action.",
            tier=2,
            read_only=False,
            required_permission="response:tier2",
            allowed_params=frozenset({"indicator", "environment", "confidence", "auto_containment"}),
        ),
    }
