from __future__ import annotations

from blueteam_broker.registry import default_registry
from blueteam_rego.engine import active_engine as rego_engine
from blueteam_sql.engine import list_hunts
from blueteam_yara.engine import active_engine as yara_engine
from fastapi import APIRouter, Depends

from app.core.config import get_settings
from app.core.deps import Permission
from app.services.auth import TenantActor

router = APIRouter(prefix="/languages", tags=["languages"])


@router.get("")
def catalogue(_: TenantActor = Depends(Permission("languages:read"))) -> dict:
    settings = get_settings()
    actions = [
        {
            "action_type": spec.action_type,
            "language": spec.language,
            "tier": spec.tier,
            "read_only": spec.read_only,
            "description": spec.description,
        }
        for spec in default_registry().values()
    ]
    return {
        "python_orchestrates": True,
        "ai_executes_os_commands": False,
        "generic_shell": False,
        "actions": actions,
        "sql_hunts": [{"id": item["id"], "name": item["name"], "version": item["version"]} for item in list_hunts()],
        "runtimes": {
            "yara": yara_engine(),
            "rego": rego_engine(),
            "clickhouse_configured": bool(settings.clickhouse_url),
            "redpanda_configured": bool(settings.kafka_bootstrap),
        },
        "optional": {
            "ebpf": {"mandatory": False, "enabled_by": "BTOS_EBPF_ENABLED", "status": "specification_only"},
            "cpp": {"restricted_to": "specialist low-level components"},
        },
    }
