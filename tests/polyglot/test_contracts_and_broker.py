from __future__ import annotations

import pytest
from blueteam_broker.broker import ExecutionBroker
from blueteam_common.errors import BlueTeamError
from blueteam_rego.engine import evaluate
from blueteam_schemas.actions import ActionRequest

TENANT = "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _req(action_type: str, **kwargs) -> ActionRequest:
    payload = {
        "action_id": "act_test",
        "action_type": action_type,
        "tenant_id": TENANT,
        "reason": "unit",
        "requested_by": "usr_test",
        "dry_run": True,
        "permissions": ["response:tier0", "hunts:execute", "detections:read"],
    }
    payload.update(kwargs)
    return ActionRequest.model_validate(payload)


@pytest.mark.polyglot
def test_unregistered_and_raw_shell_are_rejected() -> None:
    broker = ExecutionBroker()
    with pytest.raises(BlueTeamError) as exc:
        broker.submit(_req("shell.exec"))
    assert exc.value.code == "ACTION_FORBIDDEN"
    with pytest.raises(BlueTeamError) as exc:
        broker.submit(_req("not.a.real.action"))
    assert exc.value.code == "ACTION_UNREGISTERED"


@pytest.mark.polyglot
def test_undeclared_params_rejected() -> None:
    broker = ExecutionBroker()
    with pytest.raises(BlueTeamError) as exc:
        broker.submit(_req("collect.linux.processes", params={"cmd": "id"}))
    assert exc.value.code == "ACTION_SCHEMA"


@pytest.mark.polyglot
def test_read_only_collect_dry_run_is_planned() -> None:
    result = ExecutionBroker().submit(_req("collect.linux.processes", params={"limit": 10}))
    assert result.policy_decision == "ALLOW"
    assert result.status in {"planned", "skipped"}
    assert result.dry_run is True


@pytest.mark.polyglot
def test_isolate_requires_approval() -> None:
    result = ExecutionBroker().submit(
        _req(
            "isolate.host",
            dry_run=False,
            params={"host_id": "host-1"},
            permissions=["response:tier2"],
        )
    )
    assert result.policy_decision == "REQUIRE_APPROVAL"
    assert result.status == "awaiting_approval"


@pytest.mark.polyglot
def test_rego_denies_ai_and_defaults_deny() -> None:
    assert evaluate({"action": {"type": "ai.execute", "tier": 0, "read_only": False}}).decision == "DENY"
    assert evaluate({"action": {"type": "unknown", "tier": 1, "read_only": False}}).decision in {
        "DENY",
        "REQUIRE_APPROVAL",
    }
    assert evaluate({"action": {"type": "delete_evidence", "tier": 0, "read_only": True}}).decision == "DENY"
