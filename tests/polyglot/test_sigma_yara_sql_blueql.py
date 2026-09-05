from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from blueteam_blueql.engine import BlueQLError, execute, parse
from blueteam_detection.context import DetectionContext, EventWindow
from blueteam_range.loader import load_scenario
from blueteam_range.runner import run_scenario
from blueteam_schemas.events import CanonicalEvent, CanonicalProcess
from blueteam_sigma.compiler import compile_rule
from blueteam_sql.engine import execute_hunt
from blueteam_yara.engine import scan_bytes

from detections.python.catalog import build_default_registry

ROOT = Path(__file__).resolve().parents[2]
TENANT = "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _event(**kwargs) -> CanonicalEvent:
    base = {
        "id": "evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "tenant_id": TENANT,
        "timestamp": datetime(2026, 9, 5, 9, 0, tzinfo=UTC),
        "ingested_at": datetime(2026, 9, 5, 9, 0, tzinfo=UTC),
        "source": "sysmon",
        "source_type": "endpoint",
        "event_type": "process_creation",
        "category": "process",
        "schema_version": "1.0.0",
    }
    base.update(kwargs)
    return CanonicalEvent.model_validate(base)


@pytest.mark.polyglot
def test_sigma_office_powershell_compiles_and_matches() -> None:
    rule = compile_rule(ROOT / "security-languages/sigma/windows/proc_office_spawns_powershell.yml")
    event = _event(
        process=CanonicalProcess(name="powershell.exe"),
        parent_process=CanonicalProcess(name="winword.exe"),
    )
    findings = rule.evaluate(event, DetectionContext(EventWindow([event])))
    assert findings and findings[0].rule_id == "sigma.office-spawns-powershell"
    benign = _event(process=CanonicalProcess(name="notepad.exe"), parent_process=CanonicalProcess(name="explorer.exe"))
    assert rule.evaluate(benign, DetectionContext(EventWindow([benign]))) == []


@pytest.mark.polyglot
def test_yara_corpus_true_and_false_positives() -> None:
    rule = (ROOT / "security-languages/yara/webshells/webshell_eval.yar").read_text(encoding="utf-8")
    bad = (ROOT / "security-languages/yara/corpus/known-malicious/webshell_sample.php.txt").read_bytes()
    good = (ROOT / "security-languages/yara/corpus/known-good/readme.php.txt").read_bytes()
    assert scan_bytes(bad, rule) is not None
    assert scan_bytes(good, rule) is None


@pytest.mark.polyglot
def test_sql_password_spray_hunt_on_fixture() -> None:
    scenario = load_scenario(ROOT / "blue_range/scenarios/identity/password_spray.yaml")
    result = execute_hunt("sql.identity.password_spray", scenario.events, {"min_users": 5})
    rows = result["rows"] if isinstance(result, dict) else result
    assert result.get("backend") == "sqlite-fixture"
    assert rows and rows[0]["distinct_users"] >= 5


@pytest.mark.polyglot
def test_blueql_office_parent_and_rejects_injection() -> None:
    events = [
        _event(
            process=CanonicalProcess(name="powershell.exe"),
            parent_process=CanonicalProcess(name="winword.exe"),
            dst_ip="203.0.113.9",
        )
    ]
    matches = execute(
        'process.name = "powershell.exe" AND parent.name IN ("winword.exe", "excel.exe")',
        events,
    )
    assert [item.id for item in matches] == [events[0].id]
    with pytest.raises(BlueQLError):
        parse('process.name = "x"; DROP TABLE events')
    with pytest.raises(BlueQLError):
        parse("process.name = 1 UNION SELECT password")


@pytest.mark.polyglot
def test_blueql_sequence_auth_then_privilege() -> None:
    from blueteam_range.loader import load_scenario as load

    spray = load(ROOT / "blue_range/scenarios/identity/password_spray.yaml").events
    priv = load(ROOT / "blue_range/scenarios/identity/privilege_grant.yaml").events
    # Privilege is later in wall clock; sequence window 10m does not span 06:00 to 08:15.
    query = "auth.failures > 0 FOLLOWED_BY privilege.change = true WITHIN 10m"
    matches = execute(query, spray + priv)
    assert matches == []
    close = [
        spray[-1],
        priv[0].model_copy(update={"timestamp": spray[-1].timestamp}),
    ]
    assert execute(query, close)


@pytest.mark.blue_range
def test_office_sigma_blue_range() -> None:
    scenario = load_scenario(ROOT / "blue_range/scenarios/endpoint/office_spawns_powershell.yaml")
    result = run_scenario(scenario, build_default_registry())
    assert result.passed, result.errors
