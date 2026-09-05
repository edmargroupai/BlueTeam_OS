from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from blueteam_detection.context import DetectionContext, EventWindow
from blueteam_schemas.events import CanonicalEvent, CanonicalUser

from detections.python.catalog import build_default_registry

TENANT = "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _event(
    *,
    suffix: str,
    minutes: int,
    user: str,
    src_ip: str,
    outcome: str = "failure",
    category: str = "authentication",
    event_type: str = "login",
    action: str = "login",
    attributes: dict | None = None,
) -> CanonicalEvent:
    stamp = datetime(2026, 9, 5, 12, 0, tzinfo=UTC) + timedelta(minutes=minutes, seconds=int(suffix, 16) % 50)
    return CanonicalEvent(
        id=f"evt_{suffix.ljust(32, '0')}",
        tenant_id=TENANT,
        timestamp=stamp,
        ingested_at=stamp,
        source="fixture",
        source_type="test",
        event_type=event_type,
        category=category,
        user=CanonicalUser(name=user),
        src_ip=src_ip,
        action=action,
        outcome=outcome,  # type: ignore[arg-type]
        attributes=attributes or {},
        raw_event={"user": user},
    )


def _run(events: list[CanonicalEvent]) -> list[str]:
    registry = build_default_registry()
    context = DetectionContext(EventWindow(events))
    rules: list[str] = []
    for event in events:
        for finding in registry.evaluate(event, context):
            context.open_fingerprints.add(finding.fingerprint)
            rules.append(finding.rule_id)
            assert finding.evidence
            assert finding.explanation
            assert finding.mitre_techniques
    return rules


@pytest.mark.detection
def test_password_spray_requires_distinct_users() -> None:
    events = [
        _event(suffix=f"{idx:032x}", minutes=0, user=f"user{idx}", src_ip="203.0.113.9")
        for idx in range(6)
    ]
    assert "identity.password_spray" in _run(events)


@pytest.mark.detection
def test_single_user_failures_are_not_spray() -> None:
    events = [
        _event(suffix=f"{idx:032x}", minutes=0, user="alice", src_ip="203.0.113.9")
        for idx in range(6)
    ]
    assert "identity.password_spray" not in _run(events)


@pytest.mark.detection
def test_brute_force_single_account() -> None:
    events = [
        _event(suffix=f"{idx:032x}", minutes=0, user="svc-sql", src_ip="10.0.0.8")
        for idx in range(8)
    ]
    assert "identity.brute_force" in _run(events)


@pytest.mark.detection
def test_privilege_grant_domain_admins() -> None:
    events = [
        _event(
            suffix="ab",
            minutes=0,
            user="helpdesk",
            src_ip="10.0.0.2",
            outcome="success",
            category="directory",
            event_type="group_change",
            action="add_to_group",
            attributes={"group": "Domain Admins"},
        )
    ]
    assert "identity.privilege_grant" in _run(events)


@pytest.mark.detection
def test_benign_admin_success_does_not_fire() -> None:
    events = [
        _event(
            suffix="cd",
            minutes=0,
            user="alice",
            src_ip="10.0.0.4",
            outcome="success",
        )
    ]
    assert _run(events) == []
