from __future__ import annotations

from blueteam_common.time import utcnow
from blueteam_detection.context import DetectionContext, EventWindow
from blueteam_detection.registry import DetectionRegistry

from blueteam_range.models import DetectionAssertion, RangeResult, RangeScenario


def run_scenario(scenario: RangeScenario, registry: DetectionRegistry) -> RangeResult:
    started = utcnow()
    errors: list[str] = []
    if len(scenario.events) != scenario.expected_event_count:
        errors.append(
            f"fixture event count {len(scenario.events)} != declared {scenario.expected_event_count}"
        )

    tenant_ids = {event.tenant_id for event in scenario.events}
    if len(tenant_ids) != 1:
        errors.append("Blue Range scenario must be single-tenant")

    window = EventWindow(scenario.events)
    context = DetectionContext(window)
    findings = []
    for event in scenario.events:
        produced = registry.evaluate(event, context)
        for finding in produced:
            context.open_fingerprints.add(finding.fingerprint)
        findings.extend(produced)

    expected_rules = {item.rule_id: item for item in scenario.expected_detections}
    observed: dict[str, int] = {}
    for finding in findings:
        observed[finding.rule_id] = observed.get(finding.rule_id, 0) + 1

    assertions: list[DetectionAssertion] = []
    for rule_id, spec in expected_rules.items():
        count = observed.get(rule_id, 0)
        assertions.append(
            DetectionAssertion(
                rule_id=rule_id,
                expected_min=spec.min_count,
                observed=count,
                passed=count >= spec.min_count,
            )
        )

    unexpected = [rule_id for rule_id in observed if rule_id not in expected_rules]
    if len(unexpected) > scenario.allowed_false_positive_envelope:
        errors.append(f"unexpected detections exceed envelope: {unexpected}")

    finished = utcnow()
    latency = (finished - started).total_seconds()
    if latency > scenario.max_detection_latency_seconds:
        errors.append(
            f"detection latency {latency:.3f}s exceeded {scenario.max_detection_latency_seconds}s"
        )

    passed = (not errors) and all(item.passed for item in assertions)
    return RangeResult(
        scenario_id=scenario.id,
        passed=passed,
        started_at=started,
        finished_at=finished,
        latency_seconds=latency,
        event_count=len(scenario.events),
        findings=findings,
        assertions=assertions,
        unexpected_rule_ids=unexpected,
        errors=errors,
    )
