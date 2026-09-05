from __future__ import annotations

from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import DetectionRule


class DetectionRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, DetectionRule] = {}

    def register(self, rule: DetectionRule) -> None:
        self._rules[rule.meta.rule_id] = rule

    def get(self, rule_id: str) -> DetectionRule:
        return self._rules[rule_id]

    def all_rules(self) -> list[DetectionRule]:
        return list(self._rules.values())

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules.values():
            execution = getattr(rule.meta, "execution", "realtime")
            if execution == "scheduled" and not context.scheduled:
                continue
            if execution == "realtime" and context.scheduled:
                continue
            findings.extend(rule.evaluate(event, context))
        return findings
