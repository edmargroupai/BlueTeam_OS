"""Declarative correlation rules. Hard-coded storylines remain, this is the general model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from blueteam_common.ids import new_id
from blueteam_schemas.findings import Finding
from blueteam_schemas.storylines import Storyline, StorylineStage


@dataclass(frozen=True)
class CorrelationRule:
    rule_id: str
    title: str
    required_rule_ids: tuple[str, ...]
    entity_key: str
    window_seconds: int
    mitre_techniques: tuple[str, ...] = ()
    min_findings: int = 2


DEFAULT_CORRELATION_RULES = (
    CorrelationRule(
        rule_id="corr.identity.spray_then_grant",
        title="Password spray correlated with privilege grant",
        required_rule_ids=("identity.password_spray", "identity.privilege_grant"),
        entity_key="user",
        window_seconds=7200,
        mitre_techniques=("T1110.003", "T1098"),
    ),
    CorrelationRule(
        rule_id="corr.endpoint.office_c2",
        title="Office execution correlated with beacon",
        required_rule_ids=("endpoint.office_spawns_shell", "network.repetitive_beacon"),
        entity_key="host",
        window_seconds=3600,
        mitre_techniques=("T1059.001", "T1071"),
    ),
    CorrelationRule(
        rule_id="corr.network.lateral_c2",
        title="East-west movement correlated with C2",
        required_rule_ids=("network.unusual_east_west", "network.repetitive_beacon"),
        entity_key="ip",
        window_seconds=3600,
        mitre_techniques=("T1021", "T1071"),
    ),
)


def apply_correlation_rules(findings: list[Finding], rules: tuple[CorrelationRule, ...] = DEFAULT_CORRELATION_RULES) -> list[Storyline]:
    stories: list[Storyline] = []
    for rule in rules:
        matched = [item for item in findings if item.rule_id in rule.required_rule_ids]
        if len({item.rule_id for item in matched}) < len(rule.required_rule_ids):
            continue
        groups: dict[str, list[Finding]] = {}
        for item in matched:
            key = item.attributes.get(rule.entity_key) or item.attributes.get("src_ip") or ""
            groups.setdefault(key, []).append(item)
        for entity, group in groups.items():
            if len({item.rule_id for item in group}) < len(rule.required_rule_ids):
                continue
            if len(group) < rule.min_findings:
                continue
            times = [item.created_at for item in group]
            if max(times) - min(times) > timedelta(seconds=rule.window_seconds):
                continue
            stages = [
                StorylineStage(
                    name=item.rule_id,
                    rule_ids=[item.rule_id],
                    event_ids=item.event_ids,
                    timestamp=item.created_at,
                )
                for item in sorted(group, key=lambda row: row.created_at)
            ]
            evidence = [ev.evidence_id for item in group for ev in item.evidence]
            event_ids = [eid for item in group for eid in item.event_ids]
            stories.append(
                Storyline(
                    storyline_id=new_id("stl"),
                    tenant_id=group[0].tenant_id,
                    title=rule.title,
                    entities={rule.entity_key: [entity] if entity else []},
                    stages=stages,
                    confidence=75,
                    evidence_ids=evidence,
                    event_ids=event_ids,
                    mitre_techniques=list(rule.mitre_techniques),
                    start=min(times),
                    end=max(times),
                    attributes={"correlation_rule_id": rule.rule_id},
                )
            )
    return stories


def incident_fingerprint(storyline: Storyline) -> str:
    entities = []
    for key in sorted(storyline.entities):
        values = ",".join(sorted(v for v in storyline.entities[key] if v))
        entities.append(f"{key}={values}")
    return f"{storyline.title}|{'|'.join(entities)}"
