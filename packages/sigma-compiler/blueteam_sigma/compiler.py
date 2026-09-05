"""Compile approved Sigma YAML into Python DetectionRule objects."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding, FindingEvidence


class SigmaCompileError(ValueError):
    pass


def _canonical_field(event: CanonicalEvent, field: str) -> str | None:
    mapping = {
        "process.image": event.process.name if event.process else None,
        "process.name": event.process.name if event.process else None,
        "process.commandline": event.process.command_line if event.process else None,
        "parent.image": event.parent_process.name if event.parent_process else None,
        "parent.name": event.parent_process.name if event.parent_process else None,
        "user.name": event.user.name if event.user else None,
        "src_ip": event.src_ip,
        "destination.ip": event.dst_ip,
        "event_type": event.event_type,
        "category": event.category,
        "outcome": event.outcome,
        "action": event.action,
        "Image": event.process.name if event.process else None,
        "ParentImage": event.parent_process.name if event.parent_process else None,
        "CommandLine": event.process.command_line if event.process else None,
    }
    if field in mapping:
        return mapping[field]
    if field in event.attributes:
        return str(event.attributes[field])
    return None


def _match_value(observed: str | None, expected: Any) -> bool:
    if observed is None:
        return False
    if isinstance(expected, list):
        return any(_match_value(observed, item) for item in expected)
    text = str(expected).lower()
    value = observed.lower()
    if text.endswith("*") and text.startswith("*"):
        return text[1:-1] in value
    if text.endswith("*"):
        return value.startswith(text[:-1])
    if text.startswith("*"):
        return value.endswith(text[1:])
    return value == text


def compile_rule(path: Path) -> Any:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise SigmaCompileError(f"{path} is not a mapping")
    for required in ("title", "id", "detection", "logsource"):
        if required not in raw:
            raise SigmaCompileError(f"{path.name} missing {required}")
    detection = raw["detection"]
    if "condition" not in detection:
        raise SigmaCompileError("detection.condition is required")
    if detection["condition"] not in {"selection", "selection and not filter"}:
        raise SigmaCompileError("unsupported condition — only selection[/not filter] is compiled")
    selection = detection.get("selection")
    if not isinstance(selection, dict):
        raise SigmaCompileError("selection must be an object")
    filt = detection.get("filter") if "not filter" in str(detection["condition"]) else None
    tags = raw.get("tags") or []
    mitre_ids = []
    for tag in tags:
        text = str(tag).lower()
        if text.startswith("attack.t"):
            mitre_ids.append("T" + text.split("attack.t", 1)[1].upper())
    meta = RuleMeta(
        rule_id=f"sigma.{raw['id']}",
        name=str(raw["title"]),
        description=str(raw.get("description") or raw["title"]),
        version=str(raw.get("version") or "1.0.0"),
        severity={"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(
            str(raw.get("level", "medium")).lower(), "medium"
        ),
        confidence=75,
        mitre_tactics=[],
        mitre_techniques=mitre_ids,
        data_sources=[str((raw.get("logsource") or {}).get("product") or "unknown")],
        author=str(raw.get("author") or "blueteam-os"),
        status="tested" if raw.get("status") in {"test", "stable", "tested"} else "draft",
    )

    class CompiledSigmaRule:
        def __init__(self) -> None:
            self.meta = meta
            self.path = str(path)

        def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
            matched = all(_match_value(_canonical_field(event, key), expected) for key, expected in selection.items())
            if not matched:
                return []
            if isinstance(filt, dict) and all(
                _match_value(_canonical_field(event, key), expected) for key, expected in filt.items()
            ):
                return []
            fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.id}"
            if context.already_open(fingerprint):
                return []
            return [
                Finding(
                    id=new_id("fnd"),
                    tenant_id=event.tenant_id,
                    rule_id=self.meta.rule_id,
                    rule_version="1.0.0",
                    title=self.meta.name,
                    description=self.meta.description,
                    severity=self.meta.severity,  # type: ignore[arg-type]
                    confidence=self.meta.confidence,
                    fingerprint=fingerprint,
                    mitre_tactics=list(self.meta.mitre_tactics),
                    mitre_techniques=list(self.meta.mitre_techniques),
                    event_ids=[event.id],
                    evidence=[
                        FindingEvidence(
                            evidence_id=f"evi_pending_{event.id}",
                            event_id=event.id,
                            role="trigger",
                        )
                    ],
                    explanation=f"Sigma {self.meta.rule_id} matched selection on event {event.id}.",
                    created_at=utcnow(),
                )
            ]

    return CompiledSigmaRule()


def compile_rules_dir(root: Path) -> list[Any]:
    rules = []
    for path in sorted(root.rglob("*.yml")):
        rules.append(compile_rule(path))
    return rules
