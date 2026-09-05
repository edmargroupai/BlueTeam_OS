"""Cross-domain storylines from findings + events. No claim without evidence."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from blueteam_common.ids import new_id
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding
from blueteam_schemas.storylines import Storyline, StorylineStage

OFFICE_RULES = {
    "sigma.office-spawns-powershell",
    "endpoint.office_spawns_shell",
    "endpoint.encoded_powershell",
}
BEACON_RULES = {"network.repetitive_beacon", "endpoint.process_network_chain"}


def correlate(events: list[CanonicalEvent], findings: list[Finding]) -> list[Storyline]:
    if not findings:
        return []
    by_id = {event.id: event for event in events}
    storylines: list[Storyline] = []
    storylines.extend(_identity_chain(findings, by_id))
    storylines.extend(_office_c2(findings))
    storylines.extend(_lateral_c2(findings))
    from blueteam_correlation.rules import apply_correlation_rules

    existing = {(item.title, tuple(item.event_ids)) for item in storylines}
    for extra in apply_correlation_rules(findings):
        key = (extra.title, tuple(extra.event_ids))
        if key not in existing:
            storylines.append(extra)
            existing.add(key)
    return storylines


def _identity_chain(findings: list[Finding], by_id: dict[str, CanonicalEvent]) -> list[Storyline]:
    sprays = [item for item in findings if item.rule_id == "identity.password_spray"]
    successes = [item for item in findings if item.rule_id == "identity.brute_force"]
    grants = [item for item in findings if item.rule_id == "identity.privilege_grant"]
    out: list[Storyline] = []
    for spray in sprays:
        src = spray.attributes.get("src_ip")
        grant = next((item for item in grants if _overlap_user(spray, item) or _near(spray, item)), None)
        later_success = [
            event
            for event in by_id.values()
            if event.category == "authentication"
            and event.outcome == "success"
            and event.src_ip == src
            and event.timestamp >= spray.created_at - timedelta(hours=2)
        ]
        if grant is None and not later_success and not successes:
            continue
        stages = [
            StorylineStage(
                name="password_spray",
                rule_ids=[spray.rule_id],
                event_ids=spray.event_ids,
                timestamp=spray.created_at,
            ),
        ]
        if later_success:
            stages.append(
                StorylineStage(
                    name="authentication_success",
                    event_ids=[item.id for item in later_success],
                    timestamp=later_success[0].timestamp,
                )
            )
        if grant:
            stages.append(
                StorylineStage(
                    name="privilege_grant",
                    rule_ids=[grant.rule_id],
                    event_ids=grant.event_ids,
                    timestamp=grant.created_at,
                )
            )
        evidence = [item.evidence_id for item in spray.evidence]
        if grant:
            evidence.extend(item.evidence_id for item in grant.evidence)
        out.append(
            _story(
                spray.tenant_id,
                "Password spray to privilege",
                stages,
                ["T1110.003", "T1098"],
                evidence,
                spray.event_ids + (grant.event_ids if grant else []),
                {"user": [spray.attributes.get("user") or ""], "ip": [src or ""]},
                80,
            )
        )
    return out


def _office_c2(findings: list[Finding]) -> list[Storyline]:
    office = [item for item in findings if item.rule_id in OFFICE_RULES]
    beacons = [item for item in findings if item.rule_id in BEACON_RULES]
    if not office or not beacons:
        return []
    out: list[Storyline] = []
    for spawn in office:
        host = spawn.attributes.get("host")
        match = next(
            (
                item
                for item in beacons
                if not host or item.attributes.get("host") == host or item.attributes.get("src_ip")
            ),
            None,
        )
        if match is None:
            continue
        stages = [
            StorylineStage(
                name="office_process",
                rule_ids=[spawn.rule_id],
                event_ids=spawn.event_ids,
                timestamp=spawn.created_at,
            ),
            StorylineStage(
                name="powershell",
                rule_ids=[spawn.rule_id],
                event_ids=spawn.event_ids,
                timestamp=spawn.created_at,
            ),
            StorylineStage(
                name="external_beacon",
                rule_ids=[match.rule_id],
                event_ids=match.event_ids,
                timestamp=match.created_at,
            ),
        ]
        evidence = [item.evidence_id for item in spawn.evidence]
        evidence.extend(item.evidence_id for item in match.evidence)
        out.append(
            _story(
                spawn.tenant_id,
                "Office to PowerShell to beacon",
                stages,
                ["T1059.001", "T1204.002", "T1071"],
                evidence,
                spawn.event_ids + match.event_ids,
                {
                    "host": [host or ""],
                    "ip": [match.attributes.get("dst_ip") or ""],
                    "process": [spawn.attributes.get("process") or ""],
                },
                85,
            )
        )
    return out


def _lateral_c2(findings: list[Finding]) -> list[Storyline]:
    east = [item for item in findings if item.rule_id == "network.unusual_east_west"]
    beacons = [item for item in findings if item.rule_id in BEACON_RULES]
    if not east or not beacons:
        return []
    spawn = east[0]
    beacon = beacons[0]
    stages = [
        StorylineStage(name="compromised_endpoint", event_ids=spawn.event_ids, timestamp=spawn.created_at),
        StorylineStage(
            name="smb_rdp_movement",
            rule_ids=[spawn.rule_id],
            event_ids=spawn.event_ids,
            timestamp=spawn.created_at,
        ),
        StorylineStage(name="second_endpoint", event_ids=spawn.event_ids, timestamp=spawn.created_at),
        StorylineStage(
            name="c2",
            rule_ids=[beacon.rule_id],
            event_ids=beacon.event_ids,
            timestamp=beacon.created_at,
        ),
    ]
    evidence = [item.evidence_id for item in spawn.evidence]
    evidence.extend(item.evidence_id for item in beacon.evidence)
    return [
        _story(
            spawn.tenant_id,
            "Endpoint to lateral movement to C2",
            stages,
            ["T1021", "T1071"],
            evidence,
            spawn.event_ids + beacon.event_ids,
            {
                "ip": [
                    spawn.attributes.get("src_ip") or "",
                    spawn.attributes.get("dst_ip") or "",
                    beacon.attributes.get("dst_ip") or "",
                ],
                "host": [spawn.attributes.get("host") or ""],
            },
            78,
        )
    ]


def _overlap_user(left: Finding, right: Finding) -> bool:
    return bool(left.attributes.get("user") and left.attributes.get("user") == right.attributes.get("user"))


def _near(left: Finding, right: Finding) -> bool:
    return abs((left.created_at - right.created_at).total_seconds()) <= 7200


def _story(
    tenant_id: str,
    title: str,
    stages: list[StorylineStage],
    techniques: list[str],
    evidence_ids: list[str],
    event_ids: list[str],
    entities: dict[str, list[str]],
    confidence: float,
) -> Storyline:
    times = [stage.timestamp for stage in stages if stage.timestamp]
    start = min(times)
    end = max(times)
    return Storyline(
        storyline_id=new_id("stl"),
        tenant_id=tenant_id,
        title=title,
        entities={key: [value for value in values if value] for key, values in entities.items()},
        stages=stages,
        confidence=confidence,
        evidence_ids=evidence_ids,
        event_ids=event_ids,
        mitre_techniques=techniques,
        start=start,
        end=end,
    )


def index_by_keys(events: list[CanonicalEvent]) -> dict[str, list[str]]:
    keys: dict[str, list[str]] = defaultdict(list)
    for event in events:
        if event.user and event.user.name:
            keys[f"user:{event.user.name}"].append(event.id)
        if event.host and (event.host.id or event.host.name):
            keys[f"host:{event.host.id or event.host.name}"].append(event.id)
        if event.src_ip:
            keys[f"ip:{event.src_ip}"].append(event.id)
        if event.process and event.process.name:
            keys[f"process:{event.process.name}"].append(event.id)
        if event.domain:
            keys[f"domain:{event.domain}"].append(event.id)
        if event.hash:
            keys[f"hash:{event.hash}"].append(event.id)
        if event.correlation_id:
            keys[f"session:{event.correlation_id}"].append(event.id)
    return dict(keys)
