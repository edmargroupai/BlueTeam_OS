"""ATT&CK coverage engine — technique catalogue + detection/telemetry mapping."""

from __future__ import annotations

from dataclasses import dataclass, field

# Curated subset used for coverage scoring. Expand via intel feeds later; do not invent live MITRE sync.
TECHNIQUE_CATALOGUE: dict[str, dict[str, str]] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1204": {"name": "User Execution", "tactic": "Execution"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control"},
    "T1573": {"name": "Encrypted Channel", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
}

TELEMETRY_TECHNIQUE_HINTS: dict[str, list[str]] = {
    "identity": ["T1110", "T1110.001", "T1110.003", "T1078", "T1098"],
    "authentication": ["T1110", "T1110.003", "T1078"],
    "endpoint": ["T1059", "T1059.001", "T1204", "T1547", "T1053"],
    "process": ["T1059", "T1059.001", "T1047"],
    "network": ["T1046", "T1071", "T1021"],
    "zeek": ["T1046", "T1071", "T1071.004", "T1573"],
    "suricata": ["T1046", "T1071", "T1105"],
    "dns": ["T1071.004"],
    "http": ["T1071.001"],
    "tls": ["T1573"],
    "wazuh": ["T1059", "T1547", "T1053"],
}


@dataclass
class TechniqueCoverage:
    technique_id: str
    name: str
    tactic: str
    detections: list[str] = field(default_factory=list)
    telemetry_sources: list[str] = field(default_factory=list)
    finding_count: int = 0
    validated: bool = False
    coverage_score: float = 0.0
    gap_severity: str = "critical"
    gaps: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "detections": self.detections,
            "telemetry_sources": self.telemetry_sources,
            "finding_count": self.finding_count,
            "validated": self.validated,
            "coverage_score": round(self.coverage_score, 2),
            "gap_severity": self.gap_severity,
            "gaps": self.gaps,
        }


def _gap_severity(score: float) -> str:
    if score >= 0.75:
        return "low"
    if score >= 0.4:
        return "medium"
    if score > 0:
        return "high"
    return "critical"


def compute_coverage(
    *,
    detection_maps: list[tuple[str, list[str], list[str], str]],
    telemetry_source_types: list[str],
    finding_technique_counts: dict[str, int],
    validated_rule_ids: set[str] | None = None,
) -> dict:
    """
    detection_maps entries: (rule_id, mitre_techniques, data_sources, status)
    """
    validated_rule_ids = validated_rule_ids or set()
    by_tech: dict[str, TechniqueCoverage] = {}
    for tech_id, meta in TECHNIQUE_CATALOGUE.items():
        by_tech[tech_id] = TechniqueCoverage(
            technique_id=tech_id,
            name=meta["name"],
            tactic=meta["tactic"],
        )

    for rule_id, techniques, data_sources, status in detection_maps:
        for tech in techniques:
            tech = tech.upper()
            if tech not in by_tech:
                by_tech[tech] = TechniqueCoverage(
                    technique_id=tech,
                    name=tech,
                    tactic="Unknown",
                )
            row = by_tech[tech]
            if rule_id not in row.detections:
                row.detections.append(rule_id)
            for source in data_sources:
                if source and source not in row.telemetry_sources:
                    row.telemetry_sources.append(source)
            if status in {"tested", "promoted"} or rule_id in validated_rule_ids:
                row.validated = True

    for source_type in telemetry_source_types:
        for tech in TELEMETRY_TECHNIQUE_HINTS.get(source_type, []):
            if tech in by_tech:
                if source_type not in by_tech[tech].telemetry_sources:
                    by_tech[tech].telemetry_sources.append(source_type)

    for tech, count in finding_technique_counts.items():
        tech = tech.upper()
        if tech in by_tech:
            by_tech[tech].finding_count = count

    for row in by_tech.values():
        det = 0.45 if row.detections else 0.0
        tel = 0.25 if row.telemetry_sources else 0.0
        val = 0.20 if row.validated else 0.0
        fir = 0.10 if row.finding_count > 0 else 0.0
        row.coverage_score = det + tel + val + fir
        row.gap_severity = _gap_severity(row.coverage_score)
        gaps: list[str] = []
        if not row.detections:
            gaps.append("no_detection")
        if not row.telemetry_sources:
            gaps.append("no_telemetry")
        if not row.validated:
            gaps.append("unvalidated")
        if row.finding_count == 0 and row.detections:
            gaps.append("no_observed_findings")
        row.gaps = gaps

    items = sorted(by_tech.values(), key=lambda item: (item.coverage_score, item.technique_id))
    covered = sum(1 for item in items if item.coverage_score >= 0.4)
    return {
        "techniques": [item.as_dict() for item in items],
        "summary": {
            "technique_count": len(items),
            "covered": covered,
            "gaps": sum(1 for item in items if item.gap_severity in {"critical", "high"}),
            "mean_coverage": round(sum(item.coverage_score for item in items) / max(len(items), 1), 3),
        },
    }


def technique_detail(coverage: dict, technique_id: str) -> dict | None:
    for item in coverage.get("techniques", []):
        if item["technique_id"].upper() == technique_id.upper():
            return item
    return None


def catalogue() -> list[dict]:
    return [
        {"technique_id": tech_id, "name": meta["name"], "tactic": meta["tactic"]}
        for tech_id, meta in sorted(TECHNIQUE_CATALOGUE.items())
    ]
