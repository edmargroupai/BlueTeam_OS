"""Vulnerability and exposure engine — deterministic remediation priority."""

from __future__ import annotations

from dataclasses import dataclass

# Risk formula (documented, deterministic):
#   priority = clamp(0..100,
#       0.40 * cvss_norm +
#       0.25 * exploitability +
#       0.20 * asset_criticality +
#       0.15 * threat_activity
#   )
# where each input is 0..100. SLA days = 7 if priority>=80 else 14 if >=50 else 30.


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def remediation_priority(
    *,
    cvss: float,
    exploitability: float,
    asset_criticality: float,
    threat_activity: float,
) -> dict:
    cvss_norm = clamp(cvss * 10.0)  # CVSS 0-10 → 0-100
    exploit = clamp(exploitability)
    criticality = clamp(asset_criticality)
    threat = clamp(threat_activity)
    score = clamp(0.40 * cvss_norm + 0.25 * exploit + 0.20 * criticality + 0.15 * threat)
    if score >= 80:
        sla_days = 7
        band = "critical"
    elif score >= 50:
        sla_days = 14
        band = "high"
    elif score >= 25:
        sla_days = 30
        band = "medium"
    else:
        sla_days = 90
        band = "low"
    return {
        "priority": round(score, 2),
        "band": band,
        "sla_days": sla_days,
        "components": {
            "cvss_norm": round(cvss_norm, 2),
            "exploitability": round(exploit, 2),
            "asset_criticality": round(criticality, 2),
            "threat_activity": round(threat, 2),
        },
        "formula": "0.40*cvss_norm + 0.25*exploitability + 0.20*asset_criticality + 0.15*threat_activity",
    }


@dataclass
class VulnerabilityFinding:
    cve_id: str
    title: str
    cvss: float
    exploitability: float
    asset_id: str
    asset_criticality: float
    threat_activity: float
    scanner: str
    status: str = "open"

    def scored(self) -> dict:
        priority = remediation_priority(
            cvss=self.cvss,
            exploitability=self.exploitability,
            asset_criticality=self.asset_criticality,
            threat_activity=self.threat_activity,
        )
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "cvss": self.cvss,
            "exploitability": self.exploitability,
            "asset_id": self.asset_id,
            "asset_criticality": self.asset_criticality,
            "threat_activity": self.threat_activity,
            "scanner": self.scanner,
            "status": self.status,
            **priority,
        }


def import_scanner_findings(rows: list[dict]) -> list[dict]:
    """Normalize scanner CSV/JSON rows into scored vulnerability findings."""
    out: list[dict] = []
    for row in rows:
        finding = VulnerabilityFinding(
            cve_id=str(row.get("cve_id") or row.get("cve") or "CVE-UNKNOWN"),
            title=str(row.get("title") or row.get("name") or row.get("cve_id") or "vulnerability"),
            cvss=float(row.get("cvss") or row.get("cvss_score") or 0),
            exploitability=float(row.get("exploitability") or row.get("epss") or 0),
            asset_id=str(row.get("asset_id") or row.get("asset") or "unknown"),
            asset_criticality=float(row.get("asset_criticality") or row.get("criticality") or 50),
            threat_activity=float(row.get("threat_activity") or 0),
            scanner=str(row.get("scanner") or "import"),
            status=str(row.get("status") or "open"),
        )
        out.append(finding.scored())
    return sorted(out, key=lambda item: item["priority"], reverse=True)
