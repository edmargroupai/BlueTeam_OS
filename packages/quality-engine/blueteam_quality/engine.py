"""Quality index: missing evidence is a fail, never an implicit pass."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime

from blueteam_schemas.quality import (
    QUALITY_DOMAINS,
    QualityCheckResult,
    QualityIndex,
    maturity_band,
)

MODEL_VERSION = "qi-1.0.0"


def compute_quality_index(
    checks: Sequence[QualityCheckResult],
    *,
    computed_at: datetime,
    model_version: str = MODEL_VERSION,
) -> QualityIndex:
    domain_scores: dict[str, int] = {domain: 0 for domain in QUALITY_DOMAINS}
    awarded_by_domain: dict[str, int] = defaultdict(int)
    normalized: list[QualityCheckResult] = []

    for check in checks:
        if check.domain not in QUALITY_DOMAINS:
            raise ValueError(f"unknown quality domain: {check.domain}")
        awarded = check.awarded_points
        if not check.evidence_ids:
            awarded = 0
            check = check.model_copy(
                update={
                    "awarded_points": 0,
                    "passed": False,
                    "reason": f"{check.reason} Missing evidence — score withheld.",
                }
            )
        elif not check.passed:
            awarded = 0
            check = check.model_copy(update={"awarded_points": 0})
        awarded_by_domain[check.domain] += awarded
        normalized.append(check)

    for domain, ceiling in QUALITY_DOMAINS.items():
        domain_scores[domain] = min(ceiling, awarded_by_domain[domain])

    total = sum(domain_scores.values())
    return QualityIndex(
        model_version=model_version,
        computed_at=computed_at,
        total=total,
        band=maturity_band(total),
        domains=domain_scores,
        checks=normalized,
    )
