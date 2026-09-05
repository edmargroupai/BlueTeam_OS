from __future__ import annotations

from datetime import UTC, datetime

from blueteam_quality.engine import compute_quality_index
from blueteam_schemas.quality import QualityCheckResult


def test_missing_evidence_awards_zero() -> None:
    index = compute_quality_index(
        [
            QualityCheckResult(
                check_id="identity.fake",
                domain="identity_security",
                title="Pretend pass",
                max_points=80,
                awarded_points=80,
                passed=True,
                evidence_ids=[],
                reason="UI page exists",
            )
        ],
        computed_at=datetime.now(UTC),
    )
    assert index.domains["identity_security"] == 0
    assert index.total == 0
    assert index.band == "prototype"
    assert index.checks[0].passed is False


def test_evidence_backed_points_are_capped_per_domain() -> None:
    index = compute_quality_index(
        [
            QualityCheckResult(
                check_id="identity.real",
                domain="identity_security",
                title="Blue Range pass",
                max_points=50,
                awarded_points=50,
                passed=True,
                evidence_ids=["br-identity-password-spray"],
                reason="scenario passed",
            )
        ],
        computed_at=datetime.now(UTC),
    )
    assert index.domains["identity_security"] == 50
    assert index.total == 50
    assert index.band == "prototype"
