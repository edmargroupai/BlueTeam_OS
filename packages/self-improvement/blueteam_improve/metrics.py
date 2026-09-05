"""Language-layer metrics. Recommendations only — never silent promotion."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LanguageMetric:
    language: str
    artefact_id: str
    true_positives: int
    false_positives: int
    replay_score: float | None = None


def may_auto_promote(policy_allows: bool) -> bool:
    return bool(policy_allows)
