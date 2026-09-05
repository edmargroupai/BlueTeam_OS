"""Self-improvement engine — analytics + candidates; never silent promotion."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Literal

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow

from blueteam_improve.metrics import LanguageMetric, may_auto_promote

CandidateStatus = Literal["proposed", "replayed", "approved", "rejected", "promoted"]


@dataclass
class ImprovementCandidate:
    candidate_id: str
    rule_id: str
    rationale: str
    status: CandidateStatus
    metrics: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    ai_suggested: bool = False
    replay_job_id: str | None = None

    def as_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "rule_id": self.rule_id,
            "rationale": self.rationale,
            "status": self.status,
            "metrics": self.metrics,
            "created_at": self.created_at,
            "ai_suggested": self.ai_suggested,
            "replay_job_id": self.replay_job_id,
            "may_auto_promote": may_auto_promote(False),
        }


def analyse_findings(findings: list[dict[str, Any]], revisions: list[dict[str, Any]] | None = None) -> dict:
    by_rule = Counter(str(item.get("rule_id")) for item in findings)
    noisy = [{"rule_id": rule_id, "count": count} for rule_id, count in by_rule.items() if count >= 20]
    names = Counter()
    for rev in revisions or []:
        names[str(rev.get("name") or rev.get("rule_id"))] += 1
    duplicates = [{"name": name, "revisions": count} for name, count in names.items() if count > 3]
    return {
        "finding_counts": dict(by_rule),
        "noisy_rules": noisy,
        "duplicate_rules": duplicates,
        "language_metrics": [
            LanguageMetric(
                language="python",
                artefact_id=rule_id,
                true_positives=count,
                false_positives=0,
            ).__dict__
            for rule_id, count in list(by_rule.items())[:20]
        ],
    }


class ImprovementEngine:
    def __init__(self) -> None:
        self.candidates: dict[str, ImprovementCandidate] = {}

    def create(
        self,
        *,
        rule_id: str,
        rationale: str,
        metrics: dict[str, Any] | None = None,
        ai_suggested: bool = False,
    ) -> ImprovementCandidate:
        if ai_suggested and may_auto_promote(True):
            # Policy invariant: AI suggestion never flips auto-promote.
            pass
        row = ImprovementCandidate(
            candidate_id=new_id("imp"),
            rule_id=rule_id,
            rationale=rationale,
            status="proposed",
            metrics=metrics or {},
            created_at=utcnow().isoformat(),
            ai_suggested=ai_suggested,
        )
        self.candidates[row.candidate_id] = row
        return row

    def set_status(
        self,
        candidate_id: str,
        status: CandidateStatus,
        *,
        replay_job_id: str | None = None,
    ) -> ImprovementCandidate:
        row = self.candidates[candidate_id]
        if status == "promoted" and row.ai_suggested and not may_auto_promote(False):
            raise PermissionError("AI-suggested candidates cannot promote directly")
        row.status = status
        if replay_job_id:
            row.replay_job_id = replay_job_id
        return row
