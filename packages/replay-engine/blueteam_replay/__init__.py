"""Replay and validation lab — Blue Range backed regression jobs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blueteam_common.hashing import sha256_hex
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_detection.registry import DetectionRegistry
from blueteam_range.loader import load_scenarios
from blueteam_range.runner import run_scenario


@dataclass
class ReplayDataset:
    dataset_id: str
    name: str
    path: str
    checksum: str
    scenario_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "dataset_id": self.dataset_id,
            "name": self.name,
            "path": self.path,
            "checksum": self.checksum,
            "scenario_ids": self.scenario_ids,
        }


@dataclass
class ReplayJob:
    job_id: str
    dataset_id: str
    mode: str  # current | candidate | compare
    passed: bool
    started_at: str
    finished_at: str
    latency_seconds: float
    results: list[dict[str, Any]] = field(default_factory=list)
    comparison: dict[str, Any] | None = None
    rule_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "dataset_id": self.dataset_id,
            "mode": self.mode,
            "passed": self.passed,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "latency_seconds": self.latency_seconds,
            "results": self.results,
            "comparison": self.comparison,
            "rule_ids": self.rule_ids,
        }


class ReplayLab:
    def __init__(self, scenario_root: Path) -> None:
        self.scenario_root = scenario_root
        self.datasets: dict[str, ReplayDataset] = {}
        self.jobs: dict[str, ReplayJob] = {}
        self._rule_pass: dict[str, bool] = {}

    def register_dataset(self, *, name: str, relative_path: str = ".") -> ReplayDataset:
        path = (self.scenario_root / relative_path).resolve()
        root = self.scenario_root.resolve()
        if path != root and root not in path.parents:
            raise ValueError("dataset path must stay under Blue Range scenario root")
        if not path.exists():
            raise ValueError(f"dataset path missing: {path}")
        scenarios = load_scenarios(path if path.is_dir() else path.parent)
        checksum = sha256_hex("|".join(sorted(item.id for item in scenarios)))
        dataset = ReplayDataset(
            dataset_id=new_id("rds"),
            name=name,
            path=str(path if path.is_dir() else path.parent),
            checksum=checksum,
            scenario_ids=[item.id for item in scenarios],
        )
        self.datasets[dataset.dataset_id] = dataset
        return dataset

    def run(
        self,
        dataset_id: str,
        *,
        current: DetectionRegistry,
        candidate: DetectionRegistry | None = None,
        mode: str = "current",
    ) -> ReplayJob:
        dataset = self.datasets.get(dataset_id)
        if dataset is None:
            raise KeyError(dataset_id)
        started = utcnow()
        scenarios = load_scenarios(Path(dataset.path))
        current_results = [run_scenario(item, current) for item in scenarios]
        comparison = None
        if candidate is not None and mode in {"candidate", "compare"}:
            candidate_results = [run_scenario(item, candidate) for item in scenarios]
            comparison = {
                "current_passed": sum(1 for item in current_results if item.passed),
                "candidate_passed": sum(1 for item in candidate_results if item.passed),
                "current_latency": round(sum(item.latency_seconds for item in current_results), 4),
                "candidate_latency": round(sum(item.latency_seconds for item in candidate_results), 4),
                "regressions": [
                    item.scenario_id
                    for cur, item in zip(current_results, candidate_results, strict=False)
                    if cur.passed and not item.passed
                ],
            }
            results = candidate_results if mode == "candidate" else current_results
            passed = (
                all(item.passed for item in candidate_results)
                if mode == "candidate"
                else all(item.passed for item in current_results) and not comparison["regressions"]
            )
        else:
            results = current_results
            passed = all(item.passed for item in current_results)

        finished = utcnow()
        rule_ids = sorted({assertion.rule_id for result in results for assertion in result.assertions})
        job = ReplayJob(
            job_id=new_id("rpl"),
            dataset_id=dataset_id,
            mode=mode,
            passed=passed,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            latency_seconds=(finished - started).total_seconds(),
            results=[
                {
                    "scenario_id": item.scenario_id,
                    "passed": item.passed,
                    "latency_seconds": item.latency_seconds,
                    "errors": item.errors,
                    "assertions": [
                        {
                            "rule_id": assertion.rule_id,
                            "expected_min": assertion.expected_min,
                            "observed": assertion.observed,
                            "passed": assertion.passed,
                        }
                        for assertion in item.assertions
                    ],
                }
                for item in results
            ],
            comparison=comparison,
            rule_ids=rule_ids,
        )
        self.jobs[job.job_id] = job
        for rule_id in rule_ids:
            # A rule may promote only when the latest job covering it passed.
            self._rule_pass[rule_id] = passed
        return job

    def clear(self) -> None:
        self.datasets.clear()
        self.jobs.clear()
        self._rule_pass.clear()

    def rule_regression_passed(self, rule_id: str) -> bool:
        return bool(self._rule_pass.get(rule_id))

    def latest_job(self) -> ReplayJob | None:
        if not self.jobs:
            return None
        return next(reversed(self.jobs.values()))
