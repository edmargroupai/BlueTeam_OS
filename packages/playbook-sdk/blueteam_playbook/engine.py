"""Playbook DAG engine — retries, idempotency, approvals, rollback hooks."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow

from blueteam_playbook.policy import ActionTier, evaluate_action

StepStatus = Literal["success", "skipped", "failed", "awaiting_approval", "denied"]


@dataclass
class PlaybookStepDef:
    id: str
    action_type: str
    depends_on: list[str] = field(default_factory=list)
    tier: int = 0
    retries: int = 0
    params: dict[str, Any] = field(default_factory=dict)
    rollback_action: str | None = None


@dataclass
class PlaybookDef:
    playbook_id: str
    name: str
    steps: list[PlaybookStepDef]
    description: str = ""


@dataclass
class StepRun:
    step_id: str
    action_type: str
    status: StepStatus
    attempts: int = 0
    outputs: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    rollback_hook: str | None = None


@dataclass
class PlaybookRun:
    run_id: str
    playbook_id: str
    tenant_id: str
    status: str
    dry_run: bool
    idempotency_key: str
    steps: list[StepRun] = field(default_factory=list)
    approval_required: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str | None = None

    def as_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "playbook_id": self.playbook_id,
            "tenant_id": self.tenant_id,
            "status": self.status,
            "dry_run": self.dry_run,
            "idempotency_key": self.idempotency_key,
            "approval_required": self.approval_required,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "steps": [
                {
                    "step_id": step.step_id,
                    "action_type": step.action_type,
                    "status": step.status,
                    "attempts": step.attempts,
                    "outputs": step.outputs,
                    "error": step.error,
                    "rollback_hook": step.rollback_hook,
                }
                for step in self.steps
            ],
        }


Executor = Callable[[str, dict[str, Any], bool], dict[str, Any]]


class PlaybookEngine:
    def __init__(self, *, executor: Executor | None = None) -> None:
        self.executor = executor or _default_executor
        self._runs: dict[str, PlaybookRun] = {}
        self._by_idempotency: dict[str, str] = {}

    def run(
        self,
        playbook: PlaybookDef,
        *,
        tenant_id: str,
        dry_run: bool = True,
        idempotency_key: str | None = None,
        approved_steps: set[str] | None = None,
    ) -> PlaybookRun:
        key = idempotency_key or f"{playbook.playbook_id}:{tenant_id}:auto"
        if key in self._by_idempotency:
            existing = self._runs[self._by_idempotency[key]]
            return existing
        approved_steps = approved_steps or set()
        run = PlaybookRun(
            run_id=new_id("pbr"),
            playbook_id=playbook.playbook_id,
            tenant_id=tenant_id,
            status="running",
            dry_run=dry_run,
            idempotency_key=key,
            started_at=utcnow().isoformat(),
        )
        completed: set[str] = set()
        pending = {step.id: step for step in playbook.steps}
        while pending:
            progress = False
            for step_id, step in list(pending.items()):
                if any(dep not in completed for dep in step.depends_on):
                    continue
                progress = True
                del pending[step_id]
                decision = evaluate_action(step.action_type, ActionTier(step.tier))
                if decision == "REQUIRE_APPROVAL" and not dry_run and step_id not in approved_steps:
                    run.steps.append(
                        StepRun(
                            step_id=step_id,
                            action_type=step.action_type,
                            status="awaiting_approval",
                            attempts=0,
                            rollback_hook=step.rollback_action,
                        )
                    )
                    run.approval_required.append(step_id)
                    continue
                if decision == "DENY":
                    run.steps.append(
                        StepRun(step_id=step_id, action_type=step.action_type, status="denied", attempts=1)
                    )
                    run.status = "failed"
                    run.finished_at = utcnow().isoformat()
                    self._store(run)
                    return run
                attempts = 0
                last_error = None
                outputs: dict[str, Any] = {}
                while attempts <= step.retries:
                    attempts += 1
                    try:
                        outputs = self.executor(step.action_type, step.params, dry_run)
                        last_error = None
                        break
                    except Exception as exc:  # noqa: BLE001 — playbook retries bounded
                        last_error = str(exc)
                if last_error:
                    run.steps.append(
                        StepRun(
                            step_id=step_id,
                            action_type=step.action_type,
                            status="failed",
                            attempts=attempts,
                            error=last_error,
                            rollback_hook=step.rollback_action,
                        )
                    )
                    run.status = "failed"
                    run.finished_at = utcnow().isoformat()
                    self._store(run)
                    return run
                run.steps.append(
                    StepRun(
                        step_id=step_id,
                        action_type=step.action_type,
                        status="success",
                        attempts=attempts,
                        outputs=outputs,
                        rollback_hook=step.rollback_action,
                    )
                )
                completed.add(step_id)
            if not progress:
                break
        if run.approval_required:
            run.status = "awaiting_approval"
        elif pending:
            run.status = "failed"
            run.steps.append(
                StepRun(
                    step_id="dag",
                    action_type="playbook.dag",
                    status="failed",
                    error="Unresolved dependencies or cycle",
                )
            )
        else:
            run.status = "completed"
        run.finished_at = utcnow().isoformat()
        self._store(run)
        return run

    def approve(self, run_id: str, step_ids: list[str], playbook: PlaybookDef) -> PlaybookRun:
        prior = self._runs.get(run_id)
        if prior is None:
            raise KeyError(run_id)
        # Clear idempotency so a resume can execute.
        self._by_idempotency.pop(prior.idempotency_key, None)
        return self.run(
            playbook,
            tenant_id=prior.tenant_id,
            dry_run=prior.dry_run,
            idempotency_key=f"{prior.idempotency_key}:approved:{','.join(sorted(step_ids))}",
            approved_steps=set(step_ids) | set(prior.approval_required),
        )

    def get(self, run_id: str) -> PlaybookRun | None:
        return self._runs.get(run_id)

    def _store(self, run: PlaybookRun) -> None:
        self._runs[run.run_id] = run
        self._by_idempotency[run.idempotency_key] = run.run_id


def _default_executor(action_type: str, params: dict[str, Any], dry_run: bool) -> dict[str, Any]:
    return {
        "action_type": action_type,
        "params": params,
        "dry_run": dry_run,
        "status": "planned" if dry_run else "executed",
        "note": "Default playbook executor — wire broker for live actions.",
    }


CATALOGUE: dict[str, PlaybookDef] = {
    "pb.contain_host_t0": PlaybookDef(
        playbook_id="pb.contain_host_t0",
        name="Collect then plan isolate",
        description="T0 collect processes, then T2 isolate (approval required when not dry-run).",
        steps=[
            PlaybookStepDef(id="collect", action_type="collect.windows.processes", tier=0, retries=1),
            PlaybookStepDef(
                id="isolate",
                action_type="isolate.host",
                tier=2,
                depends_on=["collect"],
                rollback_action="release.host",
            ),
        ],
    ),
    "pb.enrich_only": PlaybookDef(
        playbook_id="pb.enrich_only",
        name="Read-only enrichment chain",
        description="T0 DAG with two collect steps.",
        steps=[
            PlaybookStepDef(id="a", action_type="collect.windows.processes", tier=0),
            PlaybookStepDef(id="b", action_type="collect.windows.events", tier=0, depends_on=["a"]),
        ],
    ),
}


def get_playbook(playbook_id: str) -> PlaybookDef:
    if playbook_id not in CATALOGUE:
        from blueteam_common.errors import BlueTeamError

        raise BlueTeamError("UNKNOWN_PLAYBOOK", f"Playbook {playbook_id} not found", 404)
    return CATALOGUE[playbook_id]
