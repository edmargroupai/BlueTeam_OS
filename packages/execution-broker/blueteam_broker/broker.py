"""Python-controlled execution broker. No generic remote shell."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from blueteam_common.errors import BlueTeamError, PermissionDeniedError
from blueteam_common.ids import new_id
from blueteam_playbook.policy import ActionTier, evaluate_action
from blueteam_rego.engine import evaluate as evaluate_rego
from blueteam_schemas.actions import ActionRequest, ActionResult

from blueteam_broker.registry import ActionSpec, default_registry

FORBIDDEN_ACTION_PREFIXES = ("shell.exec", "powershell.invoke_raw", "bash.eval", "os.system")


class ExecutionBroker:
    def __init__(
        self,
        registry: dict[str, ActionSpec] | None = None,
        *,
        handlers: dict[str, Callable[[ActionRequest, ActionSpec], dict[str, Any]]] | None = None,
    ) -> None:
        self.registry = registry or default_registry()
        self.handlers = handlers or {}

    def submit(self, request: ActionRequest) -> ActionResult:
        if any(request.action_type.startswith(prefix) for prefix in FORBIDDEN_ACTION_PREFIXES):
            raise BlueTeamError("ACTION_FORBIDDEN", "Arbitrary command execution is not a registered action", 403)
        spec = self.registry.get(request.action_type)
        if spec is None:
            raise BlueTeamError("ACTION_UNREGISTERED", f"Action {request.action_type} is not registered", 400)
        extra = set(request.params) - spec.allowed_params
        extra |= set(request.target) - spec.allowed_params
        if extra:
            raise BlueTeamError("ACTION_SCHEMA", f"Unsupported parameters: {sorted(extra)}", 422)
        if spec.required_permission not in request.permissions and "admin:platform" not in request.permissions:
            raise PermissionDeniedError(f"Missing permission {spec.required_permission}")

        playbook = evaluate_action(request.action_type, ActionTier(spec.tier))
        domain = request.action_type.split(".", 1)[0]
        policy = evaluate_rego(
            {
                "action": {
                    "type": request.action_type,
                    "tier": spec.tier,
                    "read_only": spec.read_only,
                    "dry_run": request.dry_run,
                },
                "environment": request.params.get("environment", "unknown"),
                "confidence": float(request.params.get("confidence", 0)),
                "auto_containment": bool(request.params.get("auto_containment", False)),
                "domain": request.params.get("domain", domain),
                "requested_by_ai": bool(request.params.get("requested_by_ai", False)),
            }
        )
        decision = policy.decision
        if playbook == "REQUIRE_APPROVAL" and decision == "ALLOW":
            decision = "REQUIRE_APPROVAL"
        if decision == "DENY":
            return self._result(request, spec, decision, "denied", error=policy.reason)
        if decision == "REQUIRE_APPROVAL" and not request.dry_run:
            return self._result(request, spec, decision, "awaiting_approval", approval="required")

        if request.dry_run or spec.read_only:
            outputs = self._execute(request, spec)
            return self._result(
                request,
                spec,
                decision,
                "planned" if request.dry_run else outputs.get("status", "executed"),
                outputs=outputs,
                skip_reason=outputs.get("skip_reason"),
            )
        return self._result(request, spec, decision, "denied", error="Non-read-only execution requires approval")

    def _execute(self, request: ActionRequest, spec: ActionSpec) -> dict[str, Any]:
        if spec.action_type in self.handlers:
            return self.handlers[spec.action_type](request, spec)
        if spec.language in {"powershell", "bash"}:
            return self._plan_or_run_script(request, spec)
        if spec.language == "yara":
            from blueteam_yara.engine import scan_b64

            return scan_b64(request.params)
        if spec.language == "blueql":
            from blueteam_blueql.engine import explain, parse

            query = str(request.params.get("query", ""))
            ast = parse(query)
            return {"ast": ast.to_dict(), "explain": explain(ast), "dry_run": True}
        if spec.language == "sql":
            from blueteam_sql.engine import describe

            return describe(str(request.params.get("query_id", "")))
        if spec.language == "rego":
            return evaluate_rego(
                {
                    "action": {
                        "type": str(request.params.get("proposed_action", "unknown")),
                        "tier": 2 if str(request.params.get("proposed_action", "")).startswith("isolate") else 0,
                        "read_only": False,
                        "dry_run": request.dry_run,
                    },
                    "environment": request.params.get("environment", "unknown"),
                    "confidence": float(request.params.get("confidence", 0)),
                    "auto_containment": bool(request.params.get("auto_containment", False)),
                }
            ).as_dict()
        return {"planned": True, "executor": spec.language}

    def _plan_or_run_script(self, request: ActionRequest, spec: ActionSpec) -> dict[str, Any]:
        if spec.script_path is None or not spec.script_path.exists():
            return {"skip_reason": "script missing", "status": "skipped"}
        digest = hashlib.sha256(spec.script_path.read_bytes()).hexdigest()
        runtime = "pwsh" if spec.language == "powershell" else "bash"
        if spec.language == "powershell":
            binary = shutil.which(runtime) or shutil.which("powershell")
        else:
            binary = shutil.which("bash")
        planned = {
            "script": str(spec.script_path),
            "script_sha256": digest,
            "runtime": runtime,
            "args": dict(request.params),
            "dry_run": request.dry_run,
            "invoke_expression": False,
            "arbitrary_shell": False,
        }
        if binary is None:
            planned["skip_reason"] = f"{runtime} not installed"
            planned["status"] = "skipped"
            return planned
        if request.dry_run:
            planned["status"] = "planned"
            return planned
        cmd = self._safe_command(spec, binary, request)
        completed = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=20)  # noqa: S603
        return {
            **planned,
            "dry_run": False,
            "exit_code": completed.returncode,
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-1000:],
            "status": "executed" if completed.returncode == 0 else "failed",
        }

    def _safe_command(self, spec: ActionSpec, binary: str, request: ActionRequest) -> list[str]:
        assert spec.script_path is not None
        if spec.language == "powershell":
            cmd = [binary, "-NoProfile", "-NonInteractive", "-File", str(spec.script_path)]
            if request.dry_run:
                cmd.append("-DryRun")
            if "limit" in request.params:
                cmd.extend(["-Limit", str(int(request.params["limit"]))])
            if "max_events" in request.params:
                cmd.extend(["-MaxEvents", str(int(request.params["max_events"]))])
            return cmd
        cmd = [binary, str(spec.script_path)]
        if request.dry_run:
            cmd.append("--dry-run")
        if "limit" in request.params:
            cmd.extend(["--limit", str(int(request.params["limit"]))])
        return cmd

    def _result(
        self,
        request: ActionRequest,
        spec: ActionSpec,
        decision: str,
        status: str,
        *,
        outputs: dict[str, Any] | None = None,
        skip_reason: str | None = None,
        error: str | None = None,
        approval: str | None = None,
    ) -> ActionResult:
        return ActionResult(
            action_id=request.action_id or new_id("act"),
            action_type=request.action_type,
            tenant_id=request.tenant_id,
            policy_decision=decision,  # type: ignore[arg-type]
            approval_status=approval,
            executor=spec.language,
            rollback_available=spec.rollback_available,
            status=status,  # type: ignore[arg-type]
            dry_run=request.dry_run,
            outputs=outputs or {},
            skip_reason=skip_reason,
            error=error,
            completed_at=datetime.now(UTC),
        )
