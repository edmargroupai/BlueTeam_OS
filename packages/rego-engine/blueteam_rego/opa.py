"""Real OPA evaluation. OPA decides; Python still orchestrates and never lets OPA execute."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
POLICY_ROOT = REPO_ROOT / "security-languages" / "rego"


def opa_binary() -> str | None:
    return shutil.which("opa")


def opa_available() -> bool:
    return opa_binary() is not None


def evaluate_opa(input_doc: dict[str, Any], *, query: str = "data.blueteam.policy.result") -> dict[str, Any]:
    binary = opa_binary()
    if binary is None:
        raise RuntimeError("opa binary is not installed")
    core = POLICY_ROOT / "policy" / "core.rego"
    files = [str(core)] if core.exists() else [str(path) for path in sorted(POLICY_ROOT.rglob("*.rego"))]
    if not files:
        raise RuntimeError("no Rego policy files found")
    completed = subprocess.run(  # noqa: S603
        [binary, "eval", "--format=json", "--stdin-input", *sum((["-d", path] for path in files), []), query],
        input=json.dumps(input_doc),
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr[-1000:] or "opa eval failed")
    payload = json.loads(completed.stdout)
    results = payload.get("result") or []
    if not results:
        return {"decision": "DENY", "reason": "OPA returned no result — default deny", "engine": "opa"}
    expressions = results[0].get("expressions") or []
    value = expressions[0].get("value") if expressions else {"decision": "DENY"}
    if isinstance(value, str):
        return {"decision": value, "reason": "OPA decision", "engine": "opa"}
    if isinstance(value, dict):
        return {
            "decision": str(value.get("decision", "DENY")),
            "reason": str(value.get("reason", "OPA decision")),
            "engine": "opa",
            "policy": str(value.get("policy", "blueteam.policy")),
        }
    return {"decision": "DENY", "reason": "unrecognised OPA result — default deny", "engine": "opa"}
