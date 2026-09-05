"""CI gate: invalid or incomplete production rules fail the build."""

from __future__ import annotations

from detections.python.catalog import build_default_registry

ALLOWED_STATUS = {"draft", "tested", "promoted", "disabled"}
ALLOWED_EXECUTION = {"realtime", "scheduled", "threshold"}


def lint_rules() -> list[str]:
    errors: list[str] = []
    registry = build_default_registry()
    seen: set[str] = set()
    for rule in registry.all_rules():
        meta = rule.meta
        if not meta.rule_id:
            errors.append("rule missing rule_id")
            continue
        if meta.rule_id in seen:
            errors.append(f"duplicate rule_id {meta.rule_id}")
        seen.add(meta.rule_id)
        if not meta.version or "." not in meta.version:
            errors.append(f"{meta.rule_id}: version must be semver-like")
        if meta.status not in ALLOWED_STATUS:
            errors.append(f"{meta.rule_id}: invalid status {meta.status}")
        if getattr(meta, "execution", "realtime") not in ALLOWED_EXECUTION:
            errors.append(f"{meta.rule_id}: invalid execution {meta.execution}")
        if not meta.mitre_techniques:
            errors.append(f"{meta.rule_id}: ATT&CK techniques required")
        if not callable(getattr(rule, "evaluate", None)):
            errors.append(f"{meta.rule_id}: evaluate() missing")
        if meta.rule_id == "sigma.identity.failed_logon_burst":
            errors.append("sigma/identity/failed_logon_burst.yml must not be in the default registry")
    if len(registry.all_rules()) < 3:
        errors.append("production catalogue has too few rules")
    return errors


def main() -> int:
    errors = lint_rules()
    for item in errors:
        print(f"ERROR {item}")
    if errors:
        return 1
    print(f"OK {len(build_default_registry().all_rules())} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
