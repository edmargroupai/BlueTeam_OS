from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PS = list((ROOT / "security-languages/powershell").rglob("*.ps1"))
SH = list((ROOT / "security-languages/shell").rglob("*.sh"))

FORBIDDEN_PS = ("Invoke-Expression", "IEX ", "Invoke-Command", "Start-Process powershell")
FORBIDDEN_SH = ("eval ", "curl | sh", "$(curl", "`", "unquoted_user")


@pytest.mark.polyglot
def test_powershell_scripts_are_versioned_and_structured() -> None:
    assert PS
    for path in PS:
        text = path.read_text(encoding="utf-8")
        assert "Version:" in text
        assert "DryRun" in text or "dry_run" in text
        assert "ConvertTo-Json" in text
        for token in FORBIDDEN_PS:
            assert token not in text, f"{path} contains {token}"


@pytest.mark.polyglot
def test_shell_scripts_avoid_eval_and_support_dry_run() -> None:
    assert SH
    for path in SH:
        text = path.read_text(encoding="utf-8")
        assert "set -euo pipefail" in text
        assert "--dry-run" in text
        assert "eval " not in text
        assert "Version:" in text
