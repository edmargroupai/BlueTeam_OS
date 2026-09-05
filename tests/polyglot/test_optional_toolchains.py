from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _run_or_skip(binary: str, args: list[str], cwd: Path) -> str:
    if shutil.which(binary) is None:
        pytest.skip(f"SKIPPED_WITH_REASON: {binary} not installed")
    completed = subprocess.run([binary, *args], cwd=cwd, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        pytest.fail(completed.stdout + completed.stderr)
    return "PASS"


@pytest.mark.polyglot
def test_go_collector_contract() -> None:
    _run_or_skip("go", ["test", "./..."], ROOT / "security-languages/go/cloud-collectors")


@pytest.mark.polyglot
def test_rust_event_model() -> None:
    _run_or_skip("cargo", ["test", "--", "--quiet"], ROOT / "security-languages/rust/event-model")
