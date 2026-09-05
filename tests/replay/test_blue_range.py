from __future__ import annotations

from pathlib import Path

import pytest
from blueteam_range.loader import load_scenarios
from blueteam_range.runner import run_scenario

from detections.python.catalog import build_default_registry

ROOT = Path(__file__).resolve().parents[2] / "blue_range" / "scenarios"


@pytest.mark.blue_range
def test_identity_blue_range_scenarios_pass() -> None:
    registry = build_default_registry()
    scenarios = load_scenarios(ROOT)
    assert len(scenarios) >= 3
    failures = []
    for scenario in scenarios:
        result = run_scenario(scenario, registry)
        if not result.passed:
            failures.append((scenario.id, result.errors, result.assertions))
    assert failures == []
