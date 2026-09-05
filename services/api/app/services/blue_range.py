from __future__ import annotations

from pathlib import Path

from blueteam_range.loader import load_scenario, load_scenarios
from blueteam_range.runner import run_scenario

from detections.python.catalog import build_default_registry

REPO_ROOT = Path(__file__).resolve().parents[4]
SCENARIO_ROOT = REPO_ROOT / "blue_range" / "scenarios"


def execute_all() -> list[dict]:
    registry = build_default_registry()
    results = [run_scenario(scenario, registry) for scenario in load_scenarios(SCENARIO_ROOT)]
    return [item.model_dump(mode="json") for item in results]


def execute_one(scenario_id: str) -> dict:
    registry = build_default_registry()
    for path in SCENARIO_ROOT.rglob("*.yaml"):
        scenario = load_scenario(path)
        if scenario.id == scenario_id:
            return run_scenario(scenario, registry).model_dump(mode="json")
    raise FileNotFoundError(scenario_id)
