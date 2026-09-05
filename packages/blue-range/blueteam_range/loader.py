from __future__ import annotations

from pathlib import Path

import yaml

from blueteam_range.models import RangeScenario


def load_scenario(path: Path) -> RangeScenario:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return RangeScenario.model_validate(payload)


def load_scenarios(root: Path) -> list[RangeScenario]:
    scenarios: list[RangeScenario] = []
    for file in sorted(root.rglob("*.yaml")):
        scenarios.append(load_scenario(file))
    return scenarios
