from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "blueteam_ai_gateway",
    ROOT / "services" / "ai-gateway" / "app" / "gateway.py",
)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def test_detection_path_never_routes_to_model() -> None:
    decision = module.route(
        module.AIRequest(
            tenant_id="ten_x",
            feature="detection",
            task_type="detect",
            context_refs=[],
            requested_capability="summarise",
            max_cost=1,
            max_tokens=100,
            sensitivity="low",
            structured_output_schema={},
        ),
        ai_enabled=True,
    )
    assert decision.decision == "deterministic_only"


def test_offline_gateway_does_not_call_provider() -> None:
    decision = module.route(
        module.AIRequest(
            tenant_id="ten_x",
            feature="soc-analyst",
            task_type="summarise",
            context_refs=["evi_1"],
            requested_capability="incident_summary",
            max_cost=1,
            max_tokens=100,
            sensitivity="low",
            structured_output_schema={},
        ),
        ai_enabled=False,
    )
    assert decision.decision == "deterministic_only"
    assert decision.provider is None
