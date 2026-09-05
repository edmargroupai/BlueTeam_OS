from pathlib import Path

from blueteam_detection.registry import DetectionRegistry
from blueteam_sigma.compiler import compile_rule

from detections.python.endpoint import ENDPOINT_RULES
from detections.python.identity.brute_force import BruteForceRule
from detections.python.identity.password_spray import PasswordSprayRule
from detections.python.identity.privilege_grant import PrivilegeGrantRule
from detections.python.network import NETWORK_RULES
from detections.python.scheduled import SCHEDULED_RULES

REPO_ROOT = Path(__file__).resolve().parents[2]
SIGMA_PRODUCTION = [
    REPO_ROOT / "security-languages" / "sigma" / "windows" / "proc_office_spawns_powershell.yml"
]


def build_default_registry() -> DetectionRegistry:
    registry = DetectionRegistry()
    registry.register(PasswordSprayRule())
    registry.register(BruteForceRule())
    registry.register(PrivilegeGrantRule())
    for rule in NETWORK_RULES + ENDPOINT_RULES + SCHEDULED_RULES:
        registry.register(rule)
    for path in SIGMA_PRODUCTION:
        if path.exists():
            registry.register(compile_rule(path))
    return registry
