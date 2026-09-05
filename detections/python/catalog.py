from pathlib import Path

from blueteam_detection.registry import DetectionRegistry
from blueteam_sigma.compiler import compile_rule

from detections.python.endpoint import ENDPOINT_RULES
from detections.python.identity.brute_force import BruteForceRule
from detections.python.identity.dormant_account import DormantAccountRule
from detections.python.identity.impossible_travel import ImpossibleTravelRule
from detections.python.identity.mfa_fatigue import MfaFatigueRule
from detections.python.identity.password_spray import PasswordSprayRule
from detections.python.identity.privilege_grant import PrivilegeGrantRule
from detections.python.identity.repeated_failures import RepeatedFailuresRule
from detections.python.identity.service_account_misuse import ServiceAccountMisuseRule
from detections.python.identity.unusual_success import UnusualSuccessRule
from detections.python.network import NETWORK_RULES
from detections.python.scheduled import SCHEDULED_RULES

REPO_ROOT = Path(__file__).resolve().parents[2]
SIGMA_PRODUCTION = [
    REPO_ROOT / "security-languages" / "sigma" / "windows" / "proc_office_spawns_powershell.yml"
]


def build_default_registry() -> DetectionRegistry:
    registry = DetectionRegistry()
    for rule in (
        PasswordSprayRule(),
        BruteForceRule(),
        PrivilegeGrantRule(),
        RepeatedFailuresRule(),
        UnusualSuccessRule(),
        ImpossibleTravelRule(),
        MfaFatigueRule(),
        DormantAccountRule(),
        ServiceAccountMisuseRule(),
    ):
        registry.register(rule)
    for rule in NETWORK_RULES + ENDPOINT_RULES + SCHEDULED_RULES:
        registry.register(rule)
    for path in SIGMA_PRODUCTION:
        if path.exists():
            registry.register(compile_rule(path))
    return registry
