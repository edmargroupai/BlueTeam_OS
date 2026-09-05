from detections.python.endpoint.encoded_powershell import EncodedPowershellRule
from detections.python.endpoint.office_shell import OfficeSpawnsShellRule
from detections.python.endpoint.persistence import (
    RegistryPersistenceRule,
    ScheduledTaskPersistenceRule,
    ServicePersistenceRule,
)
from detections.python.endpoint.process_network import ProcessNetworkChainRule
from detections.python.endpoint.rare_path import RareExecutablePathRule
from detections.python.endpoint.script_interpreter import SuspiciousScriptInterpreterRule
from detections.python.endpoint.unusual_child import UnusualChildProcessRule

ENDPOINT_RULES = [
    OfficeSpawnsShellRule(),
    EncodedPowershellRule(),
    SuspiciousScriptInterpreterRule(),
    ServicePersistenceRule(),
    ScheduledTaskPersistenceRule(),
    RegistryPersistenceRule(),
    UnusualChildProcessRule(),
    RareExecutablePathRule(),
    ProcessNetworkChainRule(),
]
