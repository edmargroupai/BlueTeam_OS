from detections.python.network.beacon import RepetitiveBeaconRule
from detections.python.network.east_west import UnusualEastWestRule
from detections.python.network.horizontal_scan import HorizontalScanRule
from detections.python.network.rare_destination import RareDestinationRule
from detections.python.network.suspicious_dns import SuspiciousDnsRule
from detections.python.network.vertical_scan import VerticalScanRule

NETWORK_RULES = [
    HorizontalScanRule(),
    VerticalScanRule(),
    RareDestinationRule(),
    RepetitiveBeaconRule(),
    SuspiciousDnsRule(),
    UnusualEastWestRule(),
]
