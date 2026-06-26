"""ForgeLens Offensive DFIR module (v2.3)."""

from core.dfir.offensive import (
    DFIRFinding,
    DFIRReport,
    OffensiveDFIR,
    detect_beacons,
    detect_credential_theft,
    hunt_persistence,
    map_lateral_movement,
    triage_ransomware,
)

__all__ = [
    "OffensiveDFIR",
    "DFIRFinding",
    "DFIRReport",
    "hunt_persistence",
    "detect_beacons",
    "detect_credential_theft",
    "triage_ransomware",
    "map_lateral_movement",
]
