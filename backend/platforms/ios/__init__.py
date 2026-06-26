"""iOS acquisition platform module."""

from platforms.ios.acquisition import (
    IOSArtifact,
    IOSDevice,
    collect_all,
    detect_devices,
    extract_afc,
    extract_itunes_backup,
    extract_media,
    get_sysdiagnose,
)

__all__ = [
    "IOSDevice",
    "IOSArtifact",
    "detect_devices",
    "collect_all",
    "extract_itunes_backup",
    "extract_afc",
    "extract_media",
    "get_sysdiagnose",
]
