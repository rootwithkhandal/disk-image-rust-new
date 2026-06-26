"""Android acquisition platform module."""

from platforms.android.acquisition import (
    AndroidArtifact,
    AndroidDevice,
    collect_all,
    detect_devices,
    extract_apks,
    extract_call_log,
    extract_contacts,
    extract_facebook,
    extract_instagram,
    extract_installed_apps,
    extract_media,
    extract_messenger,
    extract_sms,
    extract_whatsapp,
)

__all__ = [
    "AndroidDevice",
    "AndroidArtifact",
    "detect_devices",
    "collect_all",
    "extract_sms",
    "extract_contacts",
    "extract_call_log",
    "extract_installed_apps",
    "extract_media",
    "extract_apks",
    "extract_whatsapp",
    "extract_facebook",
    "extract_messenger",
    "extract_instagram",
]
