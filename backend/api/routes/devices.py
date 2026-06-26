from fastapi import APIRouter
from pydantic import BaseModel

from core.acquisition.device_detector import DeviceDetector, DeviceType

router = APIRouter(tags=["devices"])

class DeviceResponse(BaseModel):
    id: str
    label: str
    type: str
    sizeGb: float
    interface: str
    serial: str
    removable: bool
    encrypted: bool = False

@router.get("/devices", response_model=list[DeviceResponse])
def get_devices():
    """Detect and return all physical storage and mobile devices."""
    detected = DeviceDetector.detect()
    
    # Optional: also scan for Android devices
    try:
        android_devices = DeviceDetector.detect_android()
        detected.extend(android_devices)
    except Exception:
        pass
        
    response = []
    for d in detected:
        # Map backend DeviceType to frontend expected types
        frontend_type = "disk"
        if d.device_type == DeviceType.ANDROID:
            frontend_type = "android"
        elif d.is_removable or d.device_type == DeviceType.REMOVABLE:
            frontend_type = "removable"
            
        response.append(
            DeviceResponse(
                id=d.device_id,
                label=d.label or d.model or "Unknown Device",
                type=frontend_type,
                sizeGb=d.size_gb,
                interface=d.interface or "Unknown",
                serial=d.serial or "",
                removable=d.is_removable,
                encrypted=False  # TODO: implement encryption check
            )
        )
        
    return response
