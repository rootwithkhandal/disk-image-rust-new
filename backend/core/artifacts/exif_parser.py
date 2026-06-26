"""
EXIF Metadata Parser Engine
==============================
Extracts EXIF, IPTC, and XMP metadata from images and documents.
Supports GPS coordinate extraction, device fingerprinting,
and timestamp analysis.

Uses: Pillow (PIL) for basic EXIF, exifread for full EXIF support.

Usage:
    from core.artifacts.exif_parser import ExifParser

    parser = ExifParser()
    result = parser.parse("/evidence/photo.jpg")
    print(result.gps_coordinates)
    print(result.device_make, result.device_model)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger


@dataclass
class GPSCoordinates:
    latitude: float
    longitude: float
    altitude: float | None = None
    timestamp: str = ""

    def __str__(self) -> str:
        return f"{self.latitude:.6f}, {self.longitude:.6f}"

    @property
    def google_maps_url(self) -> str:
        return f"https://maps.google.com/?q={self.latitude},{self.longitude}"


@dataclass
class ExifResult:
    file_path: str
    file_type: str = ""
    # Device info
    device_make: str = ""
    device_model: str = ""
    software: str = ""
    # Timestamps
    datetime_original: str = ""
    datetime_digitized: str = ""
    datetime_modified: str = ""
    # Camera settings
    focal_length: str = ""
    aperture: str = ""
    shutter_speed: str = ""
    iso: str = ""
    flash: str = ""
    # GPS
    gps: GPSCoordinates | None = None
    # Image info
    width: int = 0
    height: int = 0
    color_space: str = ""
    # All raw tags
    raw_tags: dict = field(default_factory=dict)
    # Errors
    errors: list[str] = field(default_factory=list)

    @property
    def has_gps(self) -> bool:
        return self.gps is not None

    @property
    def has_device_info(self) -> bool:
        return bool(self.device_make or self.device_model)

    def to_dict(self) -> dict:
        d = {
            "file_path": self.file_path,
            "file_type": self.file_type,
            "device_make": self.device_make,
            "device_model": self.device_model,
            "software": self.software,
            "datetime_original": self.datetime_original,
            "datetime_modified": self.datetime_modified,
            "width": self.width,
            "height": self.height,
            "has_gps": self.has_gps,
        }
        if self.gps:
            d["gps_lat"] = self.gps.latitude
            d["gps_lon"] = self.gps.longitude
            d["gps_maps_url"] = self.gps.google_maps_url
        return d


class ExifParser:
    """
    Extracts EXIF metadata from image files.
    Falls back gracefully if optional libraries are not installed.
    """

    def __init__(self) -> None:
        self._pillow_available = self._check_pillow()
        self._exifread_available = self._check_exifread()

    def _check_pillow(self) -> bool:
        try:
            from PIL import Image  # noqa: F401

            return True
        except ImportError:
            logger.debug("Pillow not installed — basic EXIF unavailable. Run: pip install Pillow")
            return False

    def _check_exifread(self) -> bool:
        try:
            import exifread  # noqa: F401

            return True
        except ImportError:
            logger.debug(
                "exifread not installed — full EXIF unavailable. Run: pip install exifread"
            )
            return False

    def parse(self, file_path: str | Path) -> ExifResult:
        """
        Parse EXIF metadata from an image file.
        Tries exifread first (more complete), falls back to Pillow.
        """
        path = Path(file_path)
        result = ExifResult(file_path=str(path), file_type=path.suffix.lower())

        if not path.exists():
            result.errors.append(f"File not found: {path}")
            return result

        # Try exifread (most complete)
        if self._exifread_available:
            self._parse_with_exifread(path, result)
        elif self._pillow_available:
            self._parse_with_pillow(path, result)
        else:
            # Fallback: read raw EXIF bytes
            self._parse_raw_exif(path, result)

        return result

    def _parse_with_exifread(self, path: Path, result: ExifResult) -> None:
        """Parse using exifread library."""
        import exifread

        try:
            with open(path, "rb") as f:
                tags = exifread.process_file(f, details=True)

            result.raw_tags = {str(k): str(v) for k, v in tags.items()}

            def get(tag: str) -> str:
                return str(tags.get(tag, ""))

            result.device_make = get("Image Make")
            result.device_model = get("Image Model")
            result.software = get("Image Software")
            result.datetime_original = get("EXIF DateTimeOriginal")
            result.datetime_digitized = get("EXIF DateTimeDigitized")
            result.datetime_modified = get("Image DateTime")
            result.focal_length = get("EXIF FocalLength")
            result.aperture = get("EXIF FNumber")
            result.shutter_speed = get("EXIF ExposureTime")
            result.iso = get("EXIF ISOSpeedRatings")
            result.flash = get("EXIF Flash")

            # Image dimensions
            w = get("EXIF ExifImageWidth") or get("Image ImageWidth")
            h = get("EXIF ExifImageLength") or get("Image ImageLength")
            result.width = int(w) if w.isdigit() else 0
            result.height = int(h) if h.isdigit() else 0

            # GPS
            gps = _extract_gps_exifread(tags)
            if gps:
                result.gps = gps

        except Exception as exc:
            result.errors.append(f"exifread error: {exc}")
            logger.debug("exifread parse error {}: {}", path, exc)

    def _parse_with_pillow(self, path: Path, result: ExifResult) -> None:
        """Parse using Pillow library."""
        from PIL import Image
        from PIL.ExifTags import GPSTAGS, TAGS

        try:
            with Image.open(path) as img:
                result.width, result.height = img.size
                result.file_type = img.format or path.suffix.lower()

                exif_data = img._getexif()  # type: ignore[attr-defined]
                if not exif_data:
                    return

                decoded: dict = {}
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, str(tag_id))
                    decoded[tag] = value

                result.raw_tags = {k: str(v)[:200] for k, v in decoded.items()}
                result.device_make = str(decoded.get("Make", ""))
                result.device_model = str(decoded.get("Model", ""))
                result.software = str(decoded.get("Software", ""))
                result.datetime_original = str(decoded.get("DateTimeOriginal", ""))
                result.datetime_modified = str(decoded.get("DateTime", ""))
                result.iso = str(decoded.get("ISOSpeedRatings", ""))

                # GPS
                gps_info = decoded.get("GPSInfo")
                if gps_info:
                    gps = _extract_gps_pillow(gps_info, GPSTAGS)
                    if gps:
                        result.gps = gps

        except Exception as exc:
            result.errors.append(f"Pillow error: {exc}")
            logger.debug("Pillow parse error {}: {}", path, exc)

    def _parse_raw_exif(self, path: Path, result: ExifResult) -> None:
        """Minimal EXIF extraction from raw bytes (no external deps)."""
        try:
            with open(path, "rb") as f:
                header = f.read(12)
            # JPEG magic
            if header[:2] == b"\xff\xd8":
                result.file_type = "jpeg"
            # PNG magic
            elif header[:8] == b"\x89PNG\r\n\x1a\n":
                result.file_type = "png"
            result.errors.append(
                "Install exifread or Pillow for full EXIF extraction: pip install exifread Pillow"
            )
        except Exception as exc:
            result.errors.append(str(exc))

    def parse_directory(
        self, directory: Path, extensions: list[str] | None = None
    ) -> list[ExifResult]:
        """Parse all image files in a directory."""
        if extensions is None:
            extensions = [
                ".jpg",
                ".jpeg",
                ".png",
                ".tiff",
                ".tif",
                ".heic",
                ".heif",
                ".raw",
                ".cr2",
                ".nef",
            ]

        results: list[ExifResult] = []
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix.lower() in extensions:
                results.append(self.parse(path))

        gps_count = sum(1 for r in results if r.has_gps)
        logger.info("EXIF parser: {} file(s), {} with GPS", len(results), gps_count)
        return results


# ── GPS helpers ───────────────────────────────────────────────────────────────


def _dms_to_decimal(dms_str: str) -> float | None:
    """Convert DMS string '[deg, min, sec]' to decimal degrees."""
    try:
        # exifread format: [d/1, m/1, s/100]
        parts = str(dms_str).strip("[]").split(", ")
        values = []
        for part in parts:
            if "/" in part:
                num, den = part.split("/")
                values.append(float(num) / float(den))
            else:
                values.append(float(part))
        if len(values) == 3:
            return values[0] + values[1] / 60 + values[2] / 3600
    except Exception:
        pass
    return None


def _extract_gps_exifread(tags: dict) -> GPSCoordinates | None:
    """Extract GPS from exifread tags."""
    try:
        lat_str = str(tags.get("GPS GPSLatitude", ""))
        lat_ref = str(tags.get("GPS GPSLatitudeRef", "N"))
        lon_str = str(tags.get("GPS GPSLongitude", ""))
        lon_ref = str(tags.get("GPS GPSLongitudeRef", "E"))

        if not lat_str or not lon_str:
            return None

        lat = _dms_to_decimal(lat_str)
        lon = _dms_to_decimal(lon_str)

        if lat is None or lon is None:
            return None

        if lat_ref == "S":
            lat = -lat
        if lon_ref == "W":
            lon = -lon

        alt_tag = tags.get("GPS GPSAltitude")
        alt = None
        if alt_tag:
            try:
                parts = str(alt_tag).split("/")
                alt = float(parts[0]) / float(parts[1]) if len(parts) == 2 else float(parts[0])
            except Exception:
                pass

        ts = str(tags.get("GPS GPSTimeStamp", ""))
        return GPSCoordinates(latitude=lat, longitude=lon, altitude=alt, timestamp=ts)
    except Exception:
        return None


def _extract_gps_pillow(gps_info: dict, gpstags: dict) -> GPSCoordinates | None:
    """Extract GPS from Pillow GPSInfo dict."""
    try:
        decoded = {gpstags.get(k, k): v for k, v in gps_info.items()}

        def to_decimal(coord: tuple, ref: str) -> float:
            d, m, s = [float(x.numerator) / float(x.denominator) for x in coord]
            val = d + m / 60 + s / 3600
            if ref in ("S", "W"):
                val = -val
            return val

        lat = to_decimal(decoded["GPSLatitude"], decoded.get("GPSLatitudeRef", "N"))
        lon = to_decimal(decoded["GPSLongitude"], decoded.get("GPSLongitudeRef", "E"))
        return GPSCoordinates(latitude=lat, longitude=lon)
    except Exception:
        return None
