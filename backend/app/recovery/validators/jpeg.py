"""
jpeg.py — Deterministic JPEG artifact structural validator.

Validates recovered JPEG artifact bytes against ISO/IEC 10918-1 JPEG standard marker stream,
SOI (0xFFD8), APPn, DQT, SOF0/SOF2 (width/height), DHT, SOS entropy stream, and EOI (0xFFD9) termination.
"""

from __future__ import annotations

import struct
from typing import Union, Any, List

from backend.app.models.validation import ValidationResult
from backend.app.recovery.carver import RecoveredArtifact

JPEG_SOI: bytes = b"\xff\xd8"
JPEG_EOI: bytes = b"\xff\xd9"


def validate_jpeg(data: bytes | RecoveredArtifact) -> ValidationResult:
    """Validate the structural integrity of a recovered JPEG artifact.

    Accepts raw bytes or a RecoveredArtifact object.

    Checks performed:
      1. input_type: input is bytes or RecoveredArtifact
      2. non_empty: input is non-empty
      3. soi_marker: starts with SOI marker (\xFF\xD8)
      4. marker_structure: valid marker sequence and segment lengths
      5. sof_presence: SOF marker present (extracts image width, height, precision)
      6. eoi_termination: ends with EOI marker (\xFF\xD9)

    Args:
        data: Raw evidence bytes or RecoveredArtifact.

    Returns:
        ValidationResult with validation outcome, checks, errors, and details.
    """
    checks: list[str] = [
        "input_type",
        "non_empty",
        "soi_marker",
        "marker_structure",
        "sof_presence",
        "sos_presence",
        "eoi_termination",
    ]
    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}

    raw_bytes: bytes
    fmt: str = "jpeg"
    if isinstance(data, RecoveredArtifact):
        raw_bytes = data.recovered_bytes
        if data.format:
            fmt = data.format
    elif isinstance(data, (bytes, bytearray)):
        raw_bytes = bytes(data)
    else:
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=[f"Invalid input type: {type(data)}. Expected bytes or RecoveredArtifact."],
        )

    # 1. Non-empty check
    if len(raw_bytes) == 0:
        errors.append("Artifact bytes are empty")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
        )

    # 2. SOI Marker Check
    if not raw_bytes.startswith(JPEG_SOI):
        errors.append("Missing valid 2-byte JPEG Start of Image (SOI) marker (FF D8)")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    # Scan JPEG Markers
    total_len = len(raw_bytes)
    offset = 2
    found_sof = False
    found_sos = False
    found_eoi = False
    markers_found: List[str] = ["SOI"]

    while offset < total_len:
        if raw_bytes[offset] != 0xFF:
            # Skip fill bytes if padding exists between markers
            offset += 1
            continue

        # Look for marker byte
        if offset + 1 >= total_len:
            errors.append(f"Truncated marker byte at offset {offset}")
            break

        marker = raw_bytes[offset + 1]

        # Handle 0xFF padding or 0x00 (stuffed byte in scan payload)
        if marker == 0x00 or marker == 0xFF:
            offset += 1
            continue

        # EOI Marker (0xFFD9)
        if marker == 0xD9:
            markers_found.append("EOI")
            found_eoi = True
            details["end_offset"] = offset + 2
            break

        # Standalone markers without length: RST0-RST7 (0xD0-0xD7), SOI (0xD8)
        if 0xD0 <= marker <= 0xD8:
            markers_found.append(f"RST{marker - 0xD0}" if marker != 0xD8 else "SOI")
            offset += 2
            continue

        # Markers with 2-byte length payload
        if offset + 4 > total_len:
            errors.append(f"Truncated segment header for marker {marker:#04x} at offset {offset}")
            break

        segment_len = struct.unpack(">H", raw_bytes[offset + 2 : offset + 4])[0]
        if segment_len < 2:
            errors.append(f"Invalid segment length ({segment_len}) for marker {marker:#04x} at offset {offset}")
            break

        segment_end = offset + 2 + segment_len
        if segment_end > total_len:
            errors.append(
                f"Segment length ({segment_len}) for marker {marker:#04x} exceeds file bounds at offset {offset}"
            )
            break

        marker_hex = f"0x{marker:02X}"
        # Identify SOF markers (0xC0: Baseline, 0xC1: Extended, 0xC2: Progressive, 0xC3: Lossless)
        if marker in (0xC0, 0xC1, 0xC2, 0xC3):
            found_sof = True
            markers_found.append(f"SOF_{marker_hex}")
            if segment_len >= 8:
                payload = raw_bytes[offset + 4 : segment_end]
                precision, height, width, components = struct.unpack(">BHHB", payload[:6])
                details["precision"] = precision
                details["height"] = height
                details["width"] = width
                details["components"] = components
                if width == 0 or height == 0:
                    errors.append(
                        f"Invalid SOF dimensions: width={width}, height={height} (dimensions must be positive non-zero)"
                    )
        elif 0xE0 <= marker <= 0xEF:
            markers_found.append(f"APP{marker - 0xE0}")
        elif marker == 0xDB:
            markers_found.append("DQT")
        elif marker == 0xC4:
            markers_found.append("DHT")
        elif marker == 0xDA:
            found_sos = True
            markers_found.append("SOS")
            # SOS is followed by compressed entropy scan stream until EOI (0xFFD9)
            # Fast scan for EOI marker in remaining bytes
            eoi_pos = raw_bytes.find(JPEG_EOI, segment_end)
            if eoi_pos != -1:
                found_eoi = True
                markers_found.append("EOI")
                details["end_offset"] = eoi_pos + 2
            else:
                errors.append("Missing EOI marker after SOS entropy scan data")
            break
        else:
            markers_found.append(marker_hex)

        offset = segment_end

    details["markers_found"] = markers_found[:15]

    if not found_sof:
        errors.append("Missing required SOF (Start of Frame) marker detailing image dimensions")

    if not found_sos:
        errors.append("Missing required SOS (Start of Scan) marker preceding image data")

    if not found_eoi:
        errors.append("Missing required EOI (End of Image) trailer marker (FF D9)")

    valid = len(errors) == 0
    return ValidationResult(
        valid=valid,
        format=fmt,
        checks_performed=checks,
        errors=errors,
        warnings=warnings,
        details=details,
    )
