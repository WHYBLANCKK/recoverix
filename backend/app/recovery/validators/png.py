"""
png.py — Deterministic PNG artifact structural validator.

Validates recovered PNG artifact bytes against RFC 2083 standard PNG magic signature,
chunk structure, IHDR dimensions, IDAT presence, IEND termination, and zlib CRC32 verification.
"""

from __future__ import annotations

import struct
import zlib
from typing import Union, Any, List

from backend.app.models.validation import ValidationResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import PNG_SIGNATURE


def validate_png(data: bytes | RecoveredArtifact) -> ValidationResult:
    """Validate the structural integrity of a recovered PNG artifact.

    Accepts raw bytes or a RecoveredArtifact object.

    Checks performed:
      1. input_type: input is bytes or RecoveredArtifact
      2. non_empty: input is non-empty
      3. magic_bytes: starts with 8-byte PNG signature (\x89PNG\r\n\x1a\n)
      4. first_chunk_ihdr: first chunk is IHDR (length 13), extracts width/height
      5. chunk_structure: valid chunk length and bounds
      6. crc_verification: zlib CRC32 matches chunk type + data
      7. idat_presence: at least one IDAT chunk is present
      8. iend_termination: terminates with valid IEND chunk

    Args:
        data: Raw evidence bytes or RecoveredArtifact.

    Returns:
        ValidationResult with validation outcome, checks, errors, and details.
    """
    checks: list[str] = [
        "input_type",
        "non_empty",
        "magic_bytes",
        "first_chunk_ihdr",
        "chunk_structure",
        "crc_verification",
        "idat_presence",
        "iend_termination",
    ]
    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}

    raw_bytes: bytes
    fmt: str = "png"
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

    # 2. Magic bytes check
    if not raw_bytes.startswith(PNG_SIGNATURE):
        errors.append("Missing valid 8-byte PNG magic signature (89 50 4E 47 0D 0A 1A 0A)")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    # Parse PNG Chunks
    offset = len(PNG_SIGNATURE)
    total_len = len(raw_bytes)
    chunk_list: List[str] = []
    idat_count = 0
    found_ihdr = False
    found_iend = False
    invalid_crc_chunks: List[str] = []

    while offset < total_len:
        # Check if enough bytes remain for length (4) + type (4)
        if offset + 8 > total_len:
            errors.append(f"Truncated PNG chunk header at offset {offset}")
            break

        length = struct.unpack(">I", raw_bytes[offset : offset + 4])[0]
        chunk_type_bytes = raw_bytes[offset + 4 : offset + 8]

        try:
            chunk_type = chunk_type_bytes.decode("ascii")
        except UnicodeDecodeError:
            chunk_type = chunk_type_bytes.hex()

        chunk_list.append(chunk_type)

        data_start = offset + 8
        data_end = data_start + length
        crc_start = data_end
        crc_end = crc_start + 4

        if crc_end > total_len:
            errors.append(f"Truncated PNG chunk data/CRC for '{chunk_type}' at offset {offset}")
            break

        chunk_data = raw_bytes[data_start:data_end]
        expected_crc = struct.unpack(">I", raw_bytes[crc_start:crc_end])[0]

        # Verify CRC32 over chunk_type_bytes + chunk_data
        calculated_crc = zlib.crc32(chunk_type_bytes + chunk_data) & 0xFFFFFFFF
        if calculated_crc != expected_crc:
            invalid_crc_chunks.append(f"{chunk_type} (expected={expected_crc:#x}, got={calculated_crc:#x})")

        # First chunk check: MUST be IHDR
        if not found_ihdr:
            if chunk_type != "IHDR":
                errors.append(f"First PNG chunk must be IHDR, found '{chunk_type}' at offset {offset}")
            else:
                found_ihdr = True
                if length == 13:
                    width, height, bit_depth, color_type, comp, filt, interlace = struct.unpack(
                        ">IIBBBBB", chunk_data
                    )
                    details["width"] = width
                    details["height"] = height
                    details["bit_depth"] = bit_depth
                    details["color_type"] = color_type
                    if width == 0 or height == 0:
                        errors.append(
                            f"Invalid IHDR dimensions: width={width}, height={height} (dimensions must be positive non-zero)"
                        )
                    elif width > 65535 or height > 65535:
                        errors.append(
                            f"PNG dimension exceeds maximum safe dimension limit (65535): width={width}, height={height}"
                        )
                else:
                    errors.append(f"Invalid IHDR chunk length: expected 13, got {length}")

        if chunk_type == "IDAT":
            idat_count += 1

        if chunk_type == "IEND":
            found_iend = True
            details["end_offset"] = crc_end
            offset = crc_end
            break

        offset = crc_end

    details["chunk_types"] = chunk_list[:15]
    details["total_chunks"] = len(chunk_list)
    details["idat_count"] = idat_count

    if not found_ihdr and "first_chunk_ihdr" not in [e.split()[0] for e in errors]:
        errors.append("Missing required IHDR header chunk")

    if idat_count == 0:
        errors.append("Missing required IDAT data chunk")

    if not found_iend:
        errors.append("Missing required IEND trailer chunk")

    if invalid_crc_chunks:
        errors.append(f"CRC verification failed for chunk(s): {', '.join(invalid_crc_chunks)}")

    valid = len(errors) == 0
    return ValidationResult(
        valid=valid,
        format=fmt,
        checks_performed=checks,
        errors=errors,
        warnings=warnings,
        details=details,
    )
