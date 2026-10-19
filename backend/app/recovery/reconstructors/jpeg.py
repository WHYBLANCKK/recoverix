"""
jpeg.py — Deterministic JPEG reconstruction engine for Recoverix.

Recovers damaged JPEG evidence through safe, deterministic marker stream repair:
  1. Validates 2-byte JPEG SOI (0xFFD8) magic signature.
  2. Parses sequential JPEG marker segments (APPn, DQT, SOF0/SOF2, DHT, SOS).
  3. Ensures critical frame headers (SOF detailing width/height) and scan headers (SOS)
     are intact.
  4. Trims trailing non-JPEG cluster padding or extraneous data following EOI (0xFFD9).
  5. Deterministically appends missing EOI (0xFFD9) trailer marker ONLY when:
       - SOF (Start of Frame) is intact with valid image dimensions
       - SOS (Start of Scan) is intact and followed by non-empty entropy scan data
       (Rolls back incomplete trailing marker bytes such as a solitary 0xFF at EOF).
  6. Rejects files missing critical headers (SOI, SOF, or SOS) as UNRECOVERABLE.
  7. Enforces strict forensic accounting:
       verified_bytes + reconstructed_bytes == len(recovered_bytes)
       verified_bytes + missing_bytes == total_input_bytes
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple

from backend.app.models.reconstruction import ReconstructionResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import JPEG_SOI, JPEG_EOI
from backend.app.recovery.validators.jpeg import validate_jpeg


def reconstruct_jpeg(
    data: bytes | RecoveredArtifact,
    original_data: Optional[bytes] = None,
    detection_mode: str = "known_file",
) -> ReconstructionResult:
    """Deterministically reconstruct damaged JPEG evidence into a valid JPEG image.

    Args:
        data: Raw evidence bytes or RecoveredArtifact.
        original_data: Optional ground truth bytes for verification.
        detection_mode: 'known_file', 'blind', or 'synthetic_harness'.

    Returns:
        ReconstructionResult with recovered bytes and forensic byte accounting.
    """
    raw_bytes: bytes
    if isinstance(data, RecoveredArtifact):
        raw_bytes = data.recovered_bytes
    elif isinstance(data, (bytes, bytearray)):
        raw_bytes = bytes(data)
    else:
        raw_bytes = b""

    total_input_bytes = len(raw_bytes)
    if total_input_bytes == 0:
        val_res = validate_jpeg(b"")
        return ReconstructionResult(
            format="jpeg",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=0,
            damage_regions=[
                {"offset": 0, "length": 0, "type": "EMPTY_INPUT", "description": "Empty evidence input"}
            ],
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False,
            details={"error": "Empty input bytes"},
        )

    # 1. Magic signature check (SOI: FF D8)
    if not raw_bytes.startswith(JPEG_SOI):
        val_res = validate_jpeg(raw_bytes)
        return ReconstructionResult(
            format="jpeg",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=total_input_bytes,
            damage_regions=[
                {
                    "offset": 0,
                    "length": min(total_input_bytes, 2),
                    "type": "INVALID_SIGNATURE",
                    "description": "Missing 2-byte JPEG SOI marker (FF D8)",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False,
            details={"error": "Missing valid JPEG SOI marker"},
        )

    # 2. Check if already valid JPEG
    val_initial = validate_jpeg(raw_bytes)
    if val_initial.valid:
        end_offset = val_initial.details.get("end_offset", total_input_bytes)
        if end_offset < total_input_bytes:
            # Trailing garbage after EOI: trim cleanly
            trimmed = raw_bytes[:end_offset]
            trailing_len = total_input_bytes - end_offset
            val_trimmed = validate_jpeg(trimmed)
            is_exact = None
            if original_data is not None:
                is_exact = hashlib.sha256(trimmed).digest() == hashlib.sha256(original_data).digest()
            return ReconstructionResult(
                format="jpeg",
                status="FULLY_RECOVERED",
                success=True,
                recovered_bytes=trimmed,
                verified_bytes=end_offset,
                reconstructed_bytes=0,
                missing_bytes=trailing_len,
                damage_regions=[
                    {
                        "offset": end_offset,
                        "length": trailing_len,
                        "type": "TRAILING_GARBAGE",
                        "description": f"Trimmed {trailing_len} trailing non-JPEG bytes after EOI",
                    }
                ],
                reconstruction_methods=["TRAILING_GARBAGE_TRIM"],
                validation_result=val_trimmed,
                is_exact_match=is_exact,
                details={
                    "status": "Trimmed trailing garbage after EOI",
                    "width": val_initial.details.get("width"),
                    "height": val_initial.details.get("height"),
                },
            )
        else:
            is_exact = None
            if original_data is not None:
                is_exact = hashlib.sha256(raw_bytes).digest() == hashlib.sha256(original_data).digest()
            return ReconstructionResult(
                format="jpeg",
                status="FULLY_RECOVERED",
                success=True,
                recovered_bytes=raw_bytes,
                verified_bytes=total_input_bytes,
                reconstructed_bytes=0,
                missing_bytes=0,
                damage_regions=[],
                reconstruction_methods=[],
                validation_result=val_initial,
                is_exact_match=is_exact,
                details={
                    "status": "Intact JPEG image",
                    "width": val_initial.details.get("width"),
                    "height": val_initial.details.get("height"),
                },
            )

    # 3. Parse marker stream and diagnose damage
    offset = 2
    found_sof = False
    sof_details: Dict[str, Any] = {}
    found_sos = False
    sos_end: Optional[int] = None
    damage_regions: List[Dict[str, Any]] = []
    recon_methods: List[str] = []

    while offset < total_input_bytes:
        if raw_bytes[offset] != 0xFF:
            # Skip padding if between markers
            offset += 1
            continue

        if offset + 1 >= total_input_bytes:
            break

        marker = raw_bytes[offset + 1]

        # Stuffed byte or fill byte
        if marker in (0x00, 0xFF):
            offset += 1
            continue

        # EOI marker
        if marker == 0xD9:
            # Found EOI in stream
            end_pos = offset + 2
            trimmed = raw_bytes[:end_pos]
            trailing_len = total_input_bytes - end_pos
            val_trimmed = validate_jpeg(trimmed)
            if val_trimmed.valid:
                return ReconstructionResult(
                    format="jpeg",
                    status="FULLY_RECOVERED",
                    success=True,
                    recovered_bytes=trimmed,
                    verified_bytes=end_pos,
                    reconstructed_bytes=0,
                    missing_bytes=trailing_len,
                    damage_regions=[
                        {
                            "offset": end_pos,
                            "length": trailing_len,
                            "type": "TRAILING_GARBAGE",
                            "description": f"Trimmed {trailing_len} trailing non-JPEG bytes after EOI",
                        }
                    ] if trailing_len > 0 else [],
                    reconstruction_methods=["TRAILING_GARBAGE_TRIM"] if trailing_len > 0 else [],
                    validation_result=val_trimmed,
                    is_exact_match=False,
                    details=val_trimmed.details,
                )
            break

        # Standalone markers without length: RST0-RST7 (0xD0-0xD7), SOI (0xD8)
        if 0xD0 <= marker <= 0xD8:
            offset += 2
            continue

        # Length-bearing segment
        if offset + 4 > total_input_bytes:
            damage_regions.append({
                "offset": offset,
                "length": total_input_bytes - offset,
                "type": "TRUNCATED_MARKER_HEADER",
                "description": f"Truncated segment header for marker {marker:#04x}",
            })
            break

        segment_len = struct.unpack(">H", raw_bytes[offset + 2 : offset + 4])[0]
        if segment_len < 2:
            damage_regions.append({
                "offset": offset,
                "length": 4,
                "type": "CORRUPT_SEGMENT_LENGTH",
                "description": f"Invalid segment length ({segment_len}) for marker {marker:#04x}",
            })
            break

        segment_end = offset + 2 + segment_len
        if segment_end > total_input_bytes:
            damage_regions.append({
                "offset": offset,
                "length": total_input_bytes - offset,
                "type": "TRUNCATED_SEGMENT_PAYLOAD",
                "description": f"Segment for marker {marker:#04x} exceeds file bounds",
            })
            break

        # Check for SOF markers (SOF0, SOF1, SOF2, SOF3)
        if marker in (0xC0, 0xC1, 0xC2, 0xC3):
            found_sof = True
            if segment_len >= 8:
                payload = raw_bytes[offset + 4 : segment_end]
                precision, height, width, components = struct.unpack(">BHHB", payload[:6])
                sof_details = {
                    "precision": precision,
                    "height": height,
                    "width": width,
                    "components": components,
                }
        elif marker == 0xDA:
            # Start of Scan (SOS)
            found_sos = True
            sos_end = segment_end
            break

        offset = segment_end

    # 4. Evaluate recoverability
    if not found_sof or not found_sos or sos_end is None:
        val_fail = validate_jpeg(raw_bytes)
        return ReconstructionResult(
            format="jpeg",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=total_input_bytes,
            damage_regions=damage_regions or [
                {
                    "offset": 0,
                    "length": total_input_bytes,
                    "type": "MISSING_CRITICAL_HEADERS",
                    "description": "Missing required SOF (Start of Frame) or SOS (Start of Scan) marker",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_fail,
            is_exact_match=False,
            details={"error": "JPEG missing critical frame/scan headers"},
        )

    # 5. Check entropy scan data after SOS
    entropy_data = raw_bytes[sos_end:]
    if len(entropy_data) == 0:
        val_fail = validate_jpeg(raw_bytes)
        return ReconstructionResult(
            format="jpeg",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=total_input_bytes,
            damage_regions=[
                {
                    "offset": sos_end,
                    "length": 0,
                    "type": "EMPTY_ENTROPY_STREAM",
                    "description": "Zero bytes of entropy scan data following SOS header",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_fail,
            is_exact_match=False,
            details={"error": "Zero entropy scan bytes"},
        )

    # Check if EOI was located within entropy scan data
    eoi_pos = entropy_data.find(JPEG_EOI)
    if eoi_pos != -1:
        eoi_end = sos_end + eoi_pos + len(JPEG_EOI)
        trimmed = raw_bytes[:eoi_end]
        trailing_len = total_input_bytes - eoi_end
        val_trimmed = validate_jpeg(trimmed)
        if val_trimmed.valid:
            return ReconstructionResult(
                format="jpeg",
                status="FULLY_RECOVERED",
                success=True,
                recovered_bytes=trimmed,
                verified_bytes=eoi_end,
                reconstructed_bytes=0,
                missing_bytes=trailing_len,
                damage_regions=[
                    {
                        "offset": eoi_end,
                        "length": trailing_len,
                        "type": "TRAILING_GARBAGE",
                        "description": f"Trimmed {trailing_len} trailing non-JPEG bytes after EOI",
                    }
                ] if trailing_len > 0 else [],
                reconstruction_methods=["TRAILING_GARBAGE_TRIM"] if trailing_len > 0 else [],
                validation_result=val_trimmed,
                is_exact_match=False,
                details=val_trimmed.details,
            )

    # 6. Deterministically synthesize missing EOI trailer
    if detection_mode == "blind":
        val_fail = validate_jpeg(raw_bytes)
        return ReconstructionResult(
            format="jpeg",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=total_input_bytes,
            damage_regions=damage_regions if damage_regions else [
                {
                    "offset": len(raw_bytes),
                    "length": 0,
                    "type": "TRUNCATED_JPEG",
                    "description": "Truncated JPEG missing EOI in blind carving mode",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_fail,
            is_exact_match=False,
            details={"error": "Truncated JPEG missing EOI in blind carving mode"},
        )

    # If raw_bytes ends with an incomplete marker byte 0xFF, roll it back
    clean_bytes = raw_bytes
    rolled_back_byte = 0
    if clean_bytes.endswith(b"\xff"):
        clean_bytes = clean_bytes[:-1]
        rolled_back_byte = 1

    recovered_bytes = clean_bytes + JPEG_EOI
    recon_methods.append("EOI_TRAILER_SYNTHESIS")

    damage_regions.append({
        "offset": len(clean_bytes),
        "length": 2,
        "type": "TRUNCATED_TRAILER",
        "description": "Synthesized deterministic EOI marker (FF D9)",
    })
    if rolled_back_byte > 0:
        damage_regions.append({
            "offset": len(clean_bytes),
            "length": 1,
            "type": "INCOMPLETE_MARKER_BYTE",
            "description": "Rolled back incomplete solitary 0xFF byte at EOF",
        })

    val_recon = validate_jpeg(recovered_bytes)
    if not val_recon.valid:
        return ReconstructionResult(
            format="jpeg",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=total_input_bytes,
            damage_regions=damage_regions,
            reconstruction_methods=[],
            validation_result=val_recon,
            is_exact_match=False,
            details={"error": "Reconstructed JPEG failed validation"},
        )

    verified_bytes = len(clean_bytes)
    reconstructed_bytes = len(JPEG_EOI)  # 2 bytes
    missing_bytes = rolled_back_byte

    # Forensic invariant validation
    assert verified_bytes + reconstructed_bytes == len(recovered_bytes)
    assert verified_bytes + missing_bytes == total_input_bytes

    return ReconstructionResult(
        format="jpeg",
        status="PARTIALLY_RECOVERED",
        success=True,
        recovered_bytes=recovered_bytes,
        verified_bytes=verified_bytes,
        reconstructed_bytes=reconstructed_bytes,
        missing_bytes=missing_bytes,
        damage_regions=damage_regions,
        reconstruction_methods=recon_methods,
        validation_result=val_recon,
        is_exact_match=False,
        details={
            "reconstruction_method": "EOI_TRAILER_SYNTHESIS",
            "width": sof_details.get("width"),
            "height": sof_details.get("height"),
            "precision": sof_details.get("precision"),
            "components": sof_details.get("components"),
        },
    )
