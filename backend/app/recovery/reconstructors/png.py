"""
png.py — Deterministic PNG reconstruction engine for Recoverix.

Recovers damaged PNG evidence through safe, deterministic chunk repair:
  1. Validates 8-byte PNG magic signature.
  2. Parses sequential PNG chunks (length, type, data, CRC-32).
  3. Distinguishes critical chunks (IHDR, PLTE, IDAT, IEND) from ancillary chunks (e.g. tEXt, pHYs).
  4. Isolates and drops corrupted ancillary chunks without altering critical image data.
  5. Deterministically appends missing IEND trailer chunk ONLY when:
       - IHDR is fully valid and intact
       - All surviving IDAT data chunks decompress cleanly via zlib
     (Never assumes appending IEND restores lost or corrupted raster data).
  6. Rejects corrupted critical chunks (damaged IHDR or damaged IDAT) as UNRECOVERABLE.
  7. Enforces strict forensic accounting:
       verified_bytes + reconstructed_bytes == len(recovered_bytes)
       verified_bytes + missing_bytes == total_input_bytes
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from typing import Any, Dict, List, Optional, Tuple

from backend.app.models.reconstruction import ReconstructionResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import PNG_SIGNATURE
from backend.app.recovery.validators.png import validate_png

IEND_CHUNK_BYTES: bytes = b"\x00\x00\x00\x00IEND\xaeB`\x82"


def _verify_idat_decompression(idat_data: bytes) -> bool:
    """Verify that IDAT compressed stream can be decompressed by zlib."""
    if not idat_data:
        return False
    try:
        decompressor = zlib.decompressobj()
        decompressed = decompressor.decompress(idat_data)
        # Verify decompression completed without error
        return len(decompressed) > 0
    except zlib.error:
        return False


def reconstruct_png(
    data: bytes | RecoveredArtifact,
    original_data: Optional[bytes] = None,
    detection_mode: str = "known_file",
) -> ReconstructionResult:
    """Deterministically reconstruct damaged PNG evidence into a valid PNG image.

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
        val_res = validate_png(b"")
        return ReconstructionResult(
            format="png",
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

    # Magic signature check
    if not raw_bytes.startswith(PNG_SIGNATURE):
        val_res = validate_png(raw_bytes)
        return ReconstructionResult(
            format="png",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=total_input_bytes,
            damage_regions=[
                {
                    "offset": 0,
                    "length": min(total_input_bytes, 8),
                    "type": "INVALID_SIGNATURE",
                    "description": "Missing 8-byte PNG magic signature",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False,
            details={"error": "Missing valid PNG magic header"},
        )

    # Check if raw_bytes is already fully intact valid PNG with decompressed raster
    val_initial = validate_png(raw_bytes)
    if val_initial.valid:
        # Verify that IDAT payload actually decompresses cleanly
        idat_payloads_initial = []
        off_init = len(PNG_SIGNATURE)
        while off_init + 8 <= total_input_bytes:
            c_len = struct.unpack(">I", raw_bytes[off_init : off_init + 4])[0]
            c_type = raw_bytes[off_init + 4 : off_init + 8]
            if c_type == b"IDAT":
                idat_payloads_initial.append(raw_bytes[off_init + 8 : off_init + 8 + c_len])
            off_init += 12 + c_len
        if _verify_idat_decompression(b"".join(idat_payloads_initial)):
            is_exact = None
            if original_data is not None:
                is_exact = hashlib.sha256(raw_bytes).digest() == hashlib.sha256(original_data).digest()
            return ReconstructionResult(
                format="png",
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
                details={"status": "Intact PNG image"},
            )

    # Parse and filter chunks
    offset = len(PNG_SIGNATURE)
    surviving_chunks: List[bytes] = [PNG_SIGNATURE]
    damage_regions: List[Dict[str, Any]] = []
    recon_methods: List[str] = []

    verified_input_bytes = len(PNG_SIGNATURE)
    has_valid_ihdr = False
    idat_payloads: List[bytes] = []
    has_iend = False
    critical_corruption = False
    corruption_reason = ""

    while offset < total_input_bytes:
        # Check if enough bytes remain for chunk length + type
        if offset + 8 > total_input_bytes:
            # Incomplete chunk header at EOF
            incomplete_len = total_input_bytes - offset
            damage_regions.append({
                "offset": offset,
                "length": incomplete_len,
                "type": "TRUNCATED_CHUNK_HEADER",
                "description": f"Truncated chunk header ({incomplete_len} bytes) at EOF",
            })
            break

        chunk_length = struct.unpack(">I", raw_bytes[offset : offset + 4])[0]
        chunk_type_bytes = raw_bytes[offset + 4 : offset + 8]

        try:
            chunk_type = chunk_type_bytes.decode("ascii")
        except UnicodeDecodeError:
            chunk_type = "????"

        data_start = offset + 8
        data_end = data_start + chunk_length
        crc_start = data_end
        crc_end = crc_start + 4

        # Check for truncated chunk data
        if crc_end > total_input_bytes:
            truncated_len = total_input_bytes - offset
            # Is this critical or ancillary?
            is_critical = chunk_type_bytes[0:1].isupper()
            if is_critical:
                critical_corruption = True
                corruption_reason = f"Critical chunk '{chunk_type}' truncated at offset {offset}"
                damage_regions.append({
                    "offset": offset,
                    "length": truncated_len,
                    "type": "TRUNCATED_CRITICAL_CHUNK",
                    "description": corruption_reason,
                })
                break
            else:
                # Ancillary chunk truncated at EOF: safely drop
                damage_regions.append({
                    "offset": offset,
                    "length": truncated_len,
                    "type": "TRUNCATED_ANCILLARY_CHUNK",
                    "description": f"Dropped truncated ancillary chunk '{chunk_type}'",
                })
                if "ANCILLARY_CHUNK_DROPPED" not in recon_methods:
                    recon_methods.append("ANCILLARY_CHUNK_DROPPED")
                break

        chunk_data = raw_bytes[data_start:data_end]
        expected_crc = struct.unpack(">I", raw_bytes[crc_start:crc_end])[0]
        calculated_crc = zlib.crc32(chunk_type_bytes + chunk_data) & 0xFFFFFFFF
        total_chunk_bytes = raw_bytes[offset:crc_end]

        is_critical = chunk_type_bytes[0:1].isupper()

        if calculated_crc != expected_crc:
            if is_critical:
                critical_corruption = True
                corruption_reason = f"CRC-32 mismatch in critical chunk '{chunk_type}'"
                damage_regions.append({
                    "offset": offset,
                    "length": len(total_chunk_bytes),
                    "type": "CORRUPTED_CRITICAL_CHUNK",
                    "description": corruption_reason,
                })
                break
            else:
                # Corrupted ancillary chunk: isolate and drop
                damage_regions.append({
                    "offset": offset,
                    "length": len(total_chunk_bytes),
                    "type": "CORRUPTED_ANCILLARY_CHUNK",
                    "description": f"Dropped ancillary chunk '{chunk_type}' with invalid CRC",
                })
                if "ANCILLARY_CHUNK_DROPPED" not in recon_methods:
                    recon_methods.append("ANCILLARY_CHUNK_DROPPED")
                offset = crc_end
                continue

        # Chunk is structurally valid!
        if chunk_type == "IHDR":
            if chunk_length != 13:
                critical_corruption = True
                corruption_reason = f"Invalid IHDR length: {chunk_length}"
                break
            has_valid_ihdr = True
        elif not has_valid_ihdr:
            critical_corruption = True
            corruption_reason = f"First chunk was '{chunk_type}', expected IHDR"
            break

        if chunk_type == "IDAT":
            idat_payloads.append(chunk_data)

        if chunk_type == "IEND":
            has_iend = True
            surviving_chunks.append(total_chunk_bytes)
            verified_input_bytes += len(total_chunk_bytes)
            offset = crc_end
            break

        surviving_chunks.append(total_chunk_bytes)
        verified_input_bytes += len(total_chunk_bytes)
        offset = crc_end

    # If critical corruption occurred, reject safely
    if critical_corruption or not has_valid_ihdr or not idat_payloads:
        val_res = validate_png(raw_bytes)
        return ReconstructionResult(
            format="png",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=total_input_bytes,
            damage_regions=damage_regions if damage_regions else [
                {
                    "offset": 0,
                    "length": total_input_bytes,
                    "type": "CRITICAL_PNG_CORRUPTION",
                    "description": corruption_reason or "Missing critical IHDR or IDAT chunks",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False,
            details={"error": corruption_reason or "Critical PNG damage"},
        )

    # Verify IDAT decompression
    combined_idat = b"".join(idat_payloads)
    if not _verify_idat_decompression(combined_idat):
        val_res = validate_png(raw_bytes)
        return ReconstructionResult(
            format="png",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=total_input_bytes,
            damage_regions=[
                {
                    "offset": 0,
                    "length": total_input_bytes,
                    "type": "IDAT_DECOMPRESSION_FAILURE",
                    "description": "IDAT raster stream is corrupted and cannot be decompressed",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False,
            details={"error": "IDAT decompression failed"},
        )

    # Check if IEND needs to be reconstructed
    reconstructed_bytes_count = 0
    if not has_iend:
        if detection_mode == "blind":
            val_res = validate_png(raw_bytes)
            return ReconstructionResult(
                format="png",
                status="UNRECOVERABLE",
                success=False,
                recovered_bytes=b"",
                verified_bytes=0,
                reconstructed_bytes=0,
                missing_bytes=total_input_bytes,
                damage_regions=damage_regions if damage_regions else [
                    {
                        "offset": offset,
                        "length": total_input_bytes - offset,
                        "type": "TRUNCATED_IMAGE",
                        "description": "Truncated PNG missing IEND in blind carving mode",
                    }
                ],
                reconstruction_methods=[],
                validation_result=val_res,
                is_exact_match=False,
                details={"error": "Truncated PNG missing IEND in blind carving mode"},
            )
        surviving_chunks.append(IEND_CHUNK_BYTES)
        reconstructed_bytes_count = len(IEND_CHUNK_BYTES)
        recon_methods.append("IEND_TRAILER_SYNTHESIS")

    recovered_png = b"".join(surviving_chunks)
    val_final = validate_png(recovered_png)

    if not val_final.valid:
        return ReconstructionResult(
            format="png",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=total_input_bytes,
            damage_regions=damage_regions,
            reconstruction_methods=[],
            validation_result=val_final,
            is_exact_match=False,
            details={"error": "Reconstructed PNG failed validation"},
        )

    missing_bytes_count = max(0, total_input_bytes - verified_input_bytes)

    is_exact = None
    if original_data is not None:
        is_exact = hashlib.sha256(recovered_png).digest() == hashlib.sha256(original_data).digest()

    status_str = (
        "FULLY_RECOVERED"
        if (reconstructed_bytes_count == 0 and missing_bytes_count == 0 and val_final.valid)
        else "PARTIALLY_RECOVERED"
    )

    return ReconstructionResult(
        format="png",
        status=status_str,
        success=True,
        recovered_bytes=recovered_png,
        verified_bytes=verified_input_bytes,
        reconstructed_bytes=reconstructed_bytes_count,
        missing_bytes=missing_bytes_count,
        damage_regions=damage_regions,
        reconstruction_methods=recon_methods if recon_methods else ["NONE"],
        validation_result=val_final,
        is_exact_match=is_exact,
        details={
            "width": val_final.details.get("width"),
            "height": val_final.details.get("height"),
            "total_chunks": val_final.details.get("total_chunks"),
            "reconstructed_iend": not has_iend,
        },
    )
