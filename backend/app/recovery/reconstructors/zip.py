"""
zip.py — Deterministic ZIP archive reconstruction engine for Recoverix.

Recovers damaged ZIP evidence through safe, deterministic structural repair:
  1. Validates 4-byte ZIP local file header signature (PK\\x03\\x04).
  2. Parses sequential local file headers and verifies decompression/CRC-32 of surviving members.
  3. Trims trailing non-ZIP cluster padding or garbage following authentic EOCD.
  4. Deterministically synthesizes missing Central Directory and EOCD (PK\\x05\\x06) ONLY when:
       - At least one local file member is structurally intact with verified payload
       - Deflated streams decompress cleanly with matching CRC-32
     (Reconstructed central directory records are synthesized purely from surviving local headers).
  5. Rejects archives with zero recoverable members or corrupted magic headers as UNRECOVERABLE.
  6. Enforces strict forensic accounting:
       verified_bytes + reconstructed_bytes == len(recovered_bytes)
       verified_bytes + missing_bytes == total_input_bytes
"""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile
import zlib
from typing import Any, Dict, List, Optional, Tuple

from backend.app.models.reconstruction import ReconstructionResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import (
    ZIP_LOCAL_HEADER,
    ZIP_CENTRAL_HEADER,
    ZIP_EOCD_SIGNATURE,
)
from backend.app.recovery.validators.zip import validate_zip, check_zip_path_security


def reconstruct_zip(
    data: bytes | RecoveredArtifact,
    original_data: Optional[bytes] = None,
    detection_mode: str = "known_file",
) -> ReconstructionResult:
    """Deterministically reconstruct damaged ZIP archive into a valid, extractable ZIP.

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
        val_res = validate_zip(b"")
        return ReconstructionResult(
            format="zip",
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

    # 1. Magic signature check (starts with PK\x03\x04)
    if not raw_bytes.startswith(ZIP_LOCAL_HEADER):
        val_res = validate_zip(raw_bytes)
        return ReconstructionResult(
            format="zip",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=total_input_bytes,
            damage_regions=[
                {
                    "offset": 0,
                    "length": min(total_input_bytes, 4),
                    "type": "INVALID_SIGNATURE",
                    "description": "Missing 4-byte ZIP local file header signature (PK\\x03\\x04)",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False,
            details={"error": "Missing valid ZIP signature"},
        )

    # 2. Check if already valid ZIP archive
    val_initial = validate_zip(raw_bytes)
    if any(e.startswith("Security:") for e in val_initial.errors):
        return ReconstructionResult(
            format="zip",
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
                    "type": "SECURITY_VIOLATION",
                    "description": "; ".join(e for e in val_initial.errors if e.startswith("Security:")),
                }
            ],
            reconstruction_methods=[],
            validation_result=val_initial,
            is_exact_match=False,
            details=val_initial.details,
        )

    if val_initial.valid:
        end_offset = val_initial.details.get("end_offset", total_input_bytes)
        if end_offset < total_input_bytes:
            # Trailing garbage after EOCD
            trimmed = raw_bytes[:end_offset]
            trailing_len = total_input_bytes - end_offset
            val_trimmed = validate_zip(trimmed)
            is_exact = None
            if original_data is not None:
                is_exact = hashlib.sha256(trimmed).digest() == hashlib.sha256(original_data).digest()
            return ReconstructionResult(
                format="zip",
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
                        "description": f"Trimmed {trailing_len} trailing non-ZIP bytes after EOCD",
                    }
                ],
                reconstruction_methods=["TRAILING_GARBAGE_TRIM"],
                validation_result=val_trimmed,
                is_exact_match=is_exact,
                details=val_trimmed.details,
            )
        else:
            is_exact = None
            if original_data is not None:
                is_exact = hashlib.sha256(raw_bytes).digest() == hashlib.sha256(original_data).digest()
            return ReconstructionResult(
                format="zip",
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
                details=val_initial.details,
            )

    # 3. Parse surviving local file headers
    offset = 0
    surviving_entries: List[Dict[str, Any]] = []
    surviving_bytes_end = 0
    damage_regions: List[Dict[str, Any]] = []

    MAX_ZIP_ENTRIES = 5000
    MAX_UNCOMPRESSED_MEMBER_SIZE = 50 * 1024 * 1024

    while offset + 30 <= total_input_bytes:
        if len(surviving_entries) >= MAX_ZIP_ENTRIES:
            damage_regions.append({
                "offset": offset,
                "length": total_input_bytes - offset,
                "type": "SECURITY_EXCESSIVE_ENTRIES",
                "description": f"Reached maximum allowed ZIP entries ceiling ({MAX_ZIP_ENTRIES})",
            })
            break

        if raw_bytes[offset : offset + 4] != ZIP_LOCAL_HEADER:
            # Stop if encountering central directory or corrupted bytes
            break

        (
            ver,
            flags,
            comp_method,
            mod_time,
            mod_date,
            crc,
            comp_size,
            uncomp_size,
            fn_len,
            extra_len,
        ) = struct.unpack("<HHHHHIIIHH", raw_bytes[offset + 4 : offset + 30])

        header_len = 30 + fn_len + extra_len
        if offset + header_len > total_input_bytes:
            damage_regions.append({
                "offset": offset,
                "length": total_input_bytes - offset,
                "type": "TRUNCATED_LOCAL_HEADER",
                "description": f"Local file header truncated at offset {offset}",
            })
            break

        raw_filename = raw_bytes[offset + 30 : offset + 30 + fn_len]
        try:
            filename = raw_filename.decode("utf-8")
        except UnicodeDecodeError:
            filename = raw_filename.decode("latin-1", errors="replace")

        # Security: Skip entries with zip-slip path traversal
        path_err = check_zip_path_security(filename)
        if path_err:
            damage_regions.append({
                "offset": offset,
                "length": header_len,
                "type": "SECURITY_ZIP_SLIP_DROPPED",
                "description": f"Dropped unsafe member with path traversal: {path_err}",
            })
            break

        data_start = offset + header_len
        data_end = data_start + comp_size

        if data_end > total_input_bytes:
            damage_regions.append({
                "offset": offset,
                "length": total_input_bytes - offset,
                "type": "TRUNCATED_MEMBER_PAYLOAD",
                "description": f"Payload for member '{filename}' truncated ({comp_size} bytes expected)",
            })
            break

        file_payload = raw_bytes[data_start:data_end]

        if uncomp_size > MAX_UNCOMPRESSED_MEMBER_SIZE:
            damage_regions.append({
                "offset": offset,
                "length": header_len,
                "type": "SECURITY_EXCESSIVE_UNCOMPRESSED_SIZE",
                "description": f"Dropped member exceeding uncompressed size limit: '{filename}' ({uncomp_size} bytes)",
            })
            break

        # Verify payload integrity
        payload_valid = False
        if comp_method == 0:  # Stored
            if crc != 0 and zlib.crc32(file_payload) != crc:
                payload_valid = False
            else:
                payload_valid = True
                if uncomp_size == 0:
                    uncomp_size = len(file_payload)
        elif comp_method == 8:  # Deflated
            try:
                dco = zlib.decompressobj(-zlib.MAX_WBITS)
                decomp = dco.decompress(file_payload, MAX_UNCOMPRESSED_MEMBER_SIZE + 1)
                if dco.unconsumed_tail or len(decomp) > MAX_UNCOMPRESSED_MEMBER_SIZE:
                    payload_valid = False
                elif crc != 0 and zlib.crc32(decomp) != crc:
                    payload_valid = False
                else:
                    payload_valid = True
                    if uncomp_size == 0:
                        uncomp_size = len(decomp)
            except Exception:
                payload_valid = False

        if not payload_valid:
            damage_regions.append({
                "offset": data_start,
                "length": comp_size,
                "type": "CORRUPTED_MEMBER_DATA",
                "description": f"Corrupted compressed payload for member '{filename}'",
            })
            break

        surviving_entries.append({
            "local_offset": offset,
            "ver": ver,
            "flags": flags,
            "comp_method": comp_method,
            "mod_time": mod_time,
            "mod_date": mod_date,
            "crc": crc,
            "comp_size": comp_size,
            "uncomp_size": uncomp_size,
            "raw_filename": raw_filename,
            "filename": filename,
            "extra_len": 0,  # Omit extra field in CD for clean compatibility
        })

        surviving_bytes_end = data_end
        offset = data_end

    # 4. If no surviving entries could be validated, archive is unrecoverable
    if not surviving_entries:
        val_fail = validate_zip(raw_bytes)
        return ReconstructionResult(
            format="zip",
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
                    "type": "ZERO_SURVIVING_MEMBERS",
                    "description": "No structurally intact member files found in archive",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_fail,
            is_exact_match=False,
            details={"error": "Zero recoverable member files"},
        )

    if detection_mode == "blind":
        val_fail = validate_zip(raw_bytes)
        return ReconstructionResult(
            format="zip",
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
                    "type": "TRUNCATED_ARCHIVE_IN_BLIND_CARVE",
                    "description": "Missing central directory cannot be synthesized in blind carving mode",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_fail,
            is_exact_match=False,
            details={"error": "Truncated archive in blind carving mode"},
        )

    # 5. Synthesize missing Central Directory and EOCD
    cd_records: List[bytes] = []
    for entry in surviving_entries:
        fn = entry["raw_filename"]
        cd_hdr = (
            ZIP_CENTRAL_HEADER
            + struct.pack(
                "<HHHHHHIIIHHHHHII",
                20,  # version made by (DOS/FAT, ZIP 2.0)
                entry["ver"],
                entry["flags"],
                entry["comp_method"],
                entry["mod_time"],
                entry["mod_date"],
                entry["crc"],
                entry["comp_size"],
                entry["uncomp_size"],
                len(fn),
                0,  # extra field length
                0,  # comment length
                0,  # disk start
                0,  # internal attrs
                0,  # external attrs
                entry["local_offset"],
            )
            + fn
        )
        cd_records.append(cd_hdr)

    cd_bytes = b"".join(cd_records)
    cd_size = len(cd_bytes)
    cd_offset = surviving_bytes_end
    total_entries = len(surviving_entries)

    eocd_record = (
        ZIP_EOCD_SIGNATURE
        + struct.pack(
            "<HHHHIIH",
            0,  # disk number
            0,  # disk with CD
            total_entries,
            total_entries,
            cd_size,
            cd_offset,
            0,  # comment length
        )
    )

    reconstructed_bytes = cd_bytes + eocd_record
    recovered_bytes = raw_bytes[:surviving_bytes_end] + reconstructed_bytes

    verified_bytes = surviving_bytes_end
    reconstructed_byte_count = len(reconstructed_bytes)
    missing_bytes = total_input_bytes - surviving_bytes_end

    # Invariants check
    assert verified_bytes + reconstructed_byte_count == len(recovered_bytes)
    assert verified_bytes + missing_bytes == total_input_bytes

    damage_regions.append({
        "offset": surviving_bytes_end,
        "length": reconstructed_byte_count,
        "type": "SYNTHESIZED_CENTRAL_DIRECTORY",
        "description": f"Synthesized Central Directory ({len(surviving_entries)} entries) and EOCD record",
    })

    val_recon = validate_zip(recovered_bytes)
    if not val_recon.valid:
        return ReconstructionResult(
            format="zip",
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
            details={"error": "Reconstructed ZIP archive failed validation"},
        )

    return ReconstructionResult(
        format="zip",
        status="PARTIALLY_RECOVERED",
        success=True,
        recovered_bytes=recovered_bytes,
        verified_bytes=verified_bytes,
        reconstructed_bytes=reconstructed_byte_count,
        missing_bytes=missing_bytes,
        damage_regions=damage_regions,
        reconstruction_methods=["CENTRAL_DIRECTORY_SYNTHESIS", "EOCD_TRAILER_SYNTHESIS"],
        validation_result=val_recon,
        is_exact_match=False,
        details={
            "reconstruction_method": "CENTRAL_DIRECTORY_SYNTHESIS",
            "recovered_members": [e["filename"] for e in surviving_entries],
            "file_count": len(surviving_entries),
        },
    )
