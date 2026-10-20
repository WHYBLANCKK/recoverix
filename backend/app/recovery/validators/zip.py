"""
zip.py — Deterministic ZIP archive structural validator for Recoverix.

Validates recovered ZIP archive bytes against PKWARE APPNOTE / ISO/IEC 21320-1 standards:
  - Local file header magic signature (PK\\x03\\x04)
  - Central directory file headers (PK\\x01\\x02)
  - End of Central Directory record (PK\\x05\\x06)
  - Decompression and CRC-32 integrity
  - Security audit: Zip-Slip path traversal and Zip-Bomb ratio checks
"""

from __future__ import annotations

import io
import struct
import zipfile
from typing import Any, Dict, List, Optional, Union

from backend.app.models.validation import ValidationResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import ZIP_LOCAL_HEADER, ZIP_CENTRAL_HEADER, ZIP_EOCD_SIGNATURE

MAX_SAFE_EXPANSION_RATIO = 100.0
MAX_SAFE_UNCOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MiB


def check_zip_path_security(path: str) -> Optional[str]:
    """Check whether an archive member path is safe from Zip-Slip and path traversal.

    Normalizes separators, checks for Windows drive prefixes, UNC network paths,
    absolute paths, and parent-directory traversal ('..') components.

    Returns:
        None if the path is safe, or an error description string if unsafe.
    """
    if not path or "\x00" in path:
        return "Null or empty path"

    # Reject Windows drive-prefixed paths (C:\file, C:/file, C:payload, d:foo/bar)
    if len(path) >= 2 and path[0].isalpha() and path[1] == ":":
        return f"Windows drive prefix in member path '{path}'"

    # Normalize all backslashes to forward slashes for unified path analysis
    norm = path.replace("\\", "/")

    # Reject UNC / network paths (//server/share or \\server\share)
    if norm.startswith("//"):
        return f"UNC network path in member path '{path}'"

    # Reject absolute paths (/etc/passwd or \Windows\...)
    if norm.startswith("/"):
        return f"Absolute path in member path '{path}'"

    # Reject parent traversal components
    parts = norm.split("/")
    if ".." in parts:
        return f"Parent directory traversal ('..') in member path '{path}'"

    return None


def is_safe_zip_path(path: str) -> bool:
    """Return True if archive member path is safe, False otherwise."""
    return check_zip_path_security(path) is None


def validate_zip(data: bytes | RecoveredArtifact) -> ValidationResult:
    """Validate the structural and security integrity of a recovered ZIP archive.

    Accepts raw bytes or a RecoveredArtifact object.

    Checks performed:
      1. input_type: input is bytes or RecoveredArtifact
      2. non_empty: input is non-empty
      3. magic_bytes: starts with PK\\x03\\x04
      4. local_headers: valid local file header sequence
      5. central_directory: valid central directory records
      6. eocd_termination: valid End of Central Directory record (PK\\x05\\x06)
      7. decompression_integrity: testzip() passes with matching CRC32
      8. security_audit: checks for zip-slip paths and zip-bomb expansion

    Args:
        data: Raw evidence bytes or RecoveredArtifact.

    Returns:
        ValidationResult with outcome, checks, errors, warnings, and details.
    """
    checks: list[str] = [
        "input_type",
        "non_empty",
        "magic_bytes",
        "local_headers",
        "central_directory",
        "eocd_termination",
        "decompression_integrity",
        "security_audit",
    ]
    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}

    raw_bytes: bytes
    fmt: str = "zip"
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
    total_len = len(raw_bytes)
    if total_len == 0:
        errors.append("Artifact bytes are empty")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
        )

    # 2. Magic signature check (starts with PK\x03\x04)
    if not raw_bytes.startswith(ZIP_LOCAL_HEADER):
        errors.append("Missing valid 4-byte ZIP Local File Header signature (PK\\x03\\x04)")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    # 3. Locate End of Central Directory (EOCD: PK\x05\x06)
    # Search backwards from end of file (max comment length is 65535)
    eocd_pos = raw_bytes.rfind(ZIP_EOCD_SIGNATURE)
    if eocd_pos == -1:
        errors.append("Missing required End of Central Directory (EOCD) record (PK\\x05\\x06)")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    if eocd_pos + 22 > total_len:
        errors.append("Truncated End of Central Directory (EOCD) record header")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    disk_num, cd_disk, disk_entries, total_entries, cd_size, cd_offset, comment_len = struct.unpack(
        "<HHHHIIH", raw_bytes[eocd_pos + 4 : eocd_pos + 22]
    )
    details["total_entries"] = total_entries
    details["cd_size"] = cd_size
    details["cd_offset"] = cd_offset
    details["end_offset"] = eocd_pos + 22 + comment_len

    if details["end_offset"] > total_len:
        errors.append(f"EOCD comment length ({comment_len}) exceeds file bounds")

    if cd_offset + cd_size > eocd_pos:
        errors.append(f"Central directory range [{cd_offset}..{cd_offset + cd_size}] overlaps or exceeds EOCD offset {eocd_pos}")

    # 4. Parse using Python's standard zipfile library for thorough verification
    files_info: List[Dict[str, Any]] = []
    total_uncompressed = 0
    total_compressed = 0

    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes), mode="r") as zf:
            namelist = zf.namelist()
            infolist = zf.infolist()
            details["file_count"] = len(infolist)

            # Security Audit: Path Traversal (Zip-Slip)
            for zinfo in infolist:
                fname = zinfo.filename
                path_err = check_zip_path_security(fname)
                if path_err:
                    errors.append(f"Security: Detected Zip-Slip path traversal vulnerability: {path_err}")

                total_uncompressed += zinfo.file_size
                total_compressed += zinfo.compress_size

                files_info.append({
                    "filename": fname,
                    "file_size": zinfo.file_size,
                    "compress_size": zinfo.compress_size,
                    "compress_type": zinfo.compress_type,
                    "crc": zinfo.CRC,
                    "is_dir": zinfo.is_dir(),
                })

            details["files"] = files_info[:50]
            details["total_uncompressed_bytes"] = total_uncompressed
            details["total_compressed_bytes"] = total_compressed

            # Security Audit: Zip-Bomb expansion check
            has_security_violation = False
            if total_compressed > 0:
                ratio = total_uncompressed / total_compressed
                if ratio > MAX_SAFE_EXPANSION_RATIO and total_uncompressed > MAX_SAFE_UNCOMPRESSED_SIZE:
                    errors.append(
                        f"Security: Decompression ratio {ratio:.1f}:1 exceeds safe limits (potential Zip-Bomb)"
                    )
                    has_security_violation = True

            if total_uncompressed > MAX_SAFE_UNCOMPRESSED_SIZE:
                errors.append(
                    f"Security: Total uncompressed archive size ({total_uncompressed} bytes) exceeds safe limit ({MAX_SAFE_UNCOMPRESSED_SIZE} bytes)"
                )
                has_security_violation = True

            if any("Zip-Slip" in e for e in errors):
                has_security_violation = True

            # Integrity test: verify CRC-32 of member files ONLY if no security violations were detected.
            # Never invoke zf.testzip() if decompression-bomb or Zip-Slip thresholds were breached.
            if not has_security_violation and not errors:
                bad_file = zf.testzip()
                if bad_file is not None:
                    errors.append(f"CRC-32 checksum mismatch or corruption detected in archive member: '{bad_file}'")

    except zipfile.BadZipFile as bzf:
        errors.append(f"Corrupted or invalid ZIP structure: {str(bzf)}")
    except Exception as exc:
        errors.append(f"Failed to parse ZIP archive: {str(exc)}")

    valid = len(errors) == 0
    return ValidationResult(
        valid=valid,
        format=fmt,
        checks_performed=checks,
        errors=errors,
        warnings=warnings,
        details=details,
    )
