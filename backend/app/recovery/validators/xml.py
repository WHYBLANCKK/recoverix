"""
xml.py — Deterministic XML artifact structural validator.

Validates recovered XML artifact bytes against synthetic harness boundaries (if present)
or direct XML syntax, encoding requirements (UTF-8, UTF-16LE, UTF-16BE), and safe parsing rules.
Defends against XML External Entity (XXE) and recursive entity expansion (Billion Laughs) attacks
at both lexical and parser-level layers.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import xml.parsers.expat as expat
from typing import Union, Any, Optional, Tuple

from backend.app.models.validation import ValidationResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)
from backend.app.recovery.xml_security import (
    decode_xml_bytes,
    check_xml_security,
    safe_parse_xml,
    XMLSecurityError,
)

__all__ = [
    "validate_xml",
    "check_xml_security",
    "decode_xml_bytes",
    "safe_parse_xml",
    "XMLSecurityError",
]


def validate_xml(data: bytes | RecoveredArtifact) -> ValidationResult:
    """Validate the structural integrity of a recovered XML artifact.

    Accepts raw bytes or a RecoveredArtifact object.

    Checks performed:
      1. input_type: input is bytes or RecoveredArtifact yielding bytes
      2. non_empty: input is non-empty
      3. security_audit: checks for XXE and recursive entity expansion (multi-byte safe)
      4. synthetic markers check (if present: start_marker_exists, end_marker_exists, marker_ordering)
      5. encoding_decoding: payload can be safely decoded (UTF-8, UTF-16LE, UTF-16BE)
      6. xml_parsing: text parses successfully with parser-level safety controls
      7. root_structure: checks root element tag, attribute count, and child count

    Args:
        data: Raw evidence bytes or RecoveredArtifact.

    Returns:
        ValidationResult with validation outcome, checks, errors, and details.
    """
    checks: list[str] = [
        "input_type",
        "non_empty",
        "security_audit",
        "utf8_decoding",
        "xml_parsing",
        "root_structure",
    ]

    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}

    raw_bytes: bytes
    fmt: str = "xml"
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

    # Check for synthetic markers if present
    start_pos = raw_bytes.find(SYNTHETIC_START_MARKER)
    end_pos = raw_bytes.find(SYNTHETIC_END_MARKER)

    body_bytes = raw_bytes
    if start_pos != -1 or end_pos != -1:
        checks.extend(["start_marker_exists", "end_marker_exists", "marker_ordering"])
        if start_pos == -1:
            errors.append(f"Missing synthetic start marker: {SYNTHETIC_START_MARKER.decode('utf-8', errors='replace')}")
        if end_pos == -1:
            errors.append(f"Missing synthetic end marker: {SYNTHETIC_END_MARKER.decode('utf-8', errors='replace')}")
        if start_pos != -1 and end_pos != -1:
            if start_pos >= end_pos:
                errors.append(
                    f"Invalid marker ordering: start marker at offset {start_pos} "
                    f"occurs at or after end marker at offset {end_pos}"
                )
            else:
                body_start = start_pos + len(SYNTHETIC_START_MARKER)
                body_bytes = raw_bytes[body_start:end_pos]

    # 3. Security audit check (applied to decoded text, neutralizes multi-byte evasion)
    sec_err = check_xml_security(body_bytes)
    if sec_err:
        errors.append(f"Security: {sec_err}")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    # 4. Decoding check (supports UTF-8, UTF-16LE, UTF-16BE)
    text, encoding, decode_err = decode_xml_bytes(body_bytes)
    details["encoding"] = encoding
    if decode_err:
        errors.append(decode_err)
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    stripped_text = text.strip()
    if not stripped_text:
        errors.append("XML payload text is empty after trimming whitespace")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    # 5. Safe XML parsing check with parser-level controls
    try:
        root = safe_parse_xml(stripped_text)
        details["root_tag"] = root.tag
        details["child_count"] = len(root)
        details["attribute_count"] = len(root.attrib)
        if stripped_text.startswith("<?xml"):
            details["has_xml_declaration"] = True
    except XMLSecurityError as e:
        errors.append(f"Security: {e}")
    except (expat.ExpatError, ET.ParseError) as e:
        errors.append(f"XML parsing failed: {e}")
    except Exception as e:
        errors.append(f"Unexpected error during XML parsing: {e}")

    valid = len(errors) == 0
    return ValidationResult(
        valid=valid,
        format=fmt,
        checks_performed=checks,
        errors=errors,
        warnings=warnings,
        details=details,
    )
