"""
xml.py — Deterministic XML artifact structural validator.

Validates recovered XML artifact bytes against synthetic harness boundaries (if present)
or direct XML syntax, UTF-8 encoding, and ElementTree parsing rules.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Union, Any, Optional

from backend.app.models.validation import ValidationResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)


def check_xml_security(data: bytes) -> Optional[str]:
    """Check for unsafe XML constructs (XXE, Billion Laughs entity bombs).

    Returns an error description if unsafe, or None if safe.
    """
    lower = data.lower()
    if b"<!doctype" in lower and (b"system" in lower or b"public" in lower):
        return "XML contains external entity reference (XXE vulnerability protection)"
    if b"<!entity" in lower:
        # Check for external entities (SYSTEM, PUBLIC)
        if b"system" in lower or b"public" in lower:
            return "XML contains external entity reference (XXE vulnerability protection)"
        # Check for recursive entity expansion (Billion Laughs)
        entity_count = lower.count(b"<!entity")
        if entity_count > 3:
            return "XML contains excessive entity declarations (Entity expansion protection)"
    return None


def validate_xml(data: bytes | RecoveredArtifact) -> ValidationResult:
    """Validate the structural integrity of a recovered XML artifact.

    Accepts raw bytes or a RecoveredArtifact object.

    Checks performed:
      1. input_type: input is bytes or RecoveredArtifact yielding bytes
      2. non_empty: input is non-empty
      3. security_audit: checks for XXE and recursive entity expansion
      4. synthetic markers check (if present: start_marker_exists, end_marker_exists, marker_ordering)
      5. utf8_decoding: payload can be safely decoded as UTF-8
      6. xml_parsing: text parses successfully with ElementTree.fromstring
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

    # 4. UTF-8 decoding check
    try:
        text = body_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        errors.append(f"UTF-8 decoding failed: {e}")
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

    # 5. Security audit check
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

    # 6. XML parsing check
    try:
        root = ET.fromstring(stripped_text)
        details["root_tag"] = root.tag
        details["child_count"] = len(root)
        details["attribute_count"] = len(root.attrib)
        if stripped_text.startswith("<?xml"):
            details["has_xml_declaration"] = True
    except ET.ParseError as e:
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
