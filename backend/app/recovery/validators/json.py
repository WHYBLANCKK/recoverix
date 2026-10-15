"""
json.py — Deterministic JSON artifact structural validator.

Validates recovered JSON artifact bytes against synthetic harness boundaries (if present)
or direct JSON syntax, UTF-8 encoding, and json module parsing rules.
"""

from __future__ import annotations

import json
from typing import Union, Any

from backend.app.models.validation import ValidationResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)


def validate_json(data: bytes | RecoveredArtifact) -> ValidationResult:
    """Validate the structural integrity of a recovered JSON artifact.

    Accepts raw bytes or a RecoveredArtifact object.

    Checks performed:
      1. input_type: input is bytes or RecoveredArtifact yielding bytes
      2. non_empty: input is non-empty
      3. synthetic markers check (if present: start_marker_exists, end_marker_exists, marker_ordering)
      4. utf8_decoding: payload can be safely decoded as UTF-8
      5. json_parsing: text parses successfully with json.loads
      6. root_structure: checks object or array root structure

    Args:
        data: Raw evidence bytes or RecoveredArtifact.

    Returns:
        ValidationResult with validation outcome, checks, errors, and details.
    """
    checks: list[str] = [
        "input_type",
        "non_empty",
        "utf8_decoding",
        "json_parsing",
        "root_structure",
    ]
    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}

    raw_bytes: bytes
    fmt: str = "json"
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

    stripped_text = text.strip("\x00 \t\r\n")
    if not stripped_text:
        errors.append("JSON payload text is empty after trimming whitespace")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    if text.strip(" \t\r\n") != stripped_text:
        warnings.append("Stripped NUL padding around JSON payload")

    # 5. JSON parsing check
    try:
        parsed = json.loads(stripped_text)
        details["root_type"] = type(parsed).__name__
        if isinstance(parsed, dict):
            details["key_count"] = len(parsed)
            details["root_keys"] = list(parsed.keys())[:10]
        elif isinstance(parsed, list):
            details["item_count"] = len(parsed)
        else:
            warnings.append(f"JSON root element is primitive ({type(parsed).__name__}), expected object or array")
    except json.JSONDecodeError as e:
        errors.append(f"JSON parsing failed at line {e.lineno}, col {e.colno}: {e.msg}")
    except Exception as e:
        errors.append(f"Unexpected error during JSON parsing: {e}")

    valid = len(errors) == 0
    return ValidationResult(
        valid=valid,
        format=fmt,
        checks_performed=checks,
        errors=errors,
        warnings=warnings,
        details=details,
    )
