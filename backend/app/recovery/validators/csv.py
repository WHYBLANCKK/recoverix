"""
csv.py — Deterministic CSV artifact structural validator.

Validates recovered CSV artifact bytes against synthetic harness boundaries (if present)
or direct CSV content, UTF-8 encoding, Python csv module parsing rules, and row structural consistency.
"""

from __future__ import annotations

import csv
import io
from typing import Union, Any

from backend.app.models.validation import ValidationResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)


def validate_csv(data: bytes | RecoveredArtifact) -> ValidationResult:
    """Validate the structural integrity of a recovered CSV artifact.

    Accepts raw bytes or a RecoveredArtifact object.

    Checks performed:
      1. input_type: input is bytes (or RecoveredArtifact yielding bytes)
      2. non_empty: input is non-empty
      3. synthetic markers check (if present: start_marker_exists, end_marker_exists, marker_ordering)
      4. utf8_decoding: payload can be safely decoded as UTF-8
      5. csv_parsing: body parses successfully with csv.reader
      6. row_consistency: all non-empty rows have a consistent column count

    Args:
        data: Raw evidence bytes or RecoveredArtifact.

    Returns:
        ValidationResult with validation outcome, checks, errors, and details.
    """
    checks: list[str] = [
        "input_type",
        "non_empty",
        "utf8_decoding",
        "csv_parsing",
        "row_consistency",
    ]
    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}

    raw_bytes: bytes
    fmt: str = "csv"
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

    # Check for synthetic markers
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

    # Null byte rejection
    if b"\x00" in raw_bytes:
        errors.append("CSV content contains binary null bytes")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    # UTF-8 decoding check
    try:
        body_text = body_bytes.decode("utf-8")
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

    # Quote balance check: odd number of double-quotes indicates an unclosed quote
    if body_text.count('"') % 2 != 0:
        errors.append("Unclosed double-quote in CSV content: total quote count is odd")
        return ValidationResult(
            valid=False,
            format=fmt,
            checks_performed=checks,
            errors=errors,
            warnings=warnings,
            details=details,
        )

    # CSV parsing check with delimiter detection fallback
    try:
        f = io.StringIO(body_text)
        # Attempt standard comma delimiter first
        reader = csv.reader(f)
        rows = [row for row in reader if any(field.strip() for field in row)]

        # If comma yields single column rows, try alternative delimiters (;, \t, |)
        if rows and all(len(r) == 1 for r in rows):
            for delim in [";", "\t", "|"]:
                f.seek(0)
                alt_reader = csv.reader(f, delimiter=delim)
                alt_rows = [row for row in alt_reader if any(field.strip() for field in row)]
                if alt_rows and any(len(r) > 1 for r in alt_rows):
                    rows = alt_rows
                    details["delimiter"] = delim
                    break

            if all(len(r) == 1 for r in rows) and not any(d in body_text for d in (",", ";", "\t", "|")):
                errors.append("CSV requires valid tabular structure with a recognized delimiter (, ; \\t |)")

        details["row_count"] = len(rows)

        if len(rows) == 0:
            errors.append("CSV body contains no data rows")
        else:
            col_counts = [len(row) for row in rows]
            details["column_counts"] = col_counts
            first_count = col_counts[0]
            if any(c != first_count for c in col_counts):
                errors.append(f"Inconsistent row structure: column counts vary across rows ({col_counts})")
    except csv.Error as e:
        errors.append(f"CSV parsing failed: {e}")
    except Exception as e:
        errors.append(f"Unexpected error during CSV parsing: {e}")

    valid = len(errors) == 0
    return ValidationResult(
        valid=valid,
        format=fmt,
        checks_performed=checks,
        errors=errors,
        warnings=warnings,
        details=details,
    )
