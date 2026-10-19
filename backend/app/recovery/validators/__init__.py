"""
validators — Structural validation package for recovered artifacts.

Provides deterministic validators for TXT, CSV, JSON, XML, PNG, JPEG, and PDF artifacts.
"""

from __future__ import annotations

from typing import Union, Callable
from backend.app.models.validation import ValidationResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.validators.text import validate_txt
from backend.app.recovery.validators.csv import validate_csv
from backend.app.recovery.validators.json import validate_json
from backend.app.recovery.validators.xml import validate_xml
from backend.app.recovery.validators.png import validate_png
from backend.app.recovery.validators.jpeg import validate_jpeg
from backend.app.recovery.validators.pdf import validate_pdf
from backend.app.recovery.validators.zip import validate_zip

VALIDATORS: dict[str, Callable[[bytes | RecoveredArtifact], ValidationResult]] = {
    "txt": validate_txt,
    "csv": validate_csv,
    "json": validate_json,
    "xml": validate_xml,
    "png": validate_png,
    "jpeg": validate_jpeg,
    "jpg": validate_jpeg,
    "pdf": validate_pdf,
    "zip": validate_zip,
}


def validate_artifact(fmt: str, data: bytes | RecoveredArtifact) -> ValidationResult:
    """Route validation to the appropriate format validator.

    Args:
        fmt: Short format identifier ('txt', 'csv', 'json', 'xml', 'png', 'jpeg', 'pdf', 'zip').
        data: Raw evidence bytes or RecoveredArtifact.

    Returns:
        ValidationResult from the format validator, or error ValidationResult if unhandled format.
    """
    clean_fmt = fmt.lower().strip(".")
    validator = VALIDATORS.get(clean_fmt)
    if validator is not None:
        return validator(data)

    return ValidationResult(
        valid=False,
        format=clean_fmt,
        checks_performed=["format_support"],
        errors=[f"Unsupported format for structural validation: {fmt}"],
    )


__all__ = [
    "validate_txt",
    "validate_csv",
    "validate_json",
    "validate_xml",
    "validate_png",
    "validate_jpeg",
    "validate_pdf",
    "validate_zip",
    "validate_artifact",
    "VALIDATORS",
]
