"""
registry.py — Central Format Registry for Recoverix.

Maps supported format identifiers (txt, csv, json, xml, png, jpeg, pdf) to their
metadata, MIME types, categories, magic bytes/signatures, and structural validators.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, List, Dict

from backend.app.models.validation import ValidationResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
    PNG_SIGNATURE,
    JPEG_SOI,
    JPEG_EOI,
    PDF_HEADER_SIGNATURE,
    PDF_TRAILER_SIGNATURE,
    ZIP_LOCAL_HEADER,
    ZIP_EOCD_SIGNATURE,
)
from backend.app.recovery.validators import (
    validate_txt,
    validate_csv,
    validate_json,
    validate_xml,
    validate_png,
    validate_jpeg,
    validate_pdf,
    validate_zip,
)


@dataclass(frozen=True)
class FormatSpec:
    """Format Specification descriptor.

    Attributes:
        format: Short format identifier ('txt', 'csv', 'json', 'xml', 'png', 'jpeg', 'pdf').
        name: Human-readable display name.
        mime_type: Standard MIME type string.
        category: General category ('text', 'structured', 'image', 'document').
        extensions: Standard file extensions.
        header_signature: Header magic bytes or synthetic start marker.
        footer_signature: Optional footer marker or trailer bytes.
        validator: Callable performing deterministic structural validation.
    """

    format: str
    name: str
    mime_type: str
    category: str
    extensions: List[str]
    header_signature: Optional[bytes]
    footer_signature: Optional[bytes]
    validator: Callable[[bytes | RecoveredArtifact], ValidationResult]


FORMAT_REGISTRY: Dict[str, FormatSpec] = {
    "txt": FormatSpec(
        format="txt",
        name="Text Document",
        mime_type="text/plain",
        category="text",
        extensions=[".txt", ".text"],
        header_signature=SYNTHETIC_START_MARKER,
        footer_signature=SYNTHETIC_END_MARKER,
        validator=validate_txt,
    ),
    "csv": FormatSpec(
        format="csv",
        name="Comma-Separated Values",
        mime_type="text/csv",
        category="text",
        extensions=[".csv"],
        header_signature=SYNTHETIC_START_MARKER,
        footer_signature=SYNTHETIC_END_MARKER,
        validator=validate_csv,
    ),
    "json": FormatSpec(
        format="json",
        name="JSON Document",
        mime_type="application/json",
        category="structured",
        extensions=[".json"],
        header_signature=b"{",
        footer_signature=b"}",
        validator=validate_json,
    ),
    "xml": FormatSpec(
        format="xml",
        name="XML Document",
        mime_type="application/xml",
        category="structured",
        extensions=[".xml"],
        header_signature=b"<?xml",
        footer_signature=b">",
        validator=validate_xml,
    ),
    "png": FormatSpec(
        format="png",
        name="Portable Network Graphics",
        mime_type="image/png",
        category="image",
        extensions=[".png"],
        header_signature=PNG_SIGNATURE,
        footer_signature=b"IEND\xaeB`\x82",
        validator=validate_png,
    ),
    "jpeg": FormatSpec(
        format="jpeg",
        name="JPEG Image",
        mime_type="image/jpeg",
        category="image",
        extensions=[".jpg", ".jpeg"],
        header_signature=JPEG_SOI,
        footer_signature=JPEG_EOI,
        validator=validate_jpeg,
    ),
    "pdf": FormatSpec(
        format="pdf",
        name="Portable Document Format",
        mime_type="application/pdf",
        category="document",
        extensions=[".pdf"],
        header_signature=PDF_HEADER_SIGNATURE,
        footer_signature=PDF_TRAILER_SIGNATURE,
        validator=validate_pdf,
    ),
    "zip": FormatSpec(
        format="zip",
        name="ZIP Archive",
        mime_type="application/zip",
        category="archive",
        extensions=[".zip"],
        header_signature=ZIP_LOCAL_HEADER,
        footer_signature=ZIP_EOCD_SIGNATURE,
        validator=validate_zip,
    ),
}

# Alias mapping for jpg -> jpeg
FORMAT_REGISTRY["jpg"] = FORMAT_REGISTRY["jpeg"]


def get_format_spec(fmt: str) -> Optional[FormatSpec]:
    """Retrieve format specification by format string.

    Args:
        fmt: Short format identifier (e.g. 'txt', 'csv', 'png', '.json', 'pdf', 'zip').

    Returns:
        FormatSpec if found, or None.
    """
    clean_fmt = fmt.lower().strip(".")
    return FORMAT_REGISTRY.get(clean_fmt)


def list_supported_formats() -> List[str]:
    """Return ordered list of supported core format keys."""
    return ["txt", "csv", "json", "xml", "png", "jpeg", "pdf", "zip"]
