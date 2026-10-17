"""
signatures.py — Controlled format-signature registry.

Defines the signature patterns the scanner uses to identify candidate
artifact regions in raw evidence bytes across the 7 supported formats:

  - TXT  (synthetic boundary markers or plain UTF-8 text)
  - CSV  (synthetic boundary markers or CSV structure)
  - JSON (JSON header '{' / '[' or synthetic boundary markers)
  - XML  (XML header '<?xml' / '<' or synthetic boundary markers)
  - PNG  (standard PNG magic bytes 0x89 50 4E 47 0D 0A 1A 0A)
  - JPEG (ISO/IEC 10918-1 SOI marker 0xFF 0xD8)
  - PDF  (standard PDF magic header '%PDF-')

This module does NOT perform recovery, carving, reconstruction,
classification, or AI work.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


# ── Synthetic boundary markers (shared by test harness) ──────────────

SYNTHETIC_START_MARKER: bytes = b"[SYNTHETIC_ARTIFACT_START]"
SYNTHETIC_END_MARKER: bytes = b"[SYNTHETIC_ARTIFACT_END]"

# ── Image magic signatures ─────────────────────────────────────────

PNG_SIGNATURE: bytes = b"\x89PNG\r\n\x1a\n"
JPEG_SOI: bytes = b"\xff\xd8"
JPEG_EOI: bytes = b"\xff\xd9"

# ── Document magic signatures ─────────────────────────────────────

PDF_HEADER_SIGNATURE: bytes = b"%PDF-"
PDF_TRAILER_SIGNATURE: bytes = b"%%EOF"

# ── Structured text signatures ─────────────────────────────────────

XML_HEADER_SIGNATURE: bytes = b"<?xml"

# ── Archive magic signatures ───────────────────────────────────────

ZIP_LOCAL_HEADER: bytes = b"PK\x03\x04"
ZIP_CENTRAL_HEADER: bytes = b"PK\x01\x02"
ZIP_EOCD_SIGNATURE: bytes = b"PK\x05\x06"


@dataclass(frozen=True)
class FormatSignature:
    """Describes how the scanner identifies one artifact format.

    Attributes:
        format: Short format identifier (e.g. ``"txt"``, ``"csv"``, ``"png"``, ``"jpeg"``, ``"json"``, ``"xml"``, ``"pdf"``).
        mime_type: MIME type string.
        category: Human-readable category (e.g. ``"text"``, ``"image"``, ``"structured"``, ``"document"``).
        header: Byte pattern that marks the start of the artifact.
        footer: Optional byte pattern that marks the end.  ``None`` means
                the end cannot be determined from a trailer alone.
        detection_method: Label describing how this signature is detected.
    """

    format: str
    mime_type: str
    category: str
    header: bytes
    footer: Optional[bytes]
    detection_method: str


# ── Registry ────────────────────────────────────────────────────────

SIGNATURES: List[FormatSignature] = [
    FormatSignature(
        format="txt",
        mime_type="text/plain",
        category="text",
        header=SYNTHETIC_START_MARKER,
        footer=SYNTHETIC_END_MARKER,
        detection_method="synthetic_boundary",
    ),
    FormatSignature(
        format="csv",
        mime_type="text/csv",
        category="text",
        header=SYNTHETIC_START_MARKER,
        footer=SYNTHETIC_END_MARKER,
        detection_method="synthetic_boundary",
    ),
    FormatSignature(
        format="json",
        mime_type="application/json",
        category="structured",
        header=b"{",
        footer=b"}",
        detection_method="syntax_boundary",
    ),
    FormatSignature(
        format="xml",
        mime_type="application/xml",
        category="structured",
        header=XML_HEADER_SIGNATURE,
        footer=b">",
        detection_method="magic_bytes",
    ),
    FormatSignature(
        format="png",
        mime_type="image/png",
        category="image",
        header=PNG_SIGNATURE,
        footer=b"IEND\xaeB`\x82",
        detection_method="magic_bytes",
    ),
    FormatSignature(
        format="jpeg",
        mime_type="image/jpeg",
        category="image",
        header=JPEG_SOI,
        footer=JPEG_EOI,
        detection_method="magic_bytes",
    ),
    FormatSignature(
        format="pdf",
        mime_type="application/pdf",
        category="document",
        header=PDF_HEADER_SIGNATURE,
        footer=PDF_TRAILER_SIGNATURE,
        detection_method="magic_bytes",
    ),
    FormatSignature(
        format="zip",
        mime_type="application/zip",
        category="archive",
        header=ZIP_LOCAL_HEADER,
        footer=ZIP_EOCD_SIGNATURE,
        detection_method="magic_bytes",
    ),
]
