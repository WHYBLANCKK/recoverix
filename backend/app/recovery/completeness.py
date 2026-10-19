"""
completeness.py — Deterministic artifact completeness assessment.

Evaluates whether evidence is sufficient to establish a complete artifact,
distinguishing known artifact recovery, blind evidence recovery, and synthetic harnesses.

FORENSIC PRINCIPLE:
  - FULLY_RECOVERED is allowed ONLY when:
      1. R == 0 (no reconstructed bytes)
      2. M == 0 (no missing bytes)
      3. The recovered artifact is structurally valid
      4. AND the evidence is sufficient to establish a complete artifact.
  - If R > 0 or M > 0, status CANNOT be FULLY_RECOVERED.
  - If completeness cannot be established, the engine must not pretend certainty.
  - In blind evidence recovery, unstructured text/CSV has no container boundary
    and cannot establish completeness.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from backend.app.models.validation import ValidationResult
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
    PNG_SIGNATURE,
    JPEG_SOI,
    JPEG_EOI,
    PDF_HEADER_SIGNATURE,
    PDF_TRAILER_SIGNATURE,
    XML_HEADER_SIGNATURE,
    ZIP_LOCAL_HEADER,
    ZIP_EOCD_SIGNATURE,
)


def assess_artifact_completeness(
    fmt: str,
    content: bytes,
    detection_mode: str = "known_file",
    validation_result: Optional[ValidationResult] = None,
    missing_bytes: int = 0,
    reconstructed_bytes: int = 0,
) -> bool:
    """Deterministically determine if evidence is sufficient to establish a complete artifact.

    Args:
        fmt: Format identifier ('txt', 'csv', 'json', 'pdf', 'png', 'jpeg', 'xml').
        content: Evidence bytes of the recovered artifact.
        detection_mode: 'known_file', 'blind', or 'synthetic_harness'.
        validation_result: Optional ValidationResult from structural validator.
        missing_bytes: Recorded missing byte count.
        reconstructed_bytes: Recorded reconstructed byte count.

    Returns:
        True ONLY if the evidence is sufficient to establish a complete artifact.
    """
    # Invariant 1: If any bytes are missing or reconstructed, artifact is incomplete
    if missing_bytes > 0 or reconstructed_bytes > 0:
        return False

    # Invariant 2: Empty evidence is never a complete artifact
    if not content:
        return False

    # Invariant 3: Validation failure precludes completeness
    if validation_result is not None and not validation_result.valid:
        return False

    clean_fmt = fmt.lower().strip(".")

    # Mode 1: Synthetic Harness
    if detection_mode == "synthetic_harness" or (SYNTHETIC_START_MARKER in content and SYNTHETIC_END_MARKER in content):
        has_start = SYNTHETIC_START_MARKER in content
        has_end = SYNTHETIC_END_MARKER in content
        if not (has_start and has_end):
            return False
        return content.find(SYNTHETIC_START_MARKER) < content.find(SYNTHETIC_END_MARKER)

    # Mode 2: Blind evidence recovery (carved from raw disk/memory dump)
    if detection_mode == "blind":
        # Unstructured formats without self-terminating container grammar
        # can NEVER establish completeness in blind mode.
        if clean_fmt in ("txt", "csv"):
            return False

        # Self-terminating formats in blind mode require verified start & end markers
        if clean_fmt == "pdf":
            return content.startswith(PDF_HEADER_SIGNATURE) and content.rstrip(b"\r\n\t ").endswith(PDF_TRAILER_SIGNATURE)
        if clean_fmt == "png":
            return content.startswith(PNG_SIGNATURE) and b"IEND" in content
        if clean_fmt == "jpeg":
            return content.startswith(JPEG_SOI) and content.endswith(JPEG_EOI)
        if clean_fmt == "json":
            stripped = content.strip()
            return (
                (stripped.startswith(b"{") and stripped.endswith(b"}"))
                or (stripped.startswith(b"[") and stripped.endswith(b"]"))
            )
        if clean_fmt == "xml":
            return XML_HEADER_SIGNATURE in content or (content.strip().startswith(b"<") and content.strip().endswith(b">"))
        if clean_fmt == "zip":
            return content.startswith(ZIP_LOCAL_HEADER) and ZIP_EOCD_SIGNATURE in content

        return False

    # Mode 3: Known file recovery (standalone file upload)
    if clean_fmt == "txt":
        # Text must not contain binary null bytes or unprintable control noise
        if b"\x00" in content:
            return False
        # Text must be valid UTF-8
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return False

        # Multi-line text must end with a line terminator
        if b"\n" in content:
            return content.endswith(b"\n") or content.endswith(b"\r\n")

        # Single-line text must also end with a newline to prove it was not truncated mid-line
        return content.endswith(b"\n") or content.endswith(b"\r\n")

    if clean_fmt == "csv":
        if b"\x00" in content:
            return False
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return False

        # CSV must end with a newline terminator
        if not (content.endswith(b"\n") or content.endswith(b"\r\n")):
            return False

        lines = [line for line in text.splitlines() if line.strip()]
        if len(lines) < 2:
            return False

        # Verify delimiter and consistent column count
        import csv
        import io

        delims = [",", ";", "\t", "|"]
        valid_delim = None
        for delim in delims:
            try:
                reader = csv.reader(io.StringIO("\n".join(lines)), delimiter=delim)
                rows = list(reader)
                if len(rows) == len(lines):
                    counts = [len(r) for r in rows]
                    if all(c > 1 for c in counts) and len(set(counts)) == 1:
                        valid_delim = delim
                        break
            except Exception:
                pass

        return valid_delim is not None

    if clean_fmt == "json":
        stripped = content.strip()
        return (
            (stripped.startswith(b"{") and stripped.endswith(b"}"))
            or (stripped.startswith(b"[") and stripped.endswith(b"]"))
        )

    if clean_fmt == "pdf":
        return PDF_HEADER_SIGNATURE in content and content.rstrip(b"\r\n\t ").endswith(PDF_TRAILER_SIGNATURE)

    if clean_fmt == "png":
        return content.startswith(PNG_SIGNATURE) and b"IEND" in content

    if clean_fmt == "jpeg":
        return content.startswith(JPEG_SOI) and content.endswith(JPEG_EOI)

    if clean_fmt == "xml":
        stripped = content.strip()
        return stripped.startswith(b"<") and stripped.endswith(b">")

    if clean_fmt == "zip":
        return content.startswith(ZIP_LOCAL_HEADER) and ZIP_EOCD_SIGNATURE in content

    return False
