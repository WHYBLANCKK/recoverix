"""
xml.py — Deterministic XML reconstruction engine for Recoverix.

Recovers damaged XML evidence by establishing, from surviving bytes alone,
which structural elements are forced by the evidence and which are genuinely missing.

Capabilities:
  - Deterministically closes unclosed parent and root elements using an exact tag stack.
  - Drops incomplete trailing tokens (unterminated tags, unclosed attributes) safely
    without hallucinating values or tag names.
  - Rejects unsafe XML containing entity expansion (Billion Laughs) or external entity (XXE) attacks.
  - Preserves XML namespaces, attributes, and element hierarchy.
  - Enforces strict forensic accounting:
      verified_bytes + reconstructed_bytes == len(recovered_bytes)
      verified_bytes + missing_bytes == total_input_bytes
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from backend.app.models.reconstruction import ReconstructionResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
    XML_HEADER_SIGNATURE,
)
from backend.app.recovery.validators.xml import validate_xml, check_xml_security

_check_xml_security = check_xml_security

_TOKEN_PATTERN = re.compile(
    r"(?P<pi><\?.*?\?>)|"
    r"(?P<comment><!--.*?-->)|"
    r"(?P<cdata><!\[CDATA\[.*?\]\]>)|"
    r"(?P<doctype><!DOCTYPE[^>[]*(\[[^]]*\])?>)|"
    r"(?P<close></(?P<closetag>[a-zA-Z_:][a-zA-Z0-9._:-]*)\s*>)|"
    r"(?P<empty><(?P<emptytag>[a-zA-Z_:][a-zA-Z0-9._:-]*)(\s+[^>]*)?/>)|"
    r"(?P<open><(?P<opentag>[a-zA-Z_:][a-zA-Z0-9._:-]*)(\s+[^>]*)?>)|"
    r"(?P<text>[^<]+)",
    re.DOTALL,
)




def reconstruct_xml(
    data: bytes | RecoveredArtifact,
    original_data: Optional[bytes] = None,
    detection_mode: str = "known_file",
) -> ReconstructionResult:
    """Deterministically reconstruct damaged XML evidence into a structurally valid XML document.

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
        val_res = validate_xml(b"")
        return ReconstructionResult(
            format="xml",
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

    # Security pre-check
    security_error = _check_xml_security(raw_bytes)
    if security_error:
        val_res = validate_xml(raw_bytes)
        return ReconstructionResult(
            format="xml",
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
                    "type": "SECURITY_REJECTION",
                    "description": security_error,
                }
            ],
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False,
            details={"error": security_error},
        )

    # Check for synthetic harness markers
    start_pos = raw_bytes.find(SYNTHETIC_START_MARKER)
    end_pos = raw_bytes.find(SYNTHETIC_END_MARKER)

    marker_start_bytes = b""
    marker_end_bytes = b""
    body_bytes = raw_bytes

    if start_pos != -1 and end_pos != -1 and start_pos < end_pos:
        marker_start_bytes = raw_bytes[: start_pos + len(SYNTHETIC_START_MARKER)]
        body_bytes = raw_bytes[start_pos + len(SYNTHETIC_START_MARKER) : end_pos]
        marker_end_bytes = raw_bytes[end_pos:]
    elif start_pos != -1:
        marker_start_bytes = raw_bytes[: start_pos + len(SYNTHETIC_START_MARKER)]
        body_bytes = raw_bytes[start_pos + len(SYNTHETIC_START_MARKER) :]

    # Check if raw_bytes is already fully valid intact XML
    val_initial = validate_xml(raw_bytes)
    if val_initial.valid:
        is_exact = None
        if original_data is not None:
            is_exact = hashlib.sha256(raw_bytes).digest() == hashlib.sha256(original_data).digest()
        return ReconstructionResult(
            format="xml",
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
            details={"status": "Intact XML document with valid structure"},
        )

    # Decode body as UTF-8
    try:
        body_text = body_bytes.decode("utf-8")
        trimmed_utf8_len = 0
    except UnicodeDecodeError:
        # Check for truncated multi-byte sequence at tail
        trimmed_utf8_len = 0
        working = body_bytes
        for cutoff in range(1, min(4, len(working) + 1)):
            try:
                working[:-cutoff].decode("utf-8")
                sub = working[-cutoff:]
                if sub[0] >= 0xC0:
                    trimmed_utf8_len = cutoff
                    body_bytes = working[:-cutoff]
                    break
            except UnicodeDecodeError:
                continue

        try:
            body_text = body_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            # Fatal unrecoverable decoding error
            val_res = validate_xml(raw_bytes)
            return ReconstructionResult(
                format="xml",
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
                        "type": "CORRUPTED_ENCODING",
                        "description": f"Unrepairable UTF-8 corruption: {exc}",
                    }
                ],
                reconstruction_methods=[],
                validation_result=val_res,
                is_exact_match=False,
                details={"error": f"Invalid UTF-8 encoding in XML: {exc}"},
            )

    # Tokenize and parse element stack
    tag_stack: List[str] = []
    matched_pos = 0
    root_tag_found = False
    has_structural_error = False

    for m in _TOKEN_PATTERN.finditer(body_text):
        if m.start() != matched_pos:
            # Non-whitespace gap or malformed token
            break

        if m.group("open"):
            tag_name = m.group("opentag")
            tag_stack.append(tag_name)
            root_tag_found = True
        elif m.group("empty"):
            root_tag_found = True
        elif m.group("close"):
            tag_name = m.group("closetag")
            if tag_stack and tag_stack[-1] == tag_name:
                tag_stack.pop()
            else:
                # Mismatched closing tag — structural corruption
                has_structural_error = True
                break

        matched_pos = m.end()

    # If document has structural corruption (e.g. mismatched tags) or no root tag was opened
    if has_structural_error or not root_tag_found:
        val_res = validate_xml(raw_bytes)
        return ReconstructionResult(
            format="xml",
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
                    "type": "MALFORMED_XML",
                    "description": "Evidence contains mismatched tags or no valid XML elements",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False,
            details={"error": "Malformed XML structure"},
        )

    # Check if anything needs closing
    verified_body_text = body_text[:matched_pos]
    verified_body_bytes = verified_body_text.encode("utf-8")

    # If the stack has open elements, synthesize deterministic closing tags in reverse order
    if tag_stack:
        if detection_mode == "blind":
            val_res = validate_xml(raw_bytes)
            return ReconstructionResult(
                format="xml",
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
                        "type": "UNCLOSED_TAGS_IN_BLIND_CARVE",
                        "description": "Unclosed XML tags cannot be deterministically synthesized in blind carving mode",
                    }
                ],
                reconstruction_methods=[],
                validation_result=val_res,
                is_exact_match=False,
                details={"error": "Unclosed tags in blind carving mode"},
            )
        closing_tags = "".join(f"</{tag}>" for tag in reversed(tag_stack))
        closing_bytes = closing_tags.encode("utf-8")
        recon_methods = ["DETERMINISTIC_TAG_CLOSURE"]
    else:
        closing_bytes = b""
        recon_methods = []

    # Assemble reconstructed bytes
    reconstructed_payload = verified_body_bytes + closing_bytes
    if marker_start_bytes:
        reconstructed_full = marker_start_bytes + reconstructed_payload + (marker_end_bytes or SYNTHETIC_END_MARKER)
    else:
        reconstructed_full = reconstructed_payload

    # Validate reconstructed artifact
    val_reconstructed = validate_xml(reconstructed_full)
    if not val_reconstructed.valid:
        # Failed to form a valid XML document
        return ReconstructionResult(
            format="xml",
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
                    "type": "UNRECOVERABLE_XML",
                    "description": "Reconstructed XML failed structural validation",
                }
            ],
            reconstruction_methods=[],
            validation_result=val_reconstructed,
            is_exact_match=False,
            details={"errors": val_reconstructed.errors},
        )

    # Forensic accounting
    verified_len = len(marker_start_bytes) + len(verified_body_bytes) + len(marker_end_bytes)
    reconstructed_len = len(closing_bytes) + (len(SYNTHETIC_END_MARKER) if (marker_start_bytes and not marker_end_bytes) else 0)
    missing_len = max(0, total_input_bytes - verified_len)

    damage_regions = []
    if missing_len > 0:
        damage_regions.append({
            "offset": verified_len,
            "length": missing_len,
            "type": "TRUNCATED_TAIL",
            "description": f"Dropped {missing_len} incomplete trailing bytes at offset {verified_len}",
        })

    is_exact = None
    if original_data is not None:
        is_exact = hashlib.sha256(reconstructed_full).digest() == hashlib.sha256(original_data).digest()

    status_str = (
        "FULLY_RECOVERED"
        if (reconstructed_len == 0 and missing_len == 0 and val_reconstructed.valid)
        else "PARTIALLY_RECOVERED"
    )

    return ReconstructionResult(
        format="xml",
        status=status_str,
        success=True,
        recovered_bytes=reconstructed_full,
        verified_bytes=verified_len,
        reconstructed_bytes=reconstructed_len,
        missing_bytes=missing_len,
        damage_regions=damage_regions,
        reconstruction_methods=recon_methods if recon_methods else ["NONE"],
        validation_result=val_reconstructed,
        is_exact_match=is_exact,
        details={
            "reconstructed_closing_tags": len(tag_stack),
            "root_tag": val_reconstructed.details.get("root_tag"),
        },
    )
