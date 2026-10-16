"""
pdf.py — Deterministic PDF artifact structural validator and xref rebuilder.

Validates recovered PDF artifact bytes against PDF structural specifications:
  - Header magic signature: %PDF-
  - Footer trailer signature: %%EOF
  - Indirect object syntax: \\d+ \\d+ obj ... endobj
  - Stream boundary pairs: stream ... endstream
  - Cross-reference table (xref) or XRef stream
  - Trailer dictionary and startxref offset pointer
  - Indirect object references: \\d+ \\d+ R
"""

from __future__ import annotations

import re
from typing import Union, Any, Dict, List, Tuple

from backend.app.models.validation import ValidationResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import (
    PDF_HEADER_SIGNATURE,
    PDF_TRAILER_SIGNATURE,
)


def _clean_dictionary_bytes(obj_slice: bytes) -> bytes:
    """Extract and sanitize structural dictionary bytes from an indirect object or trailer.

    - Truncates at the 'stream' keyword so payload bytes are never mistaken for dictionary keys.
    - Strips comments (% to newline).
    - Replaces literal strings (...) and hex strings <...> with whitespace, preserving
      dictionary delimiters (<< and >>).
    """
    # 1. Truncate at stream keyword if present
    stream_match = re.search(rb"\bstream\r?\n", obj_slice)
    dict_slice = obj_slice[:stream_match.start()] if stream_match else obj_slice

    # 2. Strip comments: % to newline
    cleaned = re.sub(rb"%[^\r\n]*", b" ", dict_slice)

    # 3. Strip literal strings (...) and hex strings <...>
    n = len(cleaned)
    out = bytearray()
    i = 0
    while i < n:
        # Preserve dictionary delimiters << and >>
        if cleaned[i:i + 2] in (b"<<", b">>"):
            out.extend(cleaned[i:i + 2])
            i += 2
            continue
        # Literal string: (...)
        if cleaned[i:i + 1] == b"(":
            out.append(32)
            paren_depth = 1
            i += 1
            while i < n and paren_depth > 0:
                cb = cleaned[i:i + 1]
                if cb == b"\\":
                    i += 2
                    continue
                elif cb == b"(":
                    paren_depth += 1
                elif cb == b")":
                    paren_depth -= 1
                i += 1
            continue
        # Hex string: <...>
        if cleaned[i:i + 1] == b"<":
            out.append(32)
            i += 1
            while i < n and cleaned[i:i + 1] != b">":
                i += 1
            if i < n and cleaned[i:i + 1] == b">":
                i += 1
            continue
        else:
            out.append(cleaned[i])
            i += 1
    return bytes(out)


def validate_pdf(data: bytes | RecoveredArtifact) -> ValidationResult:
    """Validate the structural integrity of a recovered PDF artifact.

    Accepts raw bytes or a RecoveredArtifact object.

    Checks performed:
      1. input_type: input is bytes (or RecoveredArtifact yielding bytes)
      2. non_empty: input is non-empty
      3. pdf_header_exists: %PDF- signature exists
      4. pdf_footer_exists: %%EOF signature exists
      5. marker_ordering: %PDF- occurs before %%EOF
      6. object_structure: indirect objects (obj ... endobj) are properly formed
      7. stream_structure: stream ... endstream boundaries are balanced
      8. xref_structure: xref table or /XRef stream is valid
      9. trailer_structure: trailer dictionary and startxref are present and consistent

    Args:
        data: Raw evidence bytes or RecoveredArtifact.

    Returns:
        ValidationResult with validation outcome, checks, errors, and details.
    """
    checks: list[str] = [
        "input_type",
        "non_empty",
        "pdf_header_exists",
        "pdf_footer_exists",
    ]
    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}

    # Extract raw bytes and format
    raw_bytes: bytes
    fmt: str = "pdf"
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

    details["byte_count"] = len(raw_bytes)

    # 2. Header check (%PDF-)
    start_pos = raw_bytes.find(PDF_HEADER_SIGNATURE)
    if start_pos == -1:
        errors.append(f"Missing PDF header signature: {PDF_HEADER_SIGNATURE.decode('ascii')}")
    else:
        # Extract version if available (e.g. %PDF-1.4, %PDF-1.7)
        version_line = raw_bytes[start_pos:start_pos + 15].splitlines()[0] if start_pos + 15 <= len(raw_bytes) else raw_bytes[start_pos:]
        try:
            details["pdf_version"] = version_line.decode("ascii", errors="ignore")
        except Exception:
            details["pdf_version"] = "%PDF-1.4"

    # 3. Footer check (%%EOF)
    end_pos = raw_bytes.rfind(PDF_TRAILER_SIGNATURE)
    if end_pos == -1:
        errors.append(f"Missing PDF trailer signature: {PDF_TRAILER_SIGNATURE.decode('ascii')}")
    else:
        details["end_offset"] = end_pos + len(PDF_TRAILER_SIGNATURE)

    # 4. Marker ordering check
    if start_pos != -1 and end_pos != -1:
        checks.append("marker_ordering")
        if start_pos >= end_pos:
            errors.append(
                f"Invalid marker ordering: PDF header at offset {start_pos} "
                f"occurs at or after trailer %%EOF at offset {end_pos}"
            )

    # 5. Object & Stream structure check
    if len(raw_bytes) > 0:
        checks.extend(["object_structure", "stream_structure"])

        # Count obj ... endobj occurrences
        obj_starts = list(re.finditer(rb"\b(\d+)\s+(\d+)\s+obj\b", raw_bytes))
        obj_ends = list(re.finditer(rb"\bendobj\b", raw_bytes))

        details["object_count"] = len(obj_starts)
        details["endobj_count"] = len(obj_ends)

        if len(obj_starts) == 0:
            errors.append("No valid indirect objects (obj ... endobj) found in PDF structure")
        elif len(obj_starts) != len(obj_ends):
            errors.append(
                f"Malformed object boundaries: {len(obj_starts)} 'obj' declarations but {len(obj_ends)} 'endobj' markers"
            )

        # Count stream ... endstream occurrences
        stream_starts = list(re.finditer(rb"\bstream\r?\n", raw_bytes))
        stream_ends = list(re.finditer(rb"\bendstream\b", raw_bytes))

        details["stream_count"] = len(stream_starts)
        if len(stream_starts) != len(stream_ends):
            errors.append(
                f"Damaged stream boundaries: {len(stream_starts)} 'stream' markers but {len(stream_ends)} 'endstream' markers"
            )

    # 6. Xref & Trailer structure check
    if len(raw_bytes) > 0:
        checks.extend(["xref_structure", "trailer_structure"])

        has_xref_table = b"xref" in raw_bytes
        has_xref_stream = b"/Type /XRef" in raw_bytes or b"/Type/XRef" in raw_bytes
        has_trailer = b"trailer" in raw_bytes
        has_startxref = b"startxref" in raw_bytes

        details["has_xref_table"] = has_xref_table
        details["has_xref_stream"] = has_xref_stream
        details["has_trailer"] = has_trailer
        details["has_startxref"] = has_startxref

        if not (has_xref_table or has_xref_stream):
            errors.append("Missing cross-reference table (xref) or XRef stream")

        if not (has_trailer or has_xref_stream):
            errors.append("Missing trailer dictionary")

        if not has_startxref:
            errors.append("Missing startxref pointer before %%EOF")

        # Verify startxref offset target if present
        if has_startxref and end_pos != -1:
            startxref_match = re.search(rb"startxref\s+(\d+)\s+%%EOF", raw_bytes[max(0, end_pos - 100):end_pos + 20])
            if startxref_match:
                reported_offset = int(startxref_match.group(1))
                details["reported_startxref"] = reported_offset
                if reported_offset >= len(raw_bytes):
                    errors.append(f"Invalid startxref pointer {reported_offset}: exceeds file byte size {len(raw_bytes)}")
                else:
                    target_slice = raw_bytes[reported_offset:reported_offset + 10]
                    if not (target_slice.startswith(b"xref") or b"obj" in target_slice or b"/XRef" in target_slice):
                        warnings.append(f"startxref pointer {reported_offset} does not point directly to 'xref' or XRef object")

    # 7. Object-tree and internal reference integrity check
    if len(raw_bytes) > 0 and len(obj_starts) > 0:
        checks.append("object_tree_integrity")
        defined_objects: set[int] = set()
        for m in obj_starts:
            try:
                defined_objects.add(int(m.group(1)))
            except ValueError:
                pass
        details["defined_object_ids"] = sorted(list(defined_objects))

        missing_refs: list[str] = []

        # 7a. Trailer /Root reference
        trailer_idx = raw_bytes.rfind(b"trailer")
        trailer_search_slice = raw_bytes[trailer_idx:] if trailer_idx != -1 else raw_bytes
        cleaned_trailer = _clean_dictionary_bytes(trailer_search_slice)
        root_match = re.search(rb"/Root\s+(\d+)\s+(\d+)\s+R\b", cleaned_trailer)
        if root_match:
            root_id = int(root_match.group(1))
            details["root_object_id"] = root_id
            if root_id not in defined_objects:
                missing_refs.append(f"trailer /Root references non-existent object {root_id}")

        # 7b. Object-tree traversal for Catalog, Pages, and Page references
        for i, m in enumerate(obj_starts):
            obj_num = int(m.group(1))
            start_off = m.start()
            next_start = obj_starts[i + 1].start() if i + 1 < len(obj_starts) else len(raw_bytes)
            obj_slice = raw_bytes[start_off:next_start]

            endobj_match = re.search(rb"\bendobj\b", obj_slice)
            if endobj_match:
                obj_slice = obj_slice[:endobj_match.end()]

            cleaned_obj = _clean_dictionary_bytes(obj_slice)

            # Catalog dictionary (/Type /Catalog)
            if is_catalog_dictionary(obj_slice):
                pages_match = re.search(rb"/Pages\s+(\d+)\s+(\d+)\s+R\b", cleaned_obj)
                if pages_match:
                    pages_id = int(pages_match.group(1))
                    details["catalog_pages_id"] = pages_id
                    if pages_id not in defined_objects:
                        missing_refs.append(
                            f"Catalog object {obj_num} references non-existent /Pages object {pages_id}"
                        )
                else:
                    missing_refs.append(f"Catalog object {obj_num} missing required /Pages reference")

            # Page tree node (/Type /Pages)
            if re.search(rb"/Type\s*/Pages\b", cleaned_obj):
                kids_match = re.search(rb"/Kids\s*\[([^\]]*)\]", cleaned_obj)
                if kids_match:
                    kids_slice = kids_match.group(1)
                    for km in re.finditer(rb"(\d+)\s+(\d+)\s+R\b", kids_slice):
                        kid_id = int(km.group(1))
                        if kid_id not in defined_objects:
                            missing_refs.append(
                                f"Pages object {obj_num} references non-existent /Kids child object {kid_id}"
                            )

            # Page node (/Type /Page)
            if re.search(rb"/Type\s*/Page\b", cleaned_obj):
                parent_match = re.search(rb"/Parent\s+(\d+)\s+(\d+)\s+R\b", cleaned_obj)
                if parent_match:
                    p_id = int(parent_match.group(1))
                    if p_id not in defined_objects:
                        missing_refs.append(
                            f"Page object {obj_num} references non-existent /Parent object {p_id}"
                        )
                contents_match = re.search(rb"/Contents\s+(\d+)\s+(\d+)\s+R\b", cleaned_obj)
                if contents_match:
                    c_id = int(contents_match.group(1))
                    if c_id not in defined_objects:
                        missing_refs.append(
                            f"Page object {obj_num} references non-existent /Contents stream object {c_id}"
                        )
                contents_arr_match = re.search(rb"/Contents\s*\[([^\]]*)\]", cleaned_obj)
                if contents_arr_match:
                    for cm in re.finditer(rb"(\d+)\s+(\d+)\s+R\b", contents_arr_match.group(1)):
                        c_id = int(cm.group(1))
                        if c_id not in defined_objects:
                            missing_refs.append(
                                f"Page object {obj_num} references non-existent /Contents stream object {c_id}"
                            )

        if missing_refs:
            errors.append(f"Damaged PDF object tree: {'; '.join(missing_refs)}")

    valid = len(errors) == 0
    return ValidationResult(
        valid=valid,
        format=fmt,
        checks_performed=checks,
        errors=errors,
        warnings=warnings,
        details=details,
    )


def is_catalog_dictionary(obj_bytes: bytes) -> bool:
    """Determine whether obj_bytes contains a top-level Document Catalog dictionary.

    Uses a bounded lexical scanner that distinguishes structural dictionary
    entries from occurrences inside literal strings (with escaped parens),
    comments, hex strings, arrays, sub-dictionaries, and stream payloads.
    """
    n = len(obj_bytes)
    i = 0
    dict_depth = 0
    array_depth = 0

    while i < n:
        b = obj_bytes[i:i + 1]

        # Stop if we hit stream or endobj keywords outside of strings/comments
        if obj_bytes.startswith(b"stream", i):
            after_stream = i + 6
            if after_stream >= n or obj_bytes[after_stream:after_stream + 1] in b" \t\r\n\x00\x0c":
                break
        if obj_bytes.startswith(b"endobj", i):
            after_endobj = i + 6
            if after_endobj >= n or obj_bytes[after_endobj:after_endobj + 1] in b" \t\r\n\x00\x0c()<>[]{}/%":
                break

        # 1. Skip comments: % to end of line (\r or \n)
        if b == b"%":
            i += 1
            while i < n and obj_bytes[i:i + 1] not in b"\r\n":
                i += 1
            continue

        # 2. Skip literal strings: (...) handling nested () and escapes \( \)
        if b == b"(":
            i += 1
            paren_depth = 1
            while i < n and paren_depth > 0:
                cb = obj_bytes[i:i + 1]
                if cb == b"\\":
                    i += 2
                    continue
                elif cb == b"(":
                    paren_depth += 1
                elif cb == b")":
                    paren_depth -= 1
                i += 1
            continue

        # 3. Dictionary start << or hex string <
        if b == b"<":
            if i + 1 < n and obj_bytes[i + 1:i + 2] == b"<":
                dict_depth += 1
                i += 2
                continue
            else:
                # Hex string: skip until >
                i += 1
                while i < n and obj_bytes[i:i + 1] != b">":
                    i += 1
                if i < n and obj_bytes[i:i + 1] == b">":
                    i += 1
                continue

        # 4. Dictionary end >> or stray >
        if b == b">":
            if i + 1 < n and obj_bytes[i + 1:i + 2] == b">":
                if dict_depth > 0:
                    dict_depth -= 1
                    if dict_depth == 0:
                        break
                i += 2
                continue
            else:
                i += 1
                continue

        # 5. Array delimiters [ and ]
        if b == b"[":
            array_depth += 1
            i += 1
            continue
        if b == b"]":
            if array_depth > 0:
                array_depth -= 1
            i += 1
            continue

        # 6. Name token starting with /
        if b == b"/":
            start_name = i
            i += 1
            while i < n and obj_bytes[i:i + 1] not in b" \t\r\n\x00\x0c()<>[]{}/%":
                i += 1
            name = obj_bytes[start_name:i]

            # We only care about /Type at top-level dictionary
            if dict_depth == 1 and array_depth == 0 and name == b"/Type":
                # Scan next token, skipping whitespace and comments
                while i < n:
                    if obj_bytes[i:i + 1] in b" \t\r\n\x00\x0c":
                        i += 1
                    elif obj_bytes[i:i + 1] == b"%":
                        while i < n and obj_bytes[i:i + 1] not in b"\r\n":
                            i += 1
                    else:
                        break

                if i < n and obj_bytes[i:i + 1] == b"/":
                    val_start = i
                    i += 1
                    while i < n and obj_bytes[i:i + 1] not in b" \t\r\n\x00\x0c()<>[]{}/%":
                        i += 1
                    val_name = obj_bytes[val_start:i]
                    if val_name == b"/Catalog":
                        return True
            continue

        i += 1

    return False


class PDFReconstructResult(Tuple[bytes, bool]):
    """Tuple subclass for PDF reconstruction: (rebuilt_bytes, success_flag) with clean_base_len."""

    rebuilt_bytes: bytes
    success: bool
    clean_base_len: int

    def __new__(cls, rebuilt_bytes: bytes, success: bool, clean_base_len: int = 0):
        obj = super().__new__(cls, (rebuilt_bytes, success))
        obj.rebuilt_bytes = rebuilt_bytes
        obj.success = success
        obj.clean_base_len = clean_base_len
        return obj


def reconstruct_pdf_xref(pdf_bytes: bytes) -> PDFReconstructResult:
    """Deterministically rebuild xref table and startxref for damaged PDF bytes.

    Scans existing indirect objects in pdf_bytes, parses object numbers and byte offsets,
    and appends a clean xref table + trailer dictionary + startxref + %%EOF.

    Does NOT invent objects or modify existing object bytes.

    Returns:
        PDFReconstructResult (tuple of reconstructed_pdf_bytes, success_flag) with clean_base_len.
    """
    if not pdf_bytes.startswith(PDF_HEADER_SIGNATURE):
        return PDFReconstructResult(pdf_bytes, False, clean_base_len=0)

    # Find all obj matches: (num, gen, offset)
    obj_matches = list(re.finditer(rb"(\d+)\s+(\d+)\s+obj\b", pdf_bytes))
    if not obj_matches:
        return PDFReconstructResult(pdf_bytes, False, clean_base_len=0)

    # Build map of object_number -> byte_offset
    objects_map: Dict[int, int] = {}
    max_obj_num = 0

    for match in obj_matches:
        obj_num = int(match.group(1))
        offset = match.start()
        objects_map[obj_num] = offset
        if obj_num > max_obj_num:
            max_obj_num = obj_num

    if not objects_map:
        return PDFReconstructResult(pdf_bytes, False, clean_base_len=0)

    # Find existing catalog / Root object reference in trailer if possible
    root_ref_match = None
    trailer_idx = pdf_bytes.rfind(b"trailer")
    if trailer_idx != -1:
        root_ref_match = re.search(rb"/Root\s+(\d+)\s+(\d+)\s+R\b", pdf_bytes[trailer_idx:])

    if root_ref_match and int(root_ref_match.group(1)) in objects_map:
        root_num = int(root_ref_match.group(1))
    else:
        # Search objects for structural Document Catalog dictionary
        root_num = None
        for i, match in enumerate(obj_matches):
            obj_num = int(match.group(1))
            start_off = match.start()
            next_start = obj_matches[i + 1].start() if i + 1 < len(obj_matches) else len(pdf_bytes)
            obj_slice = pdf_bytes[start_off:next_start]

            endobj_match = re.search(rb"\bendobj\b", obj_slice)
            if endobj_match:
                obj_slice = obj_slice[:endobj_match.end()]

            if is_catalog_dictionary(obj_slice):
                root_num = obj_num
                break

        if root_num is None:
            # Conservative failure: no valid trailer /Root exists and no Catalog can be structurally identified
            return PDFReconstructResult(pdf_bytes, False, clean_base_len=0)

    # Truncate any damaged old xref / trailer if present
    clean_base = pdf_bytes
    xref_idx = clean_base.rfind(b"\nxref")
    if xref_idx != -1 and xref_idx > len(PDF_HEADER_SIGNATURE):
        surviving_len = xref_idx
        clean_base = clean_base[:xref_idx]
    else:
        clean_base_stripped = clean_base.rstrip(b"\r\n\t ")
        if pdf_bytes[len(clean_base_stripped):len(clean_base_stripped)+1] == b"\n":
            surviving_len = len(clean_base_stripped) + 1
        else:
            surviving_len = len(clean_base_stripped)

    clean_base = clean_base.rstrip(b"\r\n\t ")
    clean_base_len = surviving_len

    xref_start_offset = len(clean_base) + 1  # 1 for leading newline

    # Build classic xref section
    xref_lines: List[str] = [
        "",
        "xref",
        f"0 {max_obj_num + 1}",
        "0000000000 65535 f ",
    ]

    for i in range(1, max_obj_num + 1):
        if i in objects_map:
            off = objects_map[i]
            xref_lines.append(f"{off:010d} 00000 n ")
        else:
            xref_lines.append("0000000000 00000 f ")

    xref_bytes = "\n".join(xref_lines).encode("ascii")

    trailer_text = (
        f"\ntrailer\n"
        f"<< /Size {max_obj_num + 1} /Root {root_num} 0 R >>\n"
        f"startxref\n"
        f"{xref_start_offset}\n"
        f"%%EOF\n"
    )

    reconstructed = clean_base + xref_bytes + trailer_text.encode("ascii")
    return PDFReconstructResult(reconstructed, True, clean_base_len=clean_base_len)
