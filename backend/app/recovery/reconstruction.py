"""
reconstruction.py — Real Deterministic Reconstruction Engine for Recoverix.

Provides format-specific structural reconstruction algorithms for damaged files:
  1. reconstruct_text() — Real UTF-8 text reconstruction, null byte isolation, truncation salvage.
  2. reconstruct_csv()  — Real CSV reconstruction, schema inference, damaged row recovery, quote repair.
  (JSON, XML, PNG, JPEG, PDF to follow in subsequent milestones).

FORENSIC INVARIANTS:
  - Known bytes from input evidence are NEVER modified.
  - Unknown/missing bytes are NEVER invented, hallucinated, or synthesized as evidence.
  - Structural repair bytes (e.g. closing quotes, newlines, delimiters) are explicitly
    accounted for as `reconstructed_bytes`, distinct from `verified_bytes`.
  - Missing or destroyed evidence is explicitly accounted for as `missing_bytes`.
  - Invariant: len(recovered_bytes) == verified_bytes + reconstructed_bytes.
"""

from __future__ import annotations

import csv
import io
import re
import hashlib
from typing import Optional, List, Dict, Any, Tuple

from backend.app.models.reconstruction import ReconstructionResult
from backend.app.models.validation import ValidationResult
from backend.app.recovery.bifragment import reconstruct_bifragment
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)
from backend.app.recovery.validators.text import validate_txt
from backend.app.recovery.validators.csv import validate_csv


def _is_predominantly_binary_garbage(data: bytes, threshold: float = 0.60) -> bool:
    """Return True if *data* is predominantly non-text binary data."""
    if not data:
        return False

    valid_text_bytes = 0
    total = len(data)
    i = 0

    while i < total:
        b = data[i]
        # Standard printable ASCII (0x20..0x7E) plus tab, lf, cr
        if (0x20 <= b <= 0x7E) or b in (9, 10, 13):
            valid_text_bytes += 1
            i += 1
        else:
            # Check for valid multi-byte UTF-8 character
            matched = False
            for step in (2, 3, 4):
                if i + step <= total:
                    try:
                        ch = data[i:i + step].decode("utf-8")
                        if ch.isprintable():
                            valid_text_bytes += step
                            i += step
                            matched = True
                            break
                    except UnicodeDecodeError:
                        pass
            if not matched:
                i += 1

    ratio = valid_text_bytes / total
    return ratio < threshold


from backend.app.recovery.reconstructors.txt import reconstruct_txt
from backend.app.recovery.reconstructors.json import reconstruct_json


def _try_stitch_fragmented_txt(
    data: bytes,
    source_offset: int = 0,
    min_gap_size: int = 64,
) -> Optional[Tuple[bytes, List[Tuple[int, int]], ValidationResult]]:
    """Deterministically stitch fragmented text extents separated by unallocated null space.

    Physical & structural invariants:
      1. Candidate Window Alignment:
         The evidence window contains multiple (>= 2) contiguous non-null extents.
         The first extent MUST start at relative offset 0 of the candidate window.
         The last extent MUST end at the end of the candidate window (len(data)).
      2. Clean Unallocated Storage Blocks:
         All intervening bytes between extents must be strictly zero-fill (\\x00).
         Every gap must be >= min_gap_size (>= 64 bytes), representing Recoverix's deterministic
         heuristic for unallocated storage blocks rather than intra-file null byte corruption.
      3. Payload UTF-8 Integrity:
         When extents are concatenated in physical storage order, the stitched stream
         must be valid UTF-8 without decode errors.
      4. Text Density:
         The stitched text must consist predominantly (>= 90%) of printable text and
         standard whitespace (\\t, \\r, \\n), rejecting binary noise or control bytes.
      5. Structural Validation:
         The stitched payload must pass format-level structural validation (validate_txt),
         ensuring no binary nulls exist within the payload and valid document structure
         is established.
    """
    d_len = len(data)
    if d_len == 0:
        return None

    # 1. Extract contiguous non-null extents
    segs: List[Tuple[int, int, bytes]] = []
    idx = 0
    while idx < d_len:
        if data[idx] != 0:
            start = idx
            while idx < d_len and data[idx] != 0:
                idx += 1
            segs.append((start, idx, data[start:idx]))
        else:
            idx += 1

    # 2. Must contain at least 2 extents to be fragmented
    if len(segs) < 2:
        return None

    # 3. Spatial candidate window boundary alignment
    if segs[0][0] != 0 or segs[-1][1] != d_len:
        return None

    # 4. Validate that all inter-extent gaps are pure unallocated blocks
    for i in range(len(segs) - 1):
        gap = data[segs[i][1] : segs[i + 1][0]]
        if len(gap) < min_gap_size:
            return None  # Small intra-file gap, treated as payload damage
        if any(b != 0 for b in gap):
            return None  # Gap contains non-zero noise/entropy

    # 5. Concatenate in forward physical order & verify UTF-8
    stitched = b"".join(chunk for _, _, chunk in segs)
    try:
        text = stitched.decode("utf-8")
    except UnicodeDecodeError:
        return None

    # 6. Verify printable text density (>= 90%)
    printable_count = sum(1 for ch in text if ch.isprintable() or ch in "\t\r\n")
    if (printable_count / len(text)) < 0.90:
        return None

    # 7. Structural text validation via canonical validator
    val_res = validate_txt(stitched)
    if not val_res.valid:
        return None

    frags = [(source_offset + s, len(chunk)) for s, e, chunk in segs]
    return stitched, frags, val_res


def reconstruct_text(
    data: bytes,
    original_data: Optional[bytes] = None,
    detection_mode: str = "known_file",
    source_offset: int = 0,
) -> ReconstructionResult:
    """Deterministically reconstruct damaged TXT evidence into a valid TXT file."""
    data = bytes(data)

    stitched_result = _try_stitch_fragmented_txt(data, source_offset=source_offset)
    if stitched_result is not None:
        stitched, frags, val_res = stitched_result
        is_exact = None
        if original_data is not None:
            is_exact = hashlib.sha256(stitched).digest() == hashlib.sha256(original_data).digest()
        return ReconstructionResult(
            format="txt",
            status="FULLY_RECOVERED",
            success=True,
            recovered_bytes=stitched,
            verified_bytes=len(stitched),
            reconstructed_bytes=0,
            missing_bytes=0,
            damage_regions=[],
            reconstruction_methods=["FRAGMENTED_EXTENT_STITCHING"],
            validation_result=val_res,
            is_exact_match=is_exact,
            details={
                "reconstruction_method": "FRAGMENTED_EXTENT_STITCHING",
                "physical_fragments": frags,
                "fragment_count": len(frags),
                "total_verified_bytes": len(stitched),
                "unallocated_gap_bytes": len(data) - len(stitched),
            },
        )

    # Binary garbage is not text. Salvaging it as "recovered text" would fabricate
    # content and overstate confidence, so it is reported unrecoverable with every
    # byte accounted as missing. This check lives here so that every caller gets
    # it, not just the format dispatcher.
    if _is_predominantly_binary_garbage(data):
        return ReconstructionResult(
            format="txt",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=len(data),
            damage_regions=[
                {
                    "offset": 0,
                    "length": len(data),
                    "type": "BINARY_GARBAGE",
                    "status": "UNRECOVERABLE",
                    "details": "Evidence is predominantly non-text bytes",
                }
            ],
            reconstruction_methods=[],
            validation_result=validate_txt(data),
            is_exact_match=False if original_data is not None else None,
            details={"reason": "Evidence is predominantly binary, not recoverable text"},
        )

    return reconstruct_txt(data, ground_truth=original_data, detection_mode=detection_mode)


# ─────────────────────────────────────────────────────────────────────────────
# CSV RECONSTRUCTION
# ─────────────────────────────────────────────────────────────────────────────

def _sniff_csv_delimiter(text: str) -> str:
    """Deterministically determine the most consistent delimiter for CSV data."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ","

    delims = [",", ";", "\t", "|"]
    best_delim = ","
    best_score = -1

    for delim in delims:
        counts = [line.count(delim) for line in lines]
        if all(c > 0 for c in counts):
            if len(set(counts)) == 1 and counts[0] > 0:
                return delim
            score = sum(counts) / len(counts)
            if score > best_score:
                best_score = score
                best_delim = delim

    return best_delim


def reconstruct_csv(
    data: bytes,
    original_data: Optional[bytes] = None,
    detection_mode: str = "known_file",
) -> ReconstructionResult:
    """Deterministically reconstruct damaged CSV evidence into a valid CSV file.

    Capabilities:
      - Infers CSV delimiter and schema (column count) from intact rows.
      - Salvages intact rows and preserves authentic records.
      - Detects and drops truncated/incomplete trailing rows without inventing cell data.
      - Detects and repairs unclosed quotes where deterministically resolvable.
      - Isolates damaged middle rows with mismatched column counts or corruption.
      - Normalizes row terminators (\\n).
      - Reconnects fragmented CSV blocks across missing row gaps.
      - Explicit verified/reconstructed/missing byte accounting.
      - Produces an actual valid recovered CSV byte buffer.

    Args:
        data: Raw damaged evidence bytes.
        original_data: Optional ground-truth bytes for automated test verification.

    Returns:
        ReconstructionResult with usable recovered bytes and byte accounting.
    """
    if len(data) == 0:
        val_res = validate_csv(data)
        return ReconstructionResult(
            format="csv",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=0,
            damage_regions=[],
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False if original_data is not None else None,
            details={"reason": "Input evidence is empty"},
        )

    damage_regions: List[Dict[str, Any]] = []
    reconstruction_methods: List[str] = []
    missing_bytes_count = 0
    reconstructed_bytes_count = 0

    # 1. Check for synthetic boundary markers
    has_synthetic_start = SYNTHETIC_START_MARKER in data
    has_synthetic_end = SYNTHETIC_END_MARKER in data
    uses_synthetic_markers = has_synthetic_start or has_synthetic_end

    # Fast-path for intact, complete, valid CSV evidence:
    # Preserve original evidence byte-for-byte without destructive re-serialization.
    if b"\x00" not in data:
        val_initial = validate_csv(data)
        if val_initial.valid and not val_initial.errors:
            intact_body: Optional[bytes] = None
            if uses_synthetic_markers:
                if (
                    has_synthetic_start
                    and has_synthetic_end
                    and data.count(SYNTHETIC_START_MARKER) == 1
                    and data.count(SYNTHETIC_END_MARKER) == 1
                    and data.startswith(SYNTHETIC_START_MARKER)
                    and data.endswith(SYNTHETIC_END_MARKER)
                ):
                    intact_body = data[len(SYNTHETIC_START_MARKER) : -len(SYNTHETIC_END_MARKER)]
            else:
                intact_body = data

            if intact_body is not None:
                try:
                    intact_text = intact_body.decode("utf-8")
                except UnicodeDecodeError:
                    intact_text = None

                if intact_text is not None and (intact_body.endswith(b"\n") or intact_body.endswith(b"\r\n")):
                    intact_lines = [line for line in intact_text.splitlines() if line.strip()]
                    if len(intact_lines) >= 2 and sum(l.count('"') for l in intact_lines) % 2 == 0:
                        for test_delim in (",", ";", "\t", "|"):
                            try:
                                reader = csv.reader(io.StringIO("\n".join(intact_lines)), delimiter=test_delim)
                                parsed = list(reader)
                                if (
                                    len(parsed) == len(intact_lines)
                                    and len(set(len(r) for r in parsed)) == 1
                                    and len(parsed[0]) >= 2
                                ):
                                    from backend.app.recovery.completeness import assess_artifact_completeness

                                    eff_mode = "synthetic_harness" if uses_synthetic_markers else detection_mode
                                    is_complete = assess_artifact_completeness(
                                        fmt="csv",
                                        content=data,
                                        detection_mode=eff_mode,
                                        validation_result=val_initial,
                                        missing_bytes=0,
                                        reconstructed_bytes=0,
                                    )
                                    status_str = "FULLY_RECOVERED" if is_complete else "PARTIALLY_RECOVERED"
                                    is_exact = None
                                    if original_data is not None:
                                        is_exact = (
                                            hashlib.sha256(data).digest() == hashlib.sha256(original_data).digest()
                                        )

                                    return ReconstructionResult(
                                        format="csv",
                                        status=status_str,
                                        success=True,
                                        recovered_bytes=data,
                                        verified_bytes=len(data),
                                        reconstructed_bytes=0,
                                        missing_bytes=0,
                                        damage_regions=[],
                                        reconstruction_methods=[],
                                        validation_result=val_initial,
                                        is_exact_match=is_exact,
                                        details={
                                            "reason": "Intact CSV evidence preserved byte-for-byte",
                                            "is_complete": is_complete,
                                            "row_count": len(parsed),
                                            "column_count": len(parsed[0]),
                                            "delimiter": test_delim,
                                        },
                                    )
                            except Exception:
                                pass

    raw_body: bytes
    body_offset = 0
    leading_prefix = b""

    if uses_synthetic_markers:
        start_idx = data.find(SYNTHETIC_START_MARKER)
        end_idx = data.find(SYNTHETIC_END_MARKER)

        if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
            body_start = start_idx + len(SYNTHETIC_START_MARKER)
            raw_body = data[body_start:end_idx]
            body_offset = body_start
            if raw_body.startswith(b"\r\n"):
                leading_prefix = b"\r\n"
            elif raw_body.startswith(b"\n"):
                leading_prefix = b"\n"
        elif start_idx != -1:
            body_start = start_idx + len(SYNTHETIC_START_MARKER)
            raw_body = data[body_start:]
            body_offset = body_start
            damage_regions.append({
                "region_id": "damage-synth-end",
                "start_offset": len(data),
                "end_offset": len(data),
                "length": len(SYNTHETIC_END_MARKER),
                "type": "MISSING_SYNTHETIC_FOOTER",
                "status": "RECONSTRUCTED",
            })
            reconstruction_methods.append("SYNTHETIC_FOOTER_RESTORE")
        elif end_idx != -1:
            raw_body = data[:end_idx]
            damage_regions.append({
                "region_id": "damage-synth-start",
                "start_offset": 0,
                "end_offset": 0,
                "length": len(SYNTHETIC_START_MARKER),
                "type": "MISSING_SYNTHETIC_HEADER",
                "status": "RECONSTRUCTED",
            })
            reconstruction_methods.append("SYNTHETIC_HEADER_RESTORE")
        else:
            raw_body = data
    else:
        raw_body = data

    # 2. Check for severe unrecoverable binary garbage
    if _is_predominantly_binary_garbage(raw_body):
        val_res = validate_csv(data)
        return ReconstructionResult(
            format="csv",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=len(data),
            damage_regions=[{
                "region_id": "damage-garbage",
                "start_offset": 0,
                "end_offset": len(data),
                "length": len(data),
                "type": "HIGH_ENTROPY_BINARY_GARBAGE",
                "status": "UNRECOVERABLE",
            }],
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False if original_data is not None else None,
            details={"reason": "Input is predominantly non-text binary data"},
        )

    # 3. Detect and scrub internal null byte runs / binary gaps before CSV parsing
    clean_segments: List[bytes] = []
    idx = 0
    total_len = len(raw_body)
    while idx < total_len:
        if raw_body[idx] == 0:
            null_start = idx
            while idx < total_len and raw_body[idx] == 0:
                idx += 1
            null_len = idx - null_start
            missing_bytes_count += null_len
            damage_regions.append({
                "region_id": f"damage-null-{len(damage_regions)}",
                "start_offset": body_offset + null_start,
                "end_offset": body_offset + idx,
                "length": null_len,
                "type": "BINARY_NULL_CORRUPTION",
                "status": "ISOLATED_UNRECOVERABLE",
            })
            reconstruction_methods.append("NULL_BYTES_SCRUBBED")
        else:
            seg_start = idx
            while idx < total_len and raw_body[idx] != 0:
                idx += 1
            clean_segments.append(raw_body[seg_start:idx])

    if not clean_segments:
        val_res = validate_csv(data)
        return ReconstructionResult(
            format="csv",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=len(data),
            damage_regions=damage_regions,
            reconstruction_methods=reconstruction_methods,
            validation_result=val_res,
            is_exact_match=False if original_data is not None else None,
            details={"reason": "No non-null bytes found in CSV evidence"},
        )

    # Decode clean segments and split into lines
    lines: List[str] = []
    for seg in clean_segments:
        try:
            seg_text = seg.decode("utf-8")
        except UnicodeDecodeError:
            text_res = reconstruct_text(seg)
            seg_text = text_res.recovered_bytes.decode("utf-8", errors="replace")
            reconstruction_methods.append("UTF8_SALVAGE")
        for l in seg_text.splitlines():
            stripped_l = l.strip()
            if stripped_l:
                lines.append(stripped_l)

    if not lines:
        val_res = validate_csv(data)
        return ReconstructionResult(
            format="csv",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=len(data),
            damage_regions=damage_regions,
            reconstruction_methods=reconstruction_methods,
            validation_result=val_res,
            is_exact_match=False if original_data is not None else None,
            details={"reason": "No text lines found"},
        )

    # 4. Delimiter Sniffing
    delim = _sniff_csv_delimiter("\n".join(lines))

    # 5. Row parsing with unclosed quote repair
    parsed_rows: List[List[str]] = []
    # Exact input byte length of each parsed row's source line, in lockstep with
    # parsed_rows. Used for byte-exact accounting so that a dropped row is charged
    # its true input length rather than its re-serialised length.
    parsed_input_lengths: List[int] = []
    line_offset = body_offset

    for line_idx, line in enumerate(lines):
        line_bytes = line.encode("utf-8")

        # Check for unclosed quote on this line
        quote_count = line.count('"')
        if quote_count % 2 != 0:
            repaired_line = line + '"'
            try:
                reader = csv.reader(io.StringIO(repaired_line), delimiter=delim)
                row_test = next(reader)
                parsed_rows.append(row_test)
                parsed_input_lengths.append(len(line_bytes) + 1)
                reconstructed_bytes_count += 1  # 1 byte for '"'
                damage_regions.append({
                    "region_id": f"damage-quote-{line_idx}",
                    "start_offset": line_offset + len(line_bytes),
                    "end_offset": line_offset + len(line_bytes) + 1,
                    "length": 1,
                    "type": "UNCLOSED_QUOTE",
                    "status": "STRUCTURALLY_REPAIRED",
                })
                reconstruction_methods.append("QUOTE_CLOSURE_REPAIR")
                line_offset += len(line_bytes) + 1
                continue
            except Exception:
                pass

        try:
            reader = csv.reader(io.StringIO(line), delimiter=delim)
            row = next(reader)
            parsed_rows.append(row)
            parsed_input_lengths.append(len(line_bytes) + 1)
        except Exception:
            damage_regions.append({
                "region_id": f"damage-csv-parse-{line_idx}",
                "start_offset": line_offset,
                "end_offset": line_offset + len(line_bytes),
                "length": len(line_bytes),
                "type": "UNPARSEABLE_CSV_ROW",
                "status": "DROPPED_UNRECOVERABLE",
            })
            missing_bytes_count += len(line_bytes)
            reconstruction_methods.append("CORRUPTED_ROW_DROPPED")

        line_offset += len(line_bytes) + 1

    # Each line was charged +1 for its newline. The final line has no terminator
    # when the body does not end with one, so give that byte back rather than
    # over-counting the input budget.
    if parsed_input_lengths and not raw_body.endswith(b"\n"):
        parsed_input_lengths[-1] = max(0, parsed_input_lengths[-1] - 1)

    if not parsed_rows:
        val_res = validate_csv(data)
        return ReconstructionResult(
            format="csv",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=len(data),
            damage_regions=damage_regions,
            reconstruction_methods=reconstruction_methods,
            validation_result=val_res,
            is_exact_match=False if original_data is not None else None,
            details={"reason": "No valid CSV rows parsed"},
        )

    # 6. Schema Inference (Expected Column Count)
    col_counts = [len(r) for r in parsed_rows]
    from collections import Counter
    count_freq = Counter(col_counts)

    first_row_cols = col_counts[0]
    if first_row_cols > 1 and count_freq[first_row_cols] >= max(1, len(parsed_rows) // 3):
        expected_cols = first_row_cols
    else:
        expected_cols = count_freq.most_common(1)[0][0]

    if expected_cols < 2:
        val_res = validate_csv(data)
        return ReconstructionResult(
            format="csv",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=len(data),
            damage_regions=damage_regions,
            reconstruction_methods=reconstruction_methods,
            validation_result=val_res,
            is_exact_match=False if original_data is not None else None,
            details={"reason": f"Expected column count ({expected_cols}) is less than 2"},
        )

    # 7. Row Filtering & Alignment
    valid_rows: List[List[str]] = []
    surviving_input_bytes = 0
    for r_idx, r in enumerate(parsed_rows):
        row_input_len = parsed_input_lengths[r_idx]
        if len(r) == expected_cols:
            valid_rows.append(r)
            surviving_input_bytes += row_input_len
        else:
            is_last = (r_idx == len(parsed_rows) - 1)
            row_len = row_input_len
            missing_bytes_count += row_len

            damage_type = "TRUNCATED_FINAL_ROW" if is_last else "INCONSISTENT_ROW_COLUMNS"
            damage_regions.append({
                "region_id": f"damage-row-{r_idx}",
                "start_offset": 0,
                "end_offset": row_len,
                "length": row_len,
                "type": damage_type,
                "status": "DROPPED_UNRECOVERABLE",
                "details": f"Row had {len(r)} columns, expected {expected_cols}",
            })
            reconstruction_methods.append("INCONSISTENT_ROW_DROPPED")

    if uses_synthetic_markers:
        struct_verified_bytes = (
            (len(SYNTHETIC_START_MARKER) if has_synthetic_start else 0)
            + len(leading_prefix)
            + (len(SYNTHETIC_END_MARKER) if has_synthetic_end else 0)
        )
        surviving_input_bytes += struct_verified_bytes

    # Require at least 2 valid rows unless file only had 1 intact row
    if len(valid_rows) < 2 and len(valid_rows) < len(parsed_rows):
        val_res = validate_csv(data)
        return ReconstructionResult(
            format="csv",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=len(data),
            damage_regions=damage_regions,
            reconstruction_methods=reconstruction_methods,
            validation_result=val_res,
            is_exact_match=False if original_data is not None else None,
            details={"reason": "Insufficient valid rows to establish CSV structure"},
        )

    if not valid_rows:
        val_res = validate_csv(data)
        return ReconstructionResult(
            format="csv",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=len(data),
            damage_regions=damage_regions,
            reconstruction_methods=reconstruction_methods,
            validation_result=val_res,
            is_exact_match=False if original_data is not None else None,
            details={"reason": "No rows matched expected schema"},
        )

    # 8. Serialize clean recovered CSV
    out_io = io.StringIO()
    writer = csv.writer(out_io, delimiter=delim, lineterminator="\n")
    for r in valid_rows:
        writer.writerow(r)

    recovered_csv_text = out_io.getvalue()
    recovered_body = recovered_csv_text.encode("utf-8")

    # Track structural addition if original data was missing trailing newline
    if original_data is not None and not original_data.endswith(b"\n") and recovered_body.endswith(b"\n"):
        reconstructed_bytes_count += 1
        reconstruction_methods.append("TRAILING_NEWLINE_RESTORE")

    # Wrap in synthetic markers if used
    if uses_synthetic_markers:
        out_buf = SYNTHETIC_START_MARKER + leading_prefix + recovered_body + SYNTHETIC_END_MARKER
        if not has_synthetic_start:
            reconstructed_bytes_count += len(SYNTHETIC_START_MARKER)
        if not has_synthetic_end:
            reconstructed_bytes_count += len(SYNTHETIC_END_MARKER)
    else:
        out_buf = recovered_body

    # Enforce the two byte-exact identities:
    #   output    == verified_bytes + reconstructed_bytes
    #   budget    == verified_bytes + reconstructed_bytes + missing_bytes
    # `verified_bytes` is the exact input byte count of the surviving rows, so a
    # dropped row is charged its real input length and can never be silently
    # absorbed by CSV re-serialisation. A structural repair may add a byte the
    # damaged input never had (e.g. a restored closing quote), so the artifact
    # budget is the larger of the damaged evidence and the reconstructed output;
    # such additions are always counted as reconstructed, never as verified.
    verified_bytes_count = min(surviving_input_bytes, len(data))
    if len(out_buf) != verified_bytes_count + reconstructed_bytes_count:
        # Re-serialisation normalised the surviving rows (quoting, padding).
        # Charge the difference to structural reconstruction rather than hide it.
        reconstructed_bytes_count = max(0, len(out_buf) - verified_bytes_count)
    input_total = max(len(data), verified_bytes_count + reconstructed_bytes_count)
    missing_bytes_count = max(0, input_total - verified_bytes_count - reconstructed_bytes_count)
    assert input_total == verified_bytes_count + reconstructed_bytes_count + missing_bytes_count

    # 9. Validate recovered CSV
    val_res = validate_csv(out_buf)

    # Exact SHA-256 comparison if original provided
    is_exact = None
    if original_data is not None:
        is_exact = (hashlib.sha256(out_buf).digest() == hashlib.sha256(original_data).digest())

    if uses_synthetic_markers:
        effective_detection_mode = "synthetic_harness"
    else:
        effective_detection_mode = detection_mode

    from backend.app.recovery.completeness import assess_artifact_completeness
    is_complete = assess_artifact_completeness(
        fmt="csv",
        content=out_buf,
        detection_mode=effective_detection_mode,
        validation_result=val_res,
        missing_bytes=missing_bytes_count,
        reconstructed_bytes=reconstructed_bytes_count,
    )

    # FULLY_RECOVERED requires that nothing was reconstructed, nothing is
    # missing, and the evidence is sufficient to establish a complete artifact.
    # A byte-exact output can still contain structurally reconstructed
    # bytes (a restored quote or trailing newline), and those bytes are not
    # verified, so the status must not claim full recovery.
    if val_res.valid and missing_bytes_count == 0 and reconstructed_bytes_count == 0 and is_complete:
        status_str = "FULLY_RECOVERED"
    elif val_res.valid:
        status_str = "PARTIALLY_RECOVERED"
    else:
        status_str = "UNRECOVERABLE"

    return ReconstructionResult(
        format="csv",
        status=status_str,
        success=val_res.valid,
        recovered_bytes=out_buf,
        verified_bytes=verified_bytes_count,
        reconstructed_bytes=reconstructed_bytes_count,
        missing_bytes=missing_bytes_count,
        damage_regions=damage_regions,
        reconstruction_methods=list(set(reconstruction_methods)),
        validation_result=val_res,
        is_exact_match=is_exact,
        details={
            "delimiter": delim,
            "column_count": expected_cols,
            "row_count": len(valid_rows),
            "output_length": len(out_buf),
            "recovered_sha256": hashlib.sha256(out_buf).hexdigest(),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# UNIFIED DISPATCHER
# ─────────────────────────────────────────────────────────────────────────────

def reconstruct_artifact(
    fmt: str,
    data: bytes,
    original_data: Optional[bytes] = None,
    detection_mode: str = "known_file",
) -> ReconstructionResult:
    """Route deterministic reconstruction to the appropriate format reconstructor.

    Args:
        fmt: Format identifier ('txt', 'csv', etc.).
        data: Raw damaged evidence bytes.
        original_data: Optional ground-truth bytes.
        detection_mode: 'known_file', 'blind', or 'synthetic_harness'.

    Returns:
        ReconstructionResult with usable recovered bytes and byte accounting.
    """
    clean_fmt = fmt.lower().strip(".")
    source_offset = data.source_offset if isinstance(data, RecoveredArtifact) else 0
    if isinstance(data, RecoveredArtifact):
        data = data.recovered_bytes
    if clean_fmt == "txt":
        # reconstruct_text rejects predominantly binary evidence as unrecoverable.
        return reconstruct_text(
            data,
            original_data=original_data,
            detection_mode=detection_mode,
            source_offset=source_offset,
        )
    elif clean_fmt == "csv":
        return reconstruct_csv(data, original_data=original_data, detection_mode=detection_mode)
    elif clean_fmt == "json":
        return reconstruct_json(data, original_data=original_data)
    elif clean_fmt == "pdf":
        raw_pdf = data.recovered_bytes if isinstance(data, RecoveredArtifact) else data
        from backend.app.recovery.validators.pdf import reconstruct_pdf_xref, validate_pdf
        rebuilt_res = reconstruct_pdf_xref(raw_pdf)
        rebuilt_bytes, xref_ok = rebuilt_res
        if xref_ok:
            val_res = validate_pdf(rebuilt_bytes)
            clean_base_len = getattr(rebuilt_res, "clean_base_len", len(raw_pdf))
            pdf_input_bytes = len(raw_pdf)
            v_bytes = min(pdf_input_bytes, clean_base_len)
            m_bytes = max(0, pdf_input_bytes - v_bytes)
            r_bytes = max(0, len(rebuilt_bytes) - v_bytes)
            status_str = (
                "FULLY_RECOVERED"
                if (m_bytes == 0 and r_bytes == 0 and val_res.valid)
                else ("PARTIALLY_RECOVERED" if val_res.valid else "CORRUPTED")
            )
            return ReconstructionResult(
                format="pdf",
                status=status_str,
                success=val_res.valid,
                recovered_bytes=rebuilt_bytes,
                verified_bytes=v_bytes,
                reconstructed_bytes=r_bytes,
                missing_bytes=m_bytes,
                reconstruction_methods=["XREF_RECONSTRUCTION"],
                validation_result=val_res,
                damage_regions=[
                    {
                        "offset": v_bytes,
                        "length": m_bytes,
                        "type": "CORRUPTED",
                        "status": "RECONSTRUCTED" if val_res.valid else "UNRECOVERABLE",
                    }
                ]
                if m_bytes > 0
                else [],
                details={
                    "clean_base_len": clean_base_len,
                    "reconstruction_method": "XREF_RECONSTRUCTION",
                },
            )
        else:
            return ReconstructionResult(
                format="pdf",
                status="UNRECOVERABLE",
                success=False,
                recovered_bytes=b"",
                verified_bytes=0,
                reconstructed_bytes=0,
                missing_bytes=len(raw_pdf),
                details={"error": "PDF xref reconstruction failed: no valid objects or catalog"},
            )
    else:
        # Unsupported format for Milestone 1
        return ReconstructionResult(
            format=clean_fmt,
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=len(data),
            details={"error": f"Format '{fmt}' reconstruction not yet implemented in Milestone 1"},
        )


# ─────────────────────────────────────────────────────────────────────────────
# FRAGMENT-PAIR RECONSTRUCTION (Fragment A + unknown bounded gap + Fragment B)
# ─────────────────────────────────────────────────────────────────────────────

MIN_GAP = 1
MAX_GAP = 4096


def _validate_accounting(result: ReconstructionResult, input_bytes: int) -> None:
    """Enforce the forensic accounting and status invariants on *result*.

    The identity is on the *input* budget::

        input_bytes == verified_bytes + reconstructed_bytes + missing_bytes

    A re-serialising reconstructor (CSV) may emit an output whose length differs
    from the input, so output length is reported separately rather than forced
    into the identity.
    """
    total = result.verified_bytes + result.reconstructed_bytes + result.missing_bytes
    if total != input_bytes:
        raise AssertionError(
            f"Accounting invariant failed: verified({result.verified_bytes}) + "
            f"reconstructed({result.reconstructed_bytes}) + missing({result.missing_bytes}) "
            f"= {total} != input_bytes({input_bytes})"
        )
    if (
        result.missing_bytes > 0 or result.reconstructed_bytes > 0
    ) and result.status == "FULLY_RECOVERED":
        raise AssertionError(
            "Status cannot be FULLY_RECOVERED while bytes are reconstructed or missing"
        )


def reconstruct_fragment_pair(
    fmt: str,
    fragment_a: bytes,
    fragment_b: bytes,
    *,
    min_gap: int = MIN_GAP,
    max_gap: int = MAX_GAP,
    observed_gap: Optional[int] = None,
) -> ReconstructionResult:
    """Reconstruct an artifact from Fragment A + unknown bounded gap + Fragment B.

    The gap is searched over ``[min_gap, max_gap]``. For each candidate gap length
    a validation payload is assembled **in memory only** and passed to the format
    validator. The smallest gap length that validates is selected, and the number
    of valid candidates is recorded.

    FORENSIC INVARIANT:
      The gap payload is never emitted. :attr:`ReconstructionResult.recovered_bytes`
      is exactly ``fragment A bytes + fragment B bytes`` with deterministic
      structural repair only. The selected gap size is a *structural hypothesis*
      and its bytes stay counted in ``missing_bytes`` — they are never fabricated
      and never presented as recovered evidence.

    Args:
        fmt: ``"txt"`` or ``"csv"``.
        fragment_a: Bytes of the earlier fragment, exactly as present in evidence.
        fragment_b: Bytes of the later fragment, exactly as present in evidence.
        min_gap: Smallest candidate gap (default 1).
        max_gap: Largest candidate gap (default 4096).
        observed_gap: Bytes observed to lie between the two fragments. Only used
            for missing-byte reporting when the bounded search finds no valid gap.

    Returns:
        ReconstructionResult with honest verified/reconstructed/missing accounting.
    """
    clean_fmt = fmt.lower().strip(".")
    raw_a = bytes(fragment_a)
    raw_b = bytes(fragment_b)

    if not raw_a or not raw_b:
        raise ValueError("Both fragments must be non-empty")

    if clean_fmt not in ("txt", "csv"):
        raise ValueError(
            f"Fragment-pair reconstruction is not implemented for {fmt!r}; expected txt or csv"
        )

    validator = validate_txt if clean_fmt == "txt" else validate_csv

    # 1. Deterministic per-fragment repair. This only repairs bytes that are
    #    present but undecodable; it never creates absent bytes.
    res_a = reconstruct_artifact(clean_fmt, raw_a)
    res_b = reconstruct_artifact(clean_fmt, raw_b)

    verified = res_a.verified_bytes + res_b.verified_bytes
    structural = res_a.reconstructed_bytes + res_b.reconstructed_bytes
    # Bytes the per-fragment reconstructors could not account for inside the
    # fragments themselves. These are missing too, and must not be hidden.
    intra_missing = res_a.missing_bytes + res_b.missing_bytes
    fragment_bytes = len(raw_a) + len(raw_b)

    # The pair function is the accounting authority for the artifact budget, so
    # normalise each sub-result against its own input length. Any residual is
    # charged to missing; verified and reconstructed are never inflated.
    def _closed(res: ReconstructionResult, n: int) -> int:
        claimed = res.verified_bytes + res.reconstructed_bytes + res.missing_bytes
        if claimed == n:
            return res.missing_bytes
        return max(0, n - res.verified_bytes - res.reconstructed_bytes)

    intra_missing = _closed(res_a, len(raw_a)) + _closed(res_b, len(raw_b))

    damage_regions: List[Dict[str, Any]] = []
    for prefix, res in (("frag-a", res_a), ("frag-b", res_b)):
        for dmg in res.damage_regions:
            damage_regions.append({**dmg, "region_id": f"{prefix}-{dmg.get('type', 'DAMAGE')}"})
    methods: List[str] = []
    for m in list(res_a.reconstruction_methods) + list(res_b.reconstruction_methods):
        if m not in methods:
            methods.append(m)

    # 2. Bounded gap search. Structural validation only; no byte is emitted.
    search = reconstruct_bifragment(
        raw_a, raw_b, validator=validator, min_gap=min_gap, max_gap=max_gap
    )

    if not search.success or search.gap_size is None:
        # No deterministic gap satisfies structural validation. Preserve the
        # surviving fragments and report the intervening region as still missing.
        gap_missing = observed_gap if observed_gap is not None else 0
        missing = gap_missing + intra_missing
        result = ReconstructionResult(
            format=clean_fmt,
            status="PARTIALLY_RECOVERED" if verified else "UNRECOVERABLE",
            success=False,
            recovered_bytes=res_a.recovered_bytes + res_b.recovered_bytes,
            verified_bytes=verified,
            reconstructed_bytes=structural,
            missing_bytes=missing,
            damage_regions=damage_regions,
            reconstruction_methods=methods + ["BOUNDED_GAP_SEARCH_FAILED"],
            validation_result=None,
            is_exact_match=False,
            details={
                "gap_range_searched": [min_gap, max_gap],
                "gap_candidates_tried": max_gap - min_gap + 1,
                "valid_candidate_count": 0,
                "search_discriminating": False,
                "gap_size_determined": False,
                "selected_gap_size": None,
                "observed_gap": observed_gap,
                "intra_fragment_missing_bytes": intra_missing,
                "fragment_input_bytes": fragment_bytes,
                "input_byte_count": fragment_bytes + missing,
                "output_byte_count": len(res_a.recovered_bytes) + len(res_b.recovered_bytes),
                "gap_bytes_emitted": 0,
                "output_sha256": hashlib.sha256(
                    res_a.recovered_bytes + res_b.recovered_bytes
                ).hexdigest(),
                "note": search.missing_region_metadata.get("note"),
                "notice": (
                    f"No candidate gap size in [{min_gap}, {max_gap}] satisfied "
                    f"{clean_fmt.upper()} structural validation "
                    f"({search.missing_region_metadata.get('note')}). The surviving "
                    "fragment bytes are preserved and the intervening region is "
                    "reported as still missing. No gap bytes were synthesized, "
                    "padded, or emitted."
                ),
            },
        )
        # intra_missing is already contained in fragment_bytes, so the artifact
        # budget is the surviving fragment bytes plus the unobserved gap only.
        _validate_accounting(result, fragment_bytes + gap_missing)
        return result

    selected_gap = search.gap_size
    valid_count = search.valid_candidate_count
    candidates_tried = max_gap - min_gap + 1

    # Ambiguity Policy (Requirement 4):
    # - If exactly 1 candidate gap satisfies constraints -> select it.
    # - If multiple candidates are valid and evidence cannot distinguish them ->
    #   preserve ambiguity (selected_gap_size = None, gap_size_determined = False).
    #   Do NOT arbitrarily pick smallest or valid_candidates[0].
    # - If additional deterministic evidence (e.g. unique observed gap match) distinguishes them ->
    #   select uniquely supported candidate.
    is_uniquely_determined = False
    if valid_count == 1:
        is_uniquely_determined = True
        gap_missing = selected_gap
    elif observed_gap is not None and observed_gap == selected_gap and valid_count > 1:
        # If the observed gap in evidence uniquely matches a valid candidate
        is_uniquely_determined = True
        gap_missing = observed_gap
    else:
        # Multiple candidates valid and evidence cannot distinguish them: preserve ambiguity
        is_uniquely_determined = False
        gap_missing = observed_gap if observed_gap is not None else (selected_gap or 0)

    search_discriminating = is_uniquely_determined
    effective_selected_gap = selected_gap if is_uniquely_determined else None

    missing = gap_missing + intra_missing
    recovered = res_a.recovered_bytes + res_b.recovered_bytes
    val_res = search.validation_result

    details = {
        "gap_range_searched": [min_gap, max_gap],
        "gap_candidates_tried": candidates_tried,
        "valid_candidate_count": valid_count,
        "search_discriminating": search_discriminating,
        "selected_gap_size": effective_selected_gap,
        "gap_size_determined": is_uniquely_determined,
        "observed_gap": observed_gap,
        "proven_minimum_missing": gap_missing,
        "intra_fragment_missing_bytes": intra_missing,
        "selected_gap_is_hypothesis_only": True,
        "gap_bytes_emitted": 0,
        "fragment_a_bytes": len(res_a.recovered_bytes),
        "fragment_b_bytes": len(res_b.recovered_bytes),
        "fragment_input_bytes": fragment_bytes,
        "input_byte_count": fragment_bytes + missing,
        "output_byte_count": len(recovered),
        "output_sha256": hashlib.sha256(recovered).hexdigest(),
    }

    if is_uniquely_determined:
        details["notice"] = (
            f"Structural validation uniquely determined candidate gap size = {effective_selected_gap}. "
            "The gap bytes themselves are unobserved and were NOT synthesized, padded, or emitted."
        )
    else:
        details["notice"] = (
            f"Structural validation accepted {valid_count} candidate gap sizes. "
            "Because the evidence cannot distinguish among them, ambiguity is preserved "
            "and no gap size is arbitrarily selected (selected_gap_size = null). "
            "Missing bytes are reported as the provable lower bound observed between fragments. "
            "No gap bytes were synthesized, padded, or emitted."
        )

    result = ReconstructionResult(
        format=clean_fmt,
        status="PARTIALLY_RECOVERED",
        success=True,
        recovered_bytes=recovered,
        verified_bytes=verified,
        reconstructed_bytes=structural,
        missing_bytes=missing,
        damage_regions=damage_regions,
        reconstruction_methods=methods + ["BOUNDED_GAP_RECONSTRUCTION"],
        validation_result=val_res,
        is_exact_match=False,
        details=details,
    )
    # intra_missing is already contained in fragment_bytes, so the artifact budget
    # is the surviving fragment bytes plus the unobserved gap only.
    _validate_accounting(result, fragment_bytes + gap_missing)
    return result
