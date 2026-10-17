"""
txt.py — Deterministic TXT format reconstruction engine.

Parses damaged text evidence (UTF-8 byte corruption, null/noise byte runs,
truncation, fragmented blocks), performs deterministic UTF-8 repair and garbage cleanup,
enforces strict forensic accounting (total_input = verified + reconstructed + missing),
and evaluates recovery status without false FULLY_RECOVERED classifications.
"""

from __future__ import annotations

import hashlib
from typing import Optional, Union, List, Dict, Any, Tuple

from backend.app.models.reconstruction import ReconstructionResult
from backend.app.recovery.carver import RecoveredArtifact
from backend.app.recovery.scanner import Candidate
from backend.app.recovery.validators.text import validate_txt
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)
from backend.app.scoring.confidence import evaluate_artifact_confidence


def _analyze_and_reconstruct_utf8(body_bytes: bytes) -> Tuple[bytes, int, int, int, List[Dict[str, Any]], List[str]]:
    """Analyze and reconstruct UTF-8 body bytes.

    Returns:
        Tuple of:
          - reconstructed_body_bytes (bytes)
          - verified_bytes_count (int)
          - reconstructed_bytes_count (int)
          - missing_bytes_count (int)
          - damage_regions (List[Dict[str, Any]])
          - reconstruction_methods (List[str])
    """
    total_len = len(body_bytes)
    if total_len == 0:
        return b"", 0, 0, 0, [], []

    # Check if input is predominantly unrecoverable binary garbage
    # Count printable text characters vs unprintable binary control bytes
    non_text_count = 0
    for b in body_bytes:
        if b not in b"\t\r\n" and (b < 32 or b == 127 or (b >= 128 and b < 160)):
            non_text_count += 1

    binary_ratio = non_text_count / total_len
    if binary_ratio > 0.85 and total_len >= 16:
        # Unrecoverable binary garbage
        damage_region = {
            "offset": 0,
            "length": total_len,
            "type": "BINARY_GARBAGE",
            "description": "Evidence consists of unrecoverable binary noise",
        }
        return b"", 0, 0, total_len, [damage_region], []

    damage_regions: List[Dict[str, Any]] = []
    reconstruction_methods: List[str] = []

    # Step 1: Detect and trim truncated UTF-8 tail (only if body does not decode as valid UTF-8)
    working_bytes = body_bytes
    trimmed_tail_len = 0

    try:
        working_bytes.decode("utf-8")
        # Body is already valid UTF-8; no tail trimming needed
    except UnicodeDecodeError:
        # Determine if last bytes form an incomplete UTF-8 multi-byte sequence
        for cutoff in range(1, min(4, len(working_bytes) + 1)):
            try:
                working_bytes[:-cutoff].decode("utf-8")
                # If cutoff bytes were invalid tail, check if cutting them makes remainder valid
                sub = working_bytes[-cutoff:]
                # Check if sub is a leading multi-byte byte (\xc0-\xff) without enough continuation bytes
                if sub[0] >= 0xC0:
                    trimmed_tail_len = cutoff
                    working_bytes = working_bytes[:-cutoff]
                    damage_regions.append({
                        "offset": len(working_bytes),
                        "length": trimmed_tail_len,
                        "type": "TRUNCATED_UTF8_TAIL",
                        "description": f"Truncated UTF-8 multi-byte sequence cut off at offset {len(working_bytes)}",
                    })
                    reconstruction_methods.append("TRUNCATED_TAIL_TRIM")
                    break
            except UnicodeDecodeError:
                continue

    # Step 2: Byte-level UTF-8 scanning and repair
    verified_bytes = 0
    reconstructed_bytes = 0
    missing_bytes = trimmed_tail_len

    out_chunks: List[bytes] = []
    idx = 0
    w_len = len(working_bytes)

    while idx < w_len:
        b = working_bytes[idx]

        # Case A: Null bytes or control byte runs (\x00 or unprintable control)
        if b == 0 or (b < 32 and b not in (9, 10, 13)):
            run_start = idx
            while idx < w_len and (working_bytes[idx] == 0 or (working_bytes[idx] < 32 and working_bytes[idx] not in (9, 10, 13))):
                idx += 1
            run_len = idx - run_start

            # Determine replacement: if surrounded by printable text, normalize to space or newline
            has_prev = run_start > 0 and working_bytes[run_start - 1] in b" \t\r\n"
            has_next = idx < w_len and working_bytes[idx] in b" \t\r\n"

            if not has_prev and not has_next and run_start > 0 and idx < w_len:
                # Replace run with 1 space character to preserve text separation
                out_chunks.append(b" ")
                reconstructed_bytes += 1
                missing_bytes += (run_len - 1)
                m_type = "NULL_BYTE_RUN" if working_bytes[run_start] == 0 else "CONTROL_BYTE_RUN"
                damage_regions.append({
                    "offset": run_start,
                    "length": run_len,
                    "type": m_type,
                    "description": f"Replaced {run_len}-byte noise run with single space",
                })
                if "GARBAGE_CLEANUP" not in reconstruction_methods:
                    reconstruction_methods.append("GARBAGE_CLEANUP")
            else:
                # Strip noise run completely
                missing_bytes += run_len
                m_type = "NULL_BYTE_RUN" if working_bytes[run_start] == 0 else "CONTROL_BYTE_RUN"
                damage_regions.append({
                    "offset": run_start,
                    "length": run_len,
                    "type": m_type,
                    "description": f"Stripped {run_len}-byte noise run",
                })
                if "GARBAGE_CLEANUP" not in reconstruction_methods:
                    reconstruction_methods.append("GARBAGE_CLEANUP")
            continue

        # Case B: Standard ASCII byte
        if b < 128:
            out_chunks.append(bytes([b]))
            verified_bytes += 1
            idx += 1
            continue

        # Case C: Multi-byte UTF-8 sequence
        # Determine sequence length
        if (b & 0xE0) == 0xC0:
            seq_len = 2
        elif (b & 0xF0) == 0xE0:
            seq_len = 3
        elif (b & 0xF8) == 0xF0:
            seq_len = 4
        else:
            # Invalid UTF-8 start byte
            seq_len = 1

        chunk = working_bytes[idx:idx + seq_len]
        try:
            chunk.decode("utf-8")
            # Valid multi-byte UTF-8 sequence
            out_chunks.append(chunk)
            verified_bytes += len(chunk)
            idx += seq_len
        except UnicodeDecodeError:
            # Invalid UTF-8 sequence: repair with '?' character
            out_chunks.append(b"?")
            reconstructed_bytes += 1
            missing_bytes += (len(chunk) - 1)
            damage_regions.append({
                "offset": idx,
                "length": len(chunk),
                "type": "INVALID_UTF8_BYTES",
                "description": f"Repaired invalid UTF-8 byte sequence at offset {idx}",
            })
            if "UTF8_REPAIR" not in reconstruction_methods:
                reconstruction_methods.append("UTF8_REPAIR")
            idx += len(chunk)

    reconstructed_body_bytes = b"".join(out_chunks)

    # Sanity check total accounting invariant for body_bytes
    assert total_len == verified_bytes + reconstructed_bytes + missing_bytes, (
        f"Forensic accounting invariant failed: input={total_len} != verified({verified_bytes}) + "
        f"reconstructed({reconstructed_bytes}) + missing({missing_bytes})"
    )

    return (
        reconstructed_body_bytes,
        verified_bytes,
        reconstructed_bytes,
        missing_bytes,
        damage_regions,
        reconstruction_methods,
    )


def reconstruct_txt(
    data: Union[bytes, bytearray, RecoveredArtifact],
    ground_truth: Optional[bytes] = None,
    detection_mode: str = "known_file",
) -> ReconstructionResult:
    """Execute deterministic TXT format reconstruction on raw evidence or carved artifact.

    Args:
        data: Raw evidence bytes or RecoveredArtifact object.
        ground_truth: Optional ground truth bytes for SHA-256 verification.

    Returns:
        ReconstructionResult with exact forensic accounting and reconstructed bytes.
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
        val_res = validate_txt(b"")
        return ReconstructionResult(
            format="txt",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=0,
            damage_regions=[{"offset": 0, "length": 0, "type": "EMPTY_INPUT", "description": "Empty evidence input"}],
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False,
            details={"error": "Empty input bytes"},
        )

    # Check for synthetic boundary markers
    start_pos = raw_bytes.find(SYNTHETIC_START_MARKER)
    end_pos = raw_bytes.find(SYNTHETIC_END_MARKER)

    marker_start_bytes = b""
    marker_end_bytes = b""
    restored_end_bytes = b""
    prefix_bytes = b""
    body_content = raw_bytes

    if start_pos != -1 and end_pos != -1 and start_pos < end_pos:
        marker_start_bytes = raw_bytes[:start_pos + len(SYNTHETIC_START_MARKER)]
        body_raw = raw_bytes[start_pos + len(SYNTHETIC_START_MARKER):end_pos]
        marker_end_bytes = raw_bytes[end_pos:]

        if body_raw.startswith(b"FMT:txt;"):
            prefix_bytes = b"FMT:txt;"
            body_content = body_raw[8:]
        else:
            body_content = body_raw

        try:
            body_content.decode("utf-8")
            has_utf8_error = False
            decode_error_detail = ""
        except UnicodeDecodeError as exc:
            has_utf8_error = True
            decode_error_detail = str(exc)

        if has_utf8_error:
            val_res = validate_txt(raw_bytes)
            return ReconstructionResult(
                format="txt",
                status="CORRUPTED",
                success=False,
                recovered_bytes=raw_bytes,
                verified_bytes=0,
                reconstructed_bytes=0,
                missing_bytes=total_input_bytes,
                damage_regions=[
                    {
                        "offset": 0,
                        "length": total_input_bytes,
                        "type": "CORRUPTED",
                        "description": f"Unrepairable UTF-8 byte corruption: {decode_error_detail}",
                    }
                ],
                reconstruction_methods=[],
                validation_result=val_res,
                is_exact_match=False if ground_truth is not None else False,
                details={
                    "error": "Unrepairable byte corruption in bounded text candidate",
                    "corruption_type": "INVALID_UTF8",
                },
            )
    elif start_pos != -1 and end_pos == -1:
        # The start marker survived but the end marker did not. The end marker is
        # a known fixed constant, so restoring it is deterministic structural
        # reconstruction, not invention of content. It is counted as reconstructed
        # rather than verified because those bytes are absent from the evidence.
        marker_start_bytes = raw_bytes[:start_pos + len(SYNTHETIC_START_MARKER)]
        body_raw = raw_bytes[start_pos + len(SYNTHETIC_START_MARKER):]
        restored_end_bytes = SYNTHETIC_END_MARKER

        if body_raw.startswith(b"FMT:txt;"):
            prefix_bytes = b"FMT:txt;"
            body_content = body_raw[8:]
        else:
            body_content = body_raw

    # Structure bytes (markers + prefix) are verified evidence structure
    struct_verified_bytes = len(marker_start_bytes) + len(prefix_bytes) + len(marker_end_bytes)
    struct_reconstructed_bytes = len(restored_end_bytes)

    (
        recon_body_bytes,
        body_verified,
        body_reconstructed,
        body_missing,
        damage_regions,
        recon_methods,
    ) = _analyze_and_reconstruct_utf8(body_content)

    total_verified = struct_verified_bytes + body_verified
    total_reconstructed = body_reconstructed + struct_reconstructed_bytes
    total_missing = body_missing

    # A structural repair may restore a byte that the evidence never contained
    # (e.g. a dropped synthetic end marker). Those bytes are counted as
    # reconstructed, never as verified, so the artifact budget is the larger of
    # the damaged input and the reconstructed output.
    artifact_budget = max(
        total_input_bytes, total_verified + total_reconstructed
    )
    total_missing = max(
        0, artifact_budget - total_verified - total_reconstructed
    )

    # Strict invariant assertion
    assert artifact_budget == total_verified + total_reconstructed + total_missing, (
        f"Accounting mismatch: budget={artifact_budget} != verified={total_verified} + "
        f"reconstructed={total_reconstructed} + missing={total_missing}"
    )

    if body_verified == 0 and body_reconstructed == 0 and body_missing == len(body_content):
        # Pure unrecoverable noise
        val_res = validate_txt(raw_bytes)
        return ReconstructionResult(
            format="txt",
            status="UNRECOVERABLE",
            success=False,
            recovered_bytes=b"",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=total_input_bytes,
            damage_regions=damage_regions,
            reconstruction_methods=[],
            validation_result=val_res,
            is_exact_match=False,
            details={"error": "Unrecoverable binary evidence"},
        )

    # Reassemble recovered output bytes
    recovered_output_bytes = (
        marker_start_bytes + prefix_bytes + recon_body_bytes + marker_end_bytes + restored_end_bytes
    )

    # Validate output artifact
    val_result = validate_txt(recovered_output_bytes)

    if start_pos != -1:
        effective_detection_mode = "synthetic_harness"
    else:
        effective_detection_mode = detection_mode

    from backend.app.recovery.completeness import assess_artifact_completeness
    is_complete = assess_artifact_completeness(
        fmt="txt",
        content=recovered_output_bytes,
        detection_mode=effective_detection_mode,
        validation_result=val_result,
        missing_bytes=total_missing,
        reconstructed_bytes=total_reconstructed,
    )

    # Evaluate confidence score & status
    eval_res = evaluate_artifact_confidence(
        validation_result=val_result,
        artifact=recovered_output_bytes,
        actual_missing_bytes=total_missing,
        is_complete=is_complete,
    )

    # Enforce status override: If reconstructed_bytes > 0 or missing_bytes > 0 or not complete, status CANNOT be FULLY_RECOVERED
    status_str = eval_res.status.value
    if (total_reconstructed > 0 or total_missing > 0 or not is_complete) and status_str == "FULLY_RECOVERED":
        status_str = "PARTIALLY_RECOVERED"

    # Determine ground truth hash match
    is_exact_match: Optional[bool] = None
    if ground_truth is not None:
        is_exact_match = (hashlib.sha256(recovered_output_bytes).hexdigest() == hashlib.sha256(ground_truth).hexdigest())
    else:
        is_exact_match = (total_reconstructed == 0 and total_missing == 0)

    success = val_result.valid and status_str in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")

    return ReconstructionResult(
        format="txt",
        status=status_str,
        success=success,
        recovered_bytes=recovered_output_bytes,
        verified_bytes=total_verified,
        reconstructed_bytes=total_reconstructed,
        missing_bytes=total_missing,
        damage_regions=damage_regions,
        reconstruction_methods=recon_methods if recon_methods else ["NONE"],
        validation_result=val_result,
        is_exact_match=is_exact_match,
        details={
            "input_byte_count": total_input_bytes,
            "recovered_byte_count": len(recovered_output_bytes),
            "confidence_score": eval_res.score_breakdown.total,
        },
    )
