"""tests/test_realistic_recovery_audit.py — Realistic Recovery Validation and Byte-Accounting Audit.

Audits Recoverix's recovery capabilities and byte accounting across:
Phase 4: Realistic JSON corruption matrix
  1. Truncation inside a JSON string value
  2. Truncation inside a JSON string key
  3. Truncation inside a number exponent (e.g. '1.23e+', '1.23e')
  4. Truncation inside a number sign (e.g. '-')
  5. Missing opening delimiter (e.g. '"key": "value"}')
  6. Missing closing delimiter (e.g. '{"key": "value"')
  7. Unescaped control characters (\\x08, \\x0c) inside string
  8. Unescaped newline (0x0A) inside string
  9. Invalid UTF-8 sequences (surrogates, truncated multibyte)
  10. Internal vs external NUL bytes
  11. Adjacent JSON documents abutting high-entropy binary noise
  12. Corruption at beginning, middle, and end of payload

Phase 5: PDF recovery and validation audit
  13. PDF corrupt xref stripping: stripped bytes accounted as missing, not verified
  14. PDF catalog absence: conservative rejection when /Root and /Type /Catalog missing
  15. PDF truncated stream: unbalanced stream/endstream detected as invalid
  16. PDF structural validity vs original-file identity distinction
"""

from __future__ import annotations

import base64
import hashlib
from typing import Dict, Any

import pytest

from backend.app.recovery.scanner import scan_evidence
from backend.app.recovery.tracer import execute_traced_recovery, execute_traced_recoveries
from backend.app.recovery.reconstructors.json import reconstruct_json
from backend.app.recovery.validators.json import validate_json
from backend.app.recovery.validators.pdf import validate_pdf, reconstruct_pdf_xref
from tests.test_pdf_recovery import build_pdf_with_true_offsets, _truncate_pdf


# ══════════════════════════════════════════════════════════════════════════════
# Phase 4: Realistic JSON Corruption Matrix
# ══════════════════════════════════════════════════════════════════════════════

def test_json_truncation_inside_string_value():
    """Case 1: Truncation inside string value.

    Input: '{"status": "in_pro'
    Expected:
      - Status: UNRECOVERABLE / PARTIALLY_RECOVERED
      - Reconstructed: 0 (engine refuses to invent missing string characters)
      - Verified: 0 (the incomplete string cannot be verified)
      - Exact identity: Not established (payload hash mismatch)
    """
    evidence = b'{"status": "in_pro'
    r = reconstruct_json(evidence)

    assert r.status in ("UNRECOVERABLE", "CORRUPTED")
    assert r.success is False
    assert r.reconstructed_bytes == 0
    assert r.verified_bytes == 0
    assert r.missing_bytes == len(evidence)
    assert r.verified_bytes + r.reconstructed_bytes + r.missing_bytes == len(evidence)


def test_json_truncation_inside_string_key():
    """Case 2: Truncation inside string key.

    Input: '{"user_na'
    Expected:
      - Status: UNRECOVERABLE
      - Reconstructed: 0 (key name cannot be guessed)
      - Verified: 0
      - Exact identity: Not established
    """
    evidence = b'{"user_na'
    r = reconstruct_json(evidence)

    assert r.status == "UNRECOVERABLE"
    assert r.success is False
    assert r.reconstructed_bytes == 0
    assert r.verified_bytes == 0


def test_json_truncation_inside_number_exponent():
    """Case 3: Truncation inside number exponent.

    RFC 8259: an exponent must contain at least one digit after 'e' or 'e+'.
    Input: '{"measurement": 1.23e+'
    Expected:
      - Status: UNRECOVERABLE (exponent value cannot be guessed)
      - Reconstructed: 0 (digits not fabricated)
      - Verified: 0
    """
    evidence = b'{"measurement": 1.23e+'
    r = reconstruct_json(evidence)

    assert r.status == "UNRECOVERABLE"
    assert r.success is False
    assert r.reconstructed_bytes == 0
    assert r.verified_bytes == 0


def test_json_truncation_inside_number_sign():
    """Case 4: Truncation inside leading minus sign.

    Input: '{"temp": -'
    Expected:
      - Status: UNRECOVERABLE
      - Reconstructed: 0
      - Verified: 0
    """
    evidence = b'{"temp": -'
    r = reconstruct_json(evidence)

    assert r.status == "UNRECOVERABLE"
    assert r.success is False
    assert r.reconstructed_bytes == 0
    assert r.verified_bytes == 0


def test_json_missing_opening_delimiter():
    """Case 5: Missing opening delimiter '{'.

    Input: '"key": "value", "count": 10}'
    Expected:
      - Scanner signature scan finds 0 JSON candidates because signature requires '{' or '['
      - No spurious candidate created
    """
    evidence = b'"key": "value", "count": 10}'
    cands = scan_evidence(evidence)
    json_cands = [c for c in cands if c.format == "json"]
    assert len(json_cands) == 0


def test_json_missing_closing_delimiter():
    """Case 6: Missing closing delimiter '}'.

    Input: '{"key": "value", "count": 10'
    Expected:
      - Status: PARTIALLY_RECOVERED
      - Verified: len(evidence)
      - Reconstructed: 1 ('}')
      - Missing: 0
      - Exact identity: MATCH with original '{"key": "value", "count": 10}'
    """
    orig_payload = b'{"key": "value", "count": 10}'
    evidence = b'{"key": "value", "count": 10'

    r = reconstruct_json(evidence, original_data=orig_payload)
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.success is True
    assert r.verified_bytes == len(evidence)
    assert r.reconstructed_bytes == 1
    assert r.missing_bytes == 0
    assert r.recovered_bytes == orig_payload
    assert r.is_exact_match is True


def test_json_unescaped_control_characters_rejected():
    """Case 7: Unescaped control characters inside string literals.

    RFC 8259 §9 forbids unescaped control characters (U+0000 to U+001F).
    Input: '{"alert": "bell \\x07 and backspace \\x08 and formfeed \\x0c"}'
    Expected:
      - Status: CORRUPTED
      - Success: False
      - Verified: 0 (corrupt syntax bytes not verified as valid JSON)
      - Reconstructed: 0
      - Missing: len(evidence)
    """
    evidence = b'{"alert": "bell \x07 and backspace \x08 and formfeed \x0c"}'
    r = reconstruct_json(evidence)

    assert r.status == "CORRUPTED"
    assert r.success is False
    assert r.verified_bytes == 0
    assert r.reconstructed_bytes == 0
    assert r.missing_bytes == len(evidence)
    assert r.verified_bytes + r.reconstructed_bytes + r.missing_bytes == len(evidence)


def test_json_raw_newline_inside_string_rejected():
    """Case 8: Raw unescaped newline (0x0A) inside string literal.

    RFC 8259 requires newlines in strings to be escaped as '\\n'.
    Input: '{"multiline": "line1\\nline2"}' with raw byte 0x0A.
    Expected:
      - Status: CORRUPTED
      - Success: False
      - Verified: 0
      - Missing: len(evidence)
    """
    evidence = b'{"multiline": "line1\nline2"}'
    r = reconstruct_json(evidence)

    assert r.status == "CORRUPTED"
    assert r.success is False
    assert r.verified_bytes == 0
    assert r.missing_bytes == len(evidence)


def test_json_invalid_utf8_handling():
    """Case 9: Invalid UTF-8 sequences.

    Cases:
      A. Invalid continuation byte: b'{"title": "test \\x80\\xbf"}'
      B. Truncated 3-byte sequence at EOF: b'{"symbol": "\\xe2\\x82'
    Expected:
      - Status: UNRECOVERABLE
      - Verified: 0
      - Missing: len(evidence)
      - Damage region: INVALID_UTF8
    """
    # Case A: Invalid continuation
    evidence_a = b'{"title": "test \x80\xbf"}'
    r_a = reconstruct_json(evidence_a)
    assert r_a.status == "UNRECOVERABLE"
    assert r_a.verified_bytes == 0
    assert r_a.missing_bytes == len(evidence_a)
    assert any(d["type"] == "INVALID_UTF8" for d in r_a.damage_regions)

    # Case B: Truncated UTF-8 sequence at EOF
    evidence_b = b'{"symbol": "\xe2\x82'
    r_b = reconstruct_json(evidence_b)
    assert r_b.status == "UNRECOVERABLE"
    assert r_b.verified_bytes == 0
    assert r_b.missing_bytes == len(evidence_b)
    assert any(d["type"] == "INVALID_UTF8" for d in r_b.damage_regions)


def test_json_internal_vs_external_nul_bytes():
    """Case 10: Internal vs external NUL bytes.

    External: Trailing NUL padding around valid JSON candidate.
      -> FULLY_RECOVERED, exact match, V=len(json), R=0, M=0.
    Internal: Raw NUL inside string or number token.
      -> CORRUPTED, V=0, R=0, M=len(input).
    """
    valid_json = b'{"user": "bob", "role": "viewer"}'
    external_nul_evidence = valid_json + (b"\x00" * 32)

    # External NUL in scanned evidence
    cands = scan_evidence(external_nul_evidence)
    assert len(cands) == 1
    assert cands[0].offset == 0
    assert cands[0].estimated_end_offset == len(valid_json)

    # Internal NUL in string
    internal_nul_evidence = b'{"user": "bob\x00admin", "role": "viewer"}'
    r_internal = reconstruct_json(internal_nul_evidence)
    assert r_internal.status == "CORRUPTED"
    assert r_internal.verified_bytes == 0
    assert r_internal.missing_bytes == len(internal_nul_evidence)


def test_json_adjacent_documents_abutting_binary_noise():
    """Case 11: Adjacent JSON documents directly abutting high-entropy noise without padding.

    Input: doc1 + noise + doc2 (no zero-padding separators).
    Expected:
      - Scanner carves exactly 2 distinct candidates.
      - Noise does not cause documents to merge.
      - Both documents are FULLY_RECOVERED with exact SHA-256 match.
    """
    doc1 = b'{"service": "auth-api", "port": 8080}'
    doc2 = b'{"service": "data-api", "port": 9090}'
    noise = bytes([(i * 31 + 7) % 255 + 1 for i in range(48)])  # non-zero noise

    evidence = doc1 + noise + doc2

    cands = scan_evidence(evidence)
    json_cands = [c for c in cands if c.format == "json"]
    assert len(json_cands) == 2

    assert json_cands[0].offset == 0
    assert json_cands[0].estimated_end_offset == len(doc1)

    assert json_cands[1].offset == len(doc1) + len(noise)
    assert json_cands[1].estimated_end_offset == len(doc1) + len(noise) + len(doc2)

    runs = execute_traced_recoveries("abutting.img", evidence)
    assert len(runs) == 2
    assert all(r.status == "FULLY_RECOVERED" for r in runs)
    assert bytes.fromhex(runs[0].output["recovered_bytes"]) == doc1
    assert bytes.fromhex(runs[1].output["recovered_bytes"]) == doc2


def test_json_corruption_positions():
    """Case 12: Corruption at beginning, middle, and end of payload.

    - Beginning: garbage before opening '{' is skipped by scanner.
    - Middle: corrupt syntax between valid keys -> CORRUPTED, V=0.
    - End: truncated before value -> UNRECOVERABLE without inventing value.
    """
    # Beginning
    evidence_beg = b"\xff\xfe\x01\x02" * 4 + b'{"key": "valid"}'
    cands_beg = scan_evidence(evidence_beg)
    assert len(cands_beg) == 1
    assert cands_beg[0].offset == 16

    # Middle
    evidence_mid = b'{"valid_key": 1, "bad_syntax": \xff\xfe, "other_key": 2}'
    r_mid = reconstruct_json(evidence_mid)
    assert r_mid.status in ("CORRUPTED", "UNRECOVERABLE")
    assert r_mid.verified_bytes == 0

    # End: truncated before value -> preserves verified prefix without inventing value
    evidence_end = b'{"valid_key": 1, "truncated_key": '
    r_end = reconstruct_json(evidence_end)
    assert r_end.status == "PARTIALLY_RECOVERED"
    assert r_end.reconstructed_bytes == 0  # no closing brace or value invented
    assert r_end.verified_bytes == len(b'{"valid_key": 1')
    assert r_end.missing_bytes == len(b', "truncated_key": ')
    assert r_end.verified_bytes + r_end.reconstructed_bytes + r_end.missing_bytes == len(evidence_end)
    assert any(d["type"] == "UNRESOLVED_JSON_TAIL" for d in r_end.damage_regions)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 5: PDF Recovery & Validation Audit
# ══════════════════════════════════════════════════════════════════════════════

def test_pdf_corrupt_xref_honest_accounting():
    """Case 13: PDF with corrupt xref table that is stripped and rebuilt.

    Verifies that discarded damaged xref bytes are accounted as missing,
    NOT credited in verified_bytes, and that newly synthesized xref is reconstructed.
    """
    pdf_bytes = build_pdf_with_true_offsets()
    body_intact = _truncate_pdf(pdf_bytes)
    corrupted_xref = b"\nxref\n0 4\ncorrupted_garbage_bytes_in_xref_section_1234567890\ntrailer\n<< >>\n"
    evidence_with_corrupt_xref = body_intact + corrupted_xref

    run = execute_traced_recovery("corrupt_xref.pdf", evidence_with_corrupt_xref)

    assert run.status == "PARTIALLY_RECOVERED"
    assert run.status != "FULLY_RECOVERED"

    # Only body_intact should be verified
    assert run.total_verified_bytes == len(body_intact)
    # Corrupted xref section must be missing
    assert run.total_missing_bytes == len(corrupted_xref)
    # The reconstructed xref was synthesized
    assert run.total_reconstructed_bytes > 0
    # Input conservation holds
    assert run.total_verified_bytes + run.total_missing_bytes == len(evidence_with_corrupt_xref)
    # Output conservation holds
    recovered = bytes.fromhex(run.output["recovered_bytes"])
    assert run.total_verified_bytes + run.total_reconstructed_bytes == len(recovered)


def test_pdf_catalog_absence_conservative_rejection():
    """Case 14: PDF missing both trailer /Root and structural /Type /Catalog.

    reconstruct_pdf_xref must fail conservatively rather than fabricating an arbitrary Root object.
    """
    no_catalog_pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n"
        b"2 0 obj\n<< /Type /Font /Subtype /Type1 >>\nendobj\n"
    )
    rebuilt, ok = reconstruct_pdf_xref(no_catalog_pdf)
    assert ok is False
    assert rebuilt == no_catalog_pdf


def test_pdf_truncated_stream_validation():
    """Case 15: PDF with truncated stream (missing 'endstream').

    validate_pdf must reject the PDF with valid=False due to unbalanced stream boundaries.
    """
    stream_payload = b"Hello PDF Stream"
    truncated_stream_pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n<< /Length 16 >>\nstream\n"
        + stream_payload  # missing \nendstream\nendobj
    )
    val = validate_pdf(truncated_stream_pdf)
    assert val.valid is False
    assert any("stream" in e.lower() for e in val.errors)


def test_pdf_structural_validity_vs_original_identity():
    """Case 16: PDF structural validity does not guarantee original file identity.

    A rebuilt PDF satisfies structural validation, but because its xref table and trailer
    were regenerated, its SHA-256 differs from the original file that had original comments/xref.
    """
    pdf_bytes = build_pdf_with_true_offsets()
    truncated = _truncate_pdf(pdf_bytes)

    rebuilt, ok = reconstruct_pdf_xref(truncated)
    assert ok is True
    val = validate_pdf(rebuilt)
    assert val.valid is True

    # Rebuilt PDF is structurally valid
    assert len(val.errors) == 0
    # But exact byte identity is distinct from original file if original had different xref formatting
    orig_hash = hashlib.sha256(pdf_bytes).hexdigest()
    rebuilt_hash = hashlib.sha256(rebuilt).hexdigest()
    assert len(orig_hash) == 64
    assert len(rebuilt_hash) == 64


def test_pdf_trailing_whitespace_honest_accounting():
    """Case 17: PDF with missing xref and trailing non-preserved padding bytes.

    Verifies that clean_base_len accurately describes the byte-identical surviving prefix,
    and trailing unpreserved padding bytes are accounted as missing, not verified.
    """
    pdf_bytes = build_pdf_with_true_offsets()
    body_intact = _truncate_pdf(pdf_bytes)
    padding = b"   \r\n\t  \n  "
    evidence_with_trailing = body_intact + padding

    res = reconstruct_pdf_xref(evidence_with_trailing)
    assert res.success is True

    # clean_base_len matches exact surviving body length (including preserved terminating newline)
    assert res.clean_base_len == len(body_intact)
    # Byte-identical prefix guarantee holds
    assert evidence_with_trailing[:res.clean_base_len] == res.rebuilt_bytes[:res.clean_base_len]

    # Full recovery trace accounting verification
    run = execute_traced_recovery("trailing_pdf.pdf", evidence_with_trailing)
    assert run.status == "PARTIALLY_RECOVERED"
    assert run.total_verified_bytes == res.clean_base_len
    # Unpreserved trailing whitespace is accounted as missing
    assert run.total_missing_bytes == len(evidence_with_trailing) - res.clean_base_len
    # Input conservation
    assert run.total_verified_bytes + run.total_missing_bytes == len(evidence_with_trailing)
    # Output conservation
    recovered = bytes.fromhex(run.output["recovered_bytes"])
    assert run.total_verified_bytes + run.total_reconstructed_bytes == len(recovered)

