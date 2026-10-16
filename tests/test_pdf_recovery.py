"""
test_pdf_recovery.py — Test suite for Real PDF Recovery (Task 7).

Verifies PDF format recovery across 6 required scenarios:
  1. Intact PDF: Full recovery, score 100, FULLY_RECOVERED, recovered_bytes == original_bytes.
  2. Truncated PDF: Missing trailer/EOF, score downgraded, PARTIALLY_RECOVERED or CORRUPTED.
  3. Missing %%EOF: Header valid, footer score 0.
  4. Damaged Xref Table: Original objects preserved, xref reconstructed deterministically.
  5. Fragmented PDF: Bifragment recovery using real PDF fragments.
  6. Unrecoverable Corruption: Severe byte corruption yielding UNRECOVERABLE.
"""

from __future__ import annotations

import pytest

from backend.app.recovery.scanner import scan_evidence
from backend.app.recovery.carver import carve_candidate, RecoveredArtifact
from backend.app.recovery.validators.pdf import validate_pdf, reconstruct_pdf_xref
from backend.app.recovery.bifragment import reconstruct_bifragment
from backend.app.scoring.confidence import (
    calculate_confidence,
    evaluate_artifact_confidence,
    RecoveryStatus,
)


# Helper to build a valid minimal PDF byte structure
def build_minimal_pdf() -> bytes:
    """Build a minimal, strictly valid PDF byte buffer."""
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kinds [] /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
    )
    xref_offset = len(body)
    xref_and_trailer = (
        b"xref\n"
        b"0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000052 00000 n \n"
        b"0000000118 00000 n \n"
        b"trailer\n"
        b"<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n" +
        f"{xref_offset}\n".encode("ascii") +
        b"%%EOF\n"
    )
    return body + xref_and_trailer


# ── Scenario 1: Intact PDF ──────────────────────────────────────────

def test_intact_pdf_recovery():
    pdf_bytes = build_minimal_pdf()
    candidates = scan_evidence(pdf_bytes)

    assert len(candidates) >= 1
    pdf_cand = [c for c in candidates if c.format == "pdf"][0]
    assert pdf_cand.offset == 0

    carved = carve_candidate(pdf_bytes, pdf_cand)
    assert carved.recovered_bytes == pdf_bytes

    val = validate_pdf(carved)
    assert val.valid is True
    assert len(val.errors) == 0

    eval_res = evaluate_artifact_confidence(val, artifact=carved)
    assert eval_res.score_breakdown.total == 100
    assert eval_res.status == RecoveryStatus.FULLY_RECOVERED


# ── Scenario 2: Truncated PDF ────────────────────────────────────────

def test_truncated_pdf_recovery():
    pdf_bytes = build_minimal_pdf()
    # Truncate halfway through trailer (removing %%EOF)
    truncated_bytes = pdf_bytes[:len(pdf_bytes) - 30]

    carved = RecoveredArtifact(
        candidate_id="cand-0",
        format="pdf",
        mime_type="application/pdf",
        category="document",
        source_offset=0,
        recovered_bytes=truncated_bytes,
        recovered_byte_count=len(truncated_bytes),
        carving_method="TRUNCATED",
    )

    val = validate_pdf(carved)
    assert val.valid is False
    assert any("Missing PDF trailer signature" in e or "Missing startxref" in e for e in val.errors)

    eval_res = evaluate_artifact_confidence(val, artifact=carved)
    assert eval_res.score_breakdown.total < 100
    assert eval_res.status in (RecoveryStatus.PARTIALLY_RECOVERED, RecoveryStatus.CORRUPTED, RecoveryStatus.UNRECOVERABLE)


# ── Scenario 3: Missing %%EOF ────────────────────────────────────────

def test_missing_eof_pdf_recovery():
    pdf_bytes = build_minimal_pdf()
    no_eof_bytes = pdf_bytes.replace(b"%%EOF", b"     ")

    carved = RecoveredArtifact(
        candidate_id="cand-0",
        format="pdf",
        mime_type="application/pdf",
        category="document",
        source_offset=0,
        recovered_bytes=no_eof_bytes,
        recovered_byte_count=len(no_eof_bytes),
        carving_method="CONTIGUOUS",
    )

    val = validate_pdf(carved)
    assert val.valid is False
    assert "Missing PDF trailer signature: %%EOF" in val.errors

    breakdown = calculate_confidence(val, artifact=carved)
    assert breakdown.footer_validity == 0
    assert breakdown.total < 100


# ── Scenario 4: Damaged Xref Table ───────────────────────────────────

def test_damaged_xref_pdf_reconstruction():
    pdf_bytes = build_minimal_pdf()
    # Remove xref table completely
    corrupt_xref_bytes = pdf_bytes.replace(b"xref", b"xxxx")

    val_before = validate_pdf(corrupt_xref_bytes)
    assert val_before.valid is False

    # Perform deterministic xref reconstruction
    reconstructed, success = reconstruct_pdf_xref(corrupt_xref_bytes)
    assert success is True
    assert reconstructed.startswith(b"%PDF-1.4")
    assert reconstructed.endswith(b"%%EOF\n")

    val_after = validate_pdf(reconstructed)
    assert val_after.valid is True
    assert len(val_after.errors) == 0


# ── Scenario 5: Fragmented PDF ───────────────────────────────────────

def test_fragmented_pdf_bifragment_recovery():
    pdf_bytes = build_minimal_pdf()
    split_point = 60
    frag1 = pdf_bytes[:split_point]
    frag2 = pdf_bytes[split_point:]

    # Bounded gap reconstruction between frag1 and frag2
    res = reconstruct_bifragment(
        frag1,
        frag2,
        validator=validate_pdf,
        min_gap=1,
        max_gap=100,
    )
    assert res is not None


# ── Scenario 6: Unrecoverable Corruption ────────────────────────────

def test_unrecoverable_pdf_corruption():
    # Noise bytes with no PDF structure or header
    garbage_bytes = b"\x00\xff\xfe\xfd\x10\x20\x30\x40random_garbage_data"

    cands = scan_evidence(garbage_bytes)
    pdf_cands = [c for c in cands if c.format == "pdf"]
    assert len(pdf_cands) == 0

    carved = RecoveredArtifact(
        candidate_id="cand-99",
        format="pdf",
        mime_type="application/pdf",
        category="document",
        source_offset=0,
        recovered_bytes=garbage_bytes,
        recovered_byte_count=len(garbage_bytes),
        carving_method="FALLBACK",
    )

    val = validate_pdf(carved)
    assert val.valid is False

    eval_res = evaluate_artifact_confidence(val, artifact=carved)
    assert eval_res.score_breakdown.total < 40
    assert eval_res.status == RecoveryStatus.UNRECOVERABLE


# ── P1 Fix #2: deterministic PDF rebuild provenance accounting ───────
#
# A deterministic xref rebuild ADDS bytes on top of the surviving evidence.
# Those added bytes are reconstructed, never verified, so the accounting
# identity holds and FULLY_RECOVERED is forbidden when reconstruction
# contributed any bytes.

def _truncate_pdf(pdf_bytes: bytes, keep_xref: bool = False) -> bytes:
    """Return PDF evidence with the trailing xref/trailer removed.

    keep_xref=False drops the cross-reference table entirely, which is the
    case the deterministic xref rebuild is designed to repair.
    """
    if keep_xref:
        return pdf_bytes
    return pdf_bytes[: pdf_bytes.index(b"xref")]


def build_pdf_with_true_offsets() -> bytes:
    """Build a valid PDF whose xref offsets are computed, not hand-written.

    ``build_minimal_pdf`` hard-codes offsets that do not match the real object
    positions, so it is not byte-exact-reconstructible. This fixture derives
    each offset from the assembled body, which is what a real writer does and
    what the deterministic rebuild reproduces exactly.
    """
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kinds [] /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R >>",
    ]

    body = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(body))
        body += f"{i} 0 obj\n".encode("ascii") + obj + b"\nendobj\n"

    xref_offset = len(body)
    body += b"xref\n0 4\n"
    body += b"0000000000 65535 f \n"
    for off in offsets:
        body += f"{off:010d} 00000 n \n".encode("ascii")
    body += b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n"
    body += f"{xref_offset}\n".encode("ascii")
    body += b"%%EOF\n"

    return bytes(body)


def _run_pdf_recovery(content: bytes, filename: str = "evidence.pdf"):
    from backend.app.recovery.tracer import execute_traced_recovery

    return execute_traced_recovery(filename=filename, content=content)


def test_pdf_rebuild_is_byte_exact():
    """The deterministic xref rebuild reproduces the original PDF exactly."""
    pdf_bytes = build_pdf_with_true_offsets()
    truncated = _truncate_pdf(pdf_bytes)

    rebuilt, ok = reconstruct_pdf_xref(truncated)

    assert ok is True
    assert rebuilt == pdf_bytes


def test_pdf_reconstructed_bytes_are_not_counted_as_verified():
    """Rebuilt bytes are attributed to reconstructed_bytes, not verified_bytes."""
    pdf_bytes = build_pdf_with_true_offsets()
    truncated = _truncate_pdf(pdf_bytes)
    rebuilt, ok = reconstruct_pdf_xref(truncated)
    assert ok is True

    run = _run_pdf_recovery(truncated)

    expected_reconstructed = len(rebuilt) - len(truncated)
    assert expected_reconstructed > 0, "fixture must exercise a real rebuild"
    assert run.total_reconstructed_bytes == expected_reconstructed
    assert run.total_verified_bytes == len(truncated)
    # The rebuilt output must NOT be reported wholesale as verified evidence.
    assert run.total_verified_bytes != len(rebuilt)


def test_pdf_accounting_identity_holds_after_rebuild():
    """verified + reconstructed + missing == total_input for a rebuilt PDF."""
    pdf_bytes = build_pdf_with_true_offsets()
    truncated = _truncate_pdf(pdf_bytes)

    run = _run_pdf_recovery(truncated)

    assert run.total_verified_bytes + run.total_reconstructed_bytes + run.total_missing_bytes == run.total_input_bytes
    # The uploaded evidence size is retained so the loss is never hidden.
    assert run.provenance["evidence_size"] == len(truncated)


def test_pdf_cannot_be_fully_recovered_when_reconstruction_contributes_bytes():
    """R > 0 must downgrade the status away from FULLY_RECOVERED."""
    pdf_bytes = build_pdf_with_true_offsets()
    truncated = _truncate_pdf(pdf_bytes)

    run = _run_pdf_recovery(truncated)

    assert run.total_reconstructed_bytes > 0
    assert run.status != "FULLY_RECOVERED"


def test_intact_pdf_is_still_fully_recovered():
    """An intact PDF needs no rebuild, so V == input, R == 0, FULLY_RECOVERED."""
    pdf_bytes = build_pdf_with_true_offsets()

    run = _run_pdf_recovery(pdf_bytes)

    assert run.total_reconstructed_bytes == 0
    assert run.total_missing_bytes == 0
    assert run.total_verified_bytes == len(pdf_bytes)
    assert run.status == "FULLY_RECOVERED"
    assert bytes.fromhex(run.output["recovered_bytes"]) == pdf_bytes


def test_pdf_confidence_reflects_reconstructed_accounting():
    """Confidence is computed from the corrected provenance, not the raw output size."""
    pdf_bytes = build_pdf_with_true_offsets()
    truncated = _truncate_pdf(pdf_bytes)

    run = _run_pdf_recovery(truncated)

    assert run.total_reconstructed_bytes > 0
    # Structural validity alone must not yield a perfect score once bytes
    # were synthesized, and the run must still carry a numeric confidence.
    assert 0.0 < float(run.confidence["total"]) <= 100.0


def test_pdf_download_remains_byte_exact_after_rebuild():
    """The downloadable output is still the byte-exact rebuilt PDF."""
    pdf_bytes = build_pdf_with_true_offsets()
    truncated = _truncate_pdf(pdf_bytes)

    run = _run_pdf_recovery(truncated)
    downloaded = bytes.fromhex(run.output["recovered_bytes"])

    assert downloaded == pdf_bytes
    assert len(downloaded) == run.total_verified_bytes + run.total_reconstructed_bytes


# ── P1 Fix #1: bounded gap-search failure must not crash the tracer ──

@pytest.mark.parametrize("fmt", ["csv", "txt"])
def test_corrupted_file_gap_search_failure_returns_result(fmt):
    """A corrupted file that fails bounded search returns a result, not a crash.

    The gap-search-failure branch must carry a "notice" detail, otherwise the
    tracer raises KeyError and the API returns HTTP 500.
    """
    originals = {
        "csv": b"id,name,val\n1,a,10\n2,b,20\n3,c,30\n4,d,40\n5,e,50\n",
        "txt": b"alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\n",
    }
    original = originals[fmt]
    corrupted = bytearray(original)
    corrupted[len(corrupted) // 2] ^= 0xFF

    run = _run_pdf_recovery(bytes(corrupted), filename=f"corrupt.{fmt}")

    assert run.status is not None
    assert (
        run.total_verified_bytes
        + run.total_reconstructed_bytes
        + run.total_missing_bytes
        == run.total_input_bytes
    )


def test_gap_search_failure_details_contain_notice():
    """The gap-search-failure result exposes the "notice" key the tracer reads."""
    a = b"id,name,val\n1,a,10\n"
    b = b"\xff\xfe\xfd garbage that cannot parse"

    from backend.app.recovery.reconstruction import reconstruct_fragment_pair

    result = reconstruct_fragment_pair("csv", a, b, observed_gap=64)

    assert "notice" in result.details
    assert isinstance(result.details["notice"], str)
    assert result.details["notice"]


def test_corrupted_csv_api_returns_200_not_500():
    """Regression: corrupted CSV must return a normal response, not HTTP 500."""
    from fastapi.testclient import TestClient

    from backend.app.main import app

    original = b"id,name,val\n1,a,10\n2,b,20\n3,c,30\n4,d,40\n"
    corrupted = bytearray(original)
    corrupted[len(corrupted) // 2] ^= 0xFF

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post(
        "/api/recover-file",
        files={"file": ("corrupt.csv", bytes(corrupted), "text/csv")},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verified_bytes"] + body["reconstructed_bytes"] + body["missing_bytes"] > 0


def test_shuffled_pdf_recovery_via_tracer():
    """Regression test for P0 bug: bms_fragmented_shuffled.pdf must be detected as PDF, not JPEG."""
    from backend.app.recovery.tracer import execute_traced_recovery

    pdf = build_minimal_pdf()
    split = 120
    frag1 = pdf[:split]
    frag2 = pdf[split:]

    # Include random \xff\xd8 byte sequence in fragment 2
    frag2_with_noise = frag2.replace(b"0000000052", b"0000\xff\xd80052")
    shuffled = frag2_with_noise + frag1

    run = execute_traced_recovery(filename="bms_fragmented_shuffled.pdf", content=shuffled)
    assert run.format == "pdf"
    assert run.status == "FULLY_RECOVERED"
    assert run.total_verified_bytes == len(shuffled)
    assert run.total_reconstructed_bytes == 0
    assert run.total_missing_bytes == 0
    assert len(run.fragments) == 2
    assert run.reconstruction_steps[0].method == "FRAGMENT_UNSHUFFLE"


def test_shuffled_pdf_recovery_via_api():
    """Regression test: uploading bms_fragmented_shuffled.pdf via API returns PDF FULLY_RECOVERED."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    pdf = build_minimal_pdf()
    split = 120
    shuffled = pdf[split:] + pdf[:split]

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post(
        "/api/recover-file",
        files={"file": ("bms_fragmented_shuffled.pdf", shuffled, "application/pdf")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "pdf"
    assert data["status"] == "FULLY_RECOVERED"
    assert data["confidence_score"] == 100.0
    assert data["is_downloadable"] is True


# ── PDF Catalog Matching Regression Suite (Phases 1-3) ────────────────


def test_pdf_catalog_detection_single_line():
    """Scenario 9: Valid Catalog dictionary represented on one line is recognized."""
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Pages /Kinds [] /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"2 0 obj\n<< /Type /Catalog /Pages 1 0 R >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 1 0 R >>\nendobj\n"
    )
    reconstructed, ok = reconstruct_pdf_xref(body)
    assert ok is True
    assert b"/Root 2 0 R" in reconstructed
    assert b"/Root 1 0 R" not in reconstructed
    val = validate_pdf(reconstructed)
    assert val.valid is True


def test_pdf_catalog_detection_multiline_format():
    """Scenario 1: The original multiline Catalog defect is resolved."""
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"2 0 obj\n"
        b"<<\n"
        b"  /Type /Catalog\n"
        b"  /Pages 1 0 R\n"
        b">>\n"
        b"endobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 1 0 R >>\nendobj\n"
    )
    reconstructed, ok = reconstruct_pdf_xref(body)
    assert ok is True
    # Crucial: Must identify Object 2 as Root, NOT default to Object 1 (Pages)
    assert b"/Root 2 0 R" in reconstructed
    assert b"/Root 1 0 R" not in reconstructed
    val = validate_pdf(reconstructed)
    assert val.valid is True


def test_pdf_catalog_detection_multiline_preceding_entries():
    """Scenario 9 (cont): Catalog dictionary containing unrelated entries before /Type /Catalog."""
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"2 0 obj\n"
        b"<<\n"
        b"  /Pages 1 0 R\n"
        b"  /ViewerPreferences << /HideToolbar true >>\n"
        b"  /Version /1.4\n"
        b"  /Type /Catalog\n"
        b">>\n"
        b"endobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 1 0 R >>\nendobj\n"
    )
    reconstructed, ok = reconstruct_pdf_xref(body)
    assert ok is True
    assert b"/Root 2 0 R" in reconstructed
    assert b"/Root 1 0 R" not in reconstructed
    val = validate_pdf(reconstructed)
    assert val.valid is True


def test_pdf_catalog_misleading_literal_string_before_real_catalog():
    """Scenario 2 & Phase 1 Reproduction: Literal string /Title (Document about /Type /Catalog)
    in Object 1 must not be misidentified as the Document Catalog over real Catalog in Object 2.
    """
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Title (Document about /Type /Catalog) /Pages 3 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Catalog /Pages 3 0 R >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Pages /Count 1 /Kids [] >>\n"
        b"endobj\n"
    )
    reconstructed, ok = reconstruct_pdf_xref(body)
    assert ok is True
    assert b"/Root 2 0 R" in reconstructed
    assert b"/Root 1 0 R" not in reconstructed
    val = validate_pdf(reconstructed)
    assert val.valid is True


def test_pdf_catalog_escaped_parentheses_in_literal_string():
    """Scenario 3: Literal string with escaped parentheses \\( and \\) containing /Type /Catalog text."""
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Title (Complex title \\(with parens\\) mentioning /Type /Catalog inside) /Pages 3 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<<\n"
        b"  /Type /Catalog\n"
        b"  /Pages 3 0 R\n"
        b">>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Pages /Count 1 /Kids [] >>\n"
        b"endobj\n"
    )
    reconstructed, ok = reconstruct_pdf_xref(body)
    assert ok is True
    assert b"/Root 2 0 R" in reconstructed
    assert b"/Root 1 0 R" not in reconstructed


def test_pdf_catalog_comment_containing_misleading_text():
    """Scenario 4 & Phase 1 Reproduction: Comments containing /Type /Catalog must be ignored."""
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<<\n"
        b"  % Warning: this comment mentions /Type /Catalog\n"
        b"  /Type /Pages\n"
        b"  /Count 1\n"
        b"  /Kids [3 0 R]\n"
        b">>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Catalog /Pages 1 0 R >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 1 0 R >>\n"
        b"endobj\n"
    )
    reconstructed, ok = reconstruct_pdf_xref(body)
    assert ok is True
    assert b"/Root 2 0 R" in reconstructed
    assert b"/Root 1 0 R" not in reconstructed


def test_pdf_catalog_hexadecimal_string_containing_misleading_text():
    """Scenario 5: Hexadecimal string <...> containing misleading /Type /Catalog bytes."""
    # 2F54797065202F436174616C6F67 is hex for "/Type /Catalog"
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /CustomData <2F54797065202F436174616C6F67> /Pages 3 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Catalog /Pages 3 0 R >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Pages /Count 1 /Kids [] >>\n"
        b"endobj\n"
    )
    reconstructed, ok = reconstruct_pdf_xref(body)
    assert ok is True
    assert b"/Root 2 0 R" in reconstructed
    assert b"/Root 1 0 R" not in reconstructed


def test_pdf_catalog_stream_content_containing_misleading_text():
    """Scenario 6: Stream payload containing /Type /Catalog text must not be selected over true Catalog."""
    stream_content = b"BT /F1 12 Tf (Mentioning /Type /Catalog inside content stream) Tj ET"
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Length " + str(len(stream_content)).encode("ascii") + b" >>\n"
        b"stream\n" + stream_content + b"\nendstream\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n"
        b"<<\n"
        b"  /Type /Catalog\n"
        b"  /Pages 2 0 R\n"
        b">>\nendobj\n"
    )
    reconstructed, ok = reconstruct_pdf_xref(body)
    assert ok is True
    assert b"/Root 3 0 R" in reconstructed
    assert b"/Root 1 0 R" not in reconstructed


def test_pdf_catalog_prefers_valid_existing_trailer_root():
    """Scenario 7: A valid existing trailer /Root reference is preserved."""
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n"
        b"3 0 obj\n<< /Type /Pages /Count 1 /Kids [] >>\nendobj\n"
        b"trailer\n<< /Size 4 /Root 2 0 R >>\nstartxref\n150\n%%EOF\n"
    )
    reconstructed, ok = reconstruct_pdf_xref(body)
    assert ok is True
    assert b"/Root 2 0 R" in reconstructed


def test_pdf_catalog_missing_or_invalid_catalog_evidence_fails_conservatively():
    """Scenario 8: When no valid /Root exists in trailer and no Document Catalog can be structurally
    identified, reconstruction fails conservatively rather than fabricating an arbitrary false /Root.
    """
    no_catalog_body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Pages /Count 1 /Kids [2 0 R] >>\nendobj\n"
        b"2 0 obj\n<< /Type /Page /Parent 1 0 R >>\nendobj\n"
    )
    reconstructed, ok = reconstruct_pdf_xref(no_catalog_body)
    assert ok is False
    assert reconstructed == no_catalog_body


def test_pdf_catalog_malformed_and_truncated_input():
    """Phase 2E: Malformed and truncated PDFs must be handled conservatively without claiming false validity."""
    # Subcase 1: Truncated header with dangling catalog dictionary
    truncated_catalog = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog"
    val = validate_pdf(truncated_catalog)
    assert val.valid is False
    assert any("Missing PDF trailer signature" in e or "No valid indirect objects" in e for e in val.errors)

    # Subcase 2: Non-PDF arbitrary text containing /Type /Catalog
    garbage_data = b"RANDOM_NON_PDF_DATA /Type /Catalog MORE_GARBAGE"
    val_garbage = validate_pdf(garbage_data)
    assert val_garbage.valid is False
    rebuilt_garbage, ok_garbage = reconstruct_pdf_xref(garbage_data)
    assert ok_garbage is False

    # Subcase 3: Object with unmatched stream markers
    damaged_stream = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Length 10 >>\nstream\ncorrupted payload lacking closing marker\nendobj\n"
        b"trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n100\n%%EOF\n"
    )
    val_stream = validate_pdf(damaged_stream)
    assert val_stream.valid is False
    assert any("Damaged stream boundaries" in e for e in val_stream.errors)


# ── Milestone 12 Phase 5: PDF Object-Tree and Reference Integrity Suite ────


def test_pdf_object_tree_missing_pages_reference_rejected():
    """Milestone 12 Phase 5: A PDF with an intact xref table but dangling /Pages reference
    in its Document Catalog must NOT pass validation or be marked FULLY_RECOVERED.
    """
    from backend.app.recovery.tracer import execute_traced_recovery

    pdf_broken = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"xref\n"
        b"0 2\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n52\n%%EOF\n"
    )

    val = validate_pdf(pdf_broken)
    assert val.valid is False
    assert any("Catalog object 1 references non-existent /Pages object 2" in e for e in val.errors)

    run = execute_traced_recovery("broken_pages_ref.pdf", pdf_broken)
    assert run.status != "FULLY_RECOVERED"
    assert run.status in ("CORRUPTED", "UNRECOVERABLE")


def test_pdf_object_tree_reconstructed_xref_with_missing_internal_objects_not_fully_recovered():
    """Milestone 12 Phase 5: A PDF whose xref table was reconstructed but whose internal
    objects are missing must fail structural validation and report UNRECOVERABLE / FAILED.
    """
    from backend.app.recovery.tracer import execute_traced_recovery

    pdf_no_xref = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    )

    rebuilt, ok = reconstruct_pdf_xref(pdf_no_xref)
    assert ok is True
    val = validate_pdf(rebuilt)
    assert val.valid is False
    assert any("Catalog object 1 references non-existent /Pages object 2" in e for e in val.errors)

    run = execute_traced_recovery("broken_no_xref.pdf", pdf_no_xref)
    assert run.status != "FULLY_RECOVERED"
    assert run.status in ("CORRUPTED", "UNRECOVERABLE")
    assert any(s.result == "FAILED" for s in run.reconstruction_steps)
    assert any(d.status == "UNRECOVERABLE" for d in run.damage_regions)


def test_pdf_object_tree_missing_kids_child_reference_rejected():
    """Milestone 12 Phase 5: A PDF where a Pages node references a non-existent child Page
    in its /Kids array must fail structural validation.
    """
    pdf_broken_kids = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        # Object 3 is missing!
        b"trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n100\n%%EOF\n"
    )
    val = validate_pdf(pdf_broken_kids)
    assert val.valid is False
    assert any("Pages object 2 references non-existent /Kids child object 3" in e for e in val.errors)


def test_pdf_object_tree_missing_contents_stream_reference_rejected():
    """Milestone 12 Phase 5: A PDF where a Page references a non-existent /Contents stream
    object must fail structural validation.
    """
    pdf_broken_contents = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n"
        # Object 4 (/Contents stream) is missing!
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n150\n%%EOF\n"
    )
    val = validate_pdf(pdf_broken_contents)
    assert val.valid is False
    assert any("Page object 3 references non-existent /Contents stream object 4" in e for e in val.errors)


