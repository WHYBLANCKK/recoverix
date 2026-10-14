"""
test_multiformat_fragmentation_m317.py — M3.17.0 Multi-Format Fragmented Recovery Regression Suite.

Verifies:
  1. Shuffled (reverse-order) PDF recovery with intervening gap correctly bounds trailer,
     reconstructs original bytes with SHA-256 match, accounts gap as MISSING damage,
     and evaluates status as PARTIALLY_RECOVERED.
  2. Clean shuffled PDF without gap recovers as FULLY_RECOVERED.
  3. Contiguous candidate validation failures across formats (PNG, JPEG, XML) yield
     UNRECOVERABLE status with 0 verified bytes, missing_bytes == evidence_length,
     and empty recovered_bytes.
  4. Bifragment candidate pairing cleanly isolates downstream candidate boundaries.
  5. Unsupported formats (ZIP, DOCX) are not falsely recognized or hallucinated.
  6. PDF completeness and validator end_offset accurately detect trailing noise/gap.
"""

from __future__ import annotations

import hashlib
import pytest

from backend.app.recovery.scanner import scan_evidence, Candidate
from backend.app.recovery.tracer import execute_traced_recovery, execute_traced_recoveries
from backend.app.recovery.validators.pdf import validate_pdf
from backend.app.recovery.completeness import assess_artifact_completeness
from backend.app.recovery.signatures import (
    PNG_SIGNATURE,
    JPEG_SOI,
    JPEG_EOI,
    PDF_HEADER_SIGNATURE,
    PDF_TRAILER_SIGNATURE,
    XML_HEADER_SIGNATURE,
)
from tests.test_pdf_recovery import build_minimal_pdf


# ── 1. Shuffled PDF with Intervening Gap ─────────────────────────────────────

def test_shuffled_pdf_with_intervening_gap_bounds_trailer_and_preserves_bytes():
    """Shuffled PDF with 5KB intervening gap bounds trailer at %%EOF, does not swallow gap,
    produces exact payload hash match, records gap as MISSING damage, and reports PARTIALLY_RECOVERED."""
    pdf = build_minimal_pdf()
    split = 120
    header_frag = pdf[:split]
    trailer_frag = pdf[split:]
    expected_hash = hashlib.sha256(pdf).hexdigest()

    # Fragment 1 (trailer) at physical offset 0
    # Intervening gap of 5000 unallocated zero bytes
    # Fragment 0 (header) starting at physical offset len(trailer_frag) + 5000
    gap_len = 5000
    gap_bytes = b"\x00" * gap_len
    content = trailer_frag + gap_bytes + header_frag

    cand_offset = len(trailer_frag) + gap_len
    run = execute_traced_recovery("shuffled_gap.pdf", content, detection_mode="blind")

    # Invariants
    assert run.format == "pdf"
    assert run.status == "PARTIALLY_RECOVERED"
    assert run.status != "FULLY_RECOVERED"

    # Byte accounting
    assert run.total_verified_bytes == len(pdf)
    assert run.total_missing_bytes == gap_len
    assert run.total_reconstructed_bytes == 0
    assert run.total_verified_bytes + run.total_missing_bytes + run.total_reconstructed_bytes == len(content)

    # Recovered bytes match ground truth exactly (no gap bytes injected)
    recovered_bytes = bytes.fromhex(run.output["recovered_bytes"])
    assert recovered_bytes == pdf
    assert hashlib.sha256(recovered_bytes).hexdigest() == expected_hash

    # Fragment models
    assert len(run.fragments) == 2
    f0 = run.fragments[0]
    f1 = run.fragments[1]
    assert f0.fragment_id == "frag-0"
    assert f0.offset == cand_offset
    assert f0.length == len(header_frag)
    assert f0.verified_bytes == len(header_frag)

    assert f1.fragment_id == "frag-1"
    assert f1.offset == 0
    assert f1.length == len(trailer_frag)
    assert f1.verified_bytes == len(trailer_frag)

    # Damage region records the unallocated gap
    assert len(run.damage_regions) == 1
    dmg = run.damage_regions[0]
    assert dmg.type == "MISSING"
    assert dmg.status == "UNRECOVERABLE"
    assert dmg.start_offset == len(trailer_frag)
    assert dmg.end_offset == cand_offset
    assert dmg.length == gap_len


def test_clean_shuffled_pdf_without_gap_is_fully_recovered():
    """Shuffled PDF with contiguous boundary (gap == 0) recovers as FULLY_RECOVERED."""
    pdf = build_minimal_pdf()
    split = 120
    header_frag = pdf[:split]
    trailer_frag = pdf[split:]
    content = trailer_frag + header_frag

    run = execute_traced_recovery("shuffled_clean.pdf", content, detection_mode="known_file")
    assert run.format == "pdf"
    assert run.status == "FULLY_RECOVERED"
    assert run.total_verified_bytes == len(pdf)
    assert run.total_missing_bytes == 0
    assert run.total_reconstructed_bytes == 0
    assert bytes.fromhex(run.output["recovered_bytes"]) == pdf


# ── 2. Contiguous Candidate Validation Failure Zero-Verification ───────────────

def test_contiguous_corrupt_png_yields_unrecoverable_with_zero_verified_bytes():
    """Contiguous PNG candidate that fails structural validation yields UNRECOVERABLE
    with exactly 0 verified bytes, missing_bytes == candidate length, and empty recovered_bytes."""
    # PNG signature followed by completely corrupt chunk data (missing IHDR, invalid chunks, no IEND)
    corrupt_png = PNG_SIGNATURE + b"\x00\x00\x00\x10BADCHUNKDATA0123456789"
    content = corrupt_png

    cand = Candidate(
        candidate_id="cand-png-corrupt",
        format="png",
        mime_type="image/png",
        category="image",
        offset=0,
        detected_header_length=8,
        estimated_end_offset=len(content),
        detection_method="magic_bytes",
    )

    runs = execute_traced_recoveries("corrupt.png", content, candidates=[cand], detection_mode="blind")
    assert len(runs) == 1
    run = runs[0]

    assert run.status == "UNRECOVERABLE"
    assert run.total_verified_bytes == 0
    assert run.total_missing_bytes == len(content)
    assert run.total_reconstructed_bytes == 0
    assert run.output.get("recovered_bytes") == ""

    assert len(run.fragments) == 1
    f0 = run.fragments[0]
    assert f0.status == "UNRECOVERABLE"
    assert f0.verified_bytes == 0
    assert f0.missing_bytes == len(content)

    assert len(run.damage_regions) >= 1
    assert any(d.status == "UNRECOVERABLE" for d in run.damage_regions)


def test_contiguous_corrupt_jpeg_yields_unrecoverable_with_zero_verified_bytes():
    """Contiguous JPEG candidate with corrupt marker structure yields UNRECOVERABLE
    with exactly 0 verified bytes and missing_bytes == candidate length."""
    # JPEG SOI followed by immediate EOI without any frame headers or tables
    corrupt_jpeg = JPEG_SOI + b"\xff\xff\xff\xff" + JPEG_EOI
    content = corrupt_jpeg

    cand = Candidate(
        candidate_id="cand-jpeg-corrupt",
        format="jpeg",
        mime_type="image/jpeg",
        category="image",
        offset=0,
        detected_header_length=2,
        estimated_end_offset=len(content),
        detection_method="magic_bytes",
    )

    runs = execute_traced_recoveries("corrupt.jpg", content, candidates=[cand], detection_mode="blind")
    assert len(runs) == 1
    run = runs[0]

    assert run.status == "UNRECOVERABLE"
    assert run.total_verified_bytes == 0
    assert run.total_missing_bytes == len(content)
    assert run.total_reconstructed_bytes == 0
    assert run.output.get("recovered_bytes") == ""
    assert run.fragments[0].status == "UNRECOVERABLE"
    assert run.fragments[0].verified_bytes == 0


def test_contiguous_corrupt_xml_yields_unrecoverable_with_zero_verified_bytes():
    """Contiguous XML candidate with broken syntax yields UNRECOVERABLE
    with 0 verified bytes and empty output."""
    corrupt_xml = XML_HEADER_SIGNATURE + b' version="1.0"?><unclosed_tag><broken>'
    content = corrupt_xml

    cand = Candidate(
        candidate_id="cand-xml-corrupt",
        format="xml",
        mime_type="application/xml",
        category="structured",
        offset=0,
        detected_header_length=5,
        estimated_end_offset=len(content),
        detection_method="magic_bytes",
    )

    runs = execute_traced_recoveries("corrupt.xml", content, candidates=[cand], detection_mode="blind")
    assert len(runs) == 1
    run = runs[0]

    assert run.status == "UNRECOVERABLE"
    assert run.total_verified_bytes == 0
    assert run.total_missing_bytes == len(content)
    assert run.output.get("recovered_bytes") == ""


# ── 3. Downstream Candidate Boundary Isolation in Bifragment Pairing ──────────

def test_downstream_candidate_boundary_isolation_after_bifragment():
    """When a 3rd candidate follows a bifragment pair, frag-1 of the pair is bounded
    by Candidate 3's offset and does not swallow Candidate 3's evidence bytes."""
    # Bifragment pair in XML
    frag_a = b'<?xml version="1.0"?><root><item>Fragment A'
    frag_b = b' continuation</item></root>'
    gap = b"\x00" * 16

    cand1_offset = 0
    cand2_offset = len(frag_a) + len(gap)
    cand3_offset = cand2_offset + len(frag_b)

    # 3rd candidate: a standalone text candidate at cand3_offset
    frag_c = b"Plain text log entry following the XML artifact\n"

    content = frag_a + gap + frag_b + frag_c

    cand1 = Candidate(
        candidate_id="cand-xml-1",
        format="xml",
        mime_type="application/xml",
        category="structured",
        offset=cand1_offset,
        detected_header_length=5,
        estimated_end_offset=None,
        detection_method="magic_bytes",
    )
    cand2 = Candidate(
        candidate_id="cand-xml-2",
        format="xml",
        mime_type="application/xml",
        category="structured",
        offset=cand2_offset,
        detected_header_length=5,
        estimated_end_offset=None,
        detection_method="magic_bytes",
    )
    cand3 = Candidate(
        candidate_id="cand-txt-3",
        format="txt",
        mime_type="text/plain",
        category="text",
        offset=cand3_offset,
        detected_header_length=0,
        estimated_end_offset=None,
        detection_method="synthetic_boundary",
    )

    runs = execute_traced_recoveries(
        "evidence.raw",
        content,
        candidates=[cand1, cand2, cand3],
        detection_mode="known_file",
    )

    # Should have 2 runs: the bifragment run, and the subsequent text run
    assert len(runs) == 2

    xml_run = runs[0]
    txt_run = runs[1]

    assert xml_run.format == "xml"
    # Frag 1 of XML run must end exactly at cand3_offset
    frag_1 = xml_run.fragments[1]
    assert frag_1.offset == cand2_offset
    assert frag_1.end_offset == cand3_offset
    assert frag_1.length == len(frag_b)

    # Text run starts cleanly at cand3_offset
    assert txt_run.format == "txt"
    assert txt_run.fragments[0].offset == cand3_offset


# ── 4. Capability Matrix: Unsupported Formats (ZIP, DOCX) ─────────────────────

def test_unsupported_formats_matrix_zip_docx():
    """Scanner correctly returns 0 candidates for ZIP and DOCX format signatures,
    proving Recoverix does not hallucinate support for unhandled container formats."""
    # Standard ZIP Local File Header magic bytes: PK\x03\x04
    zip_bytes = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"dummy file data" + b"PK\x05\x06" + b"\x00" * 18
    cands_zip = scan_evidence(zip_bytes)
    assert not any(c.format in ("zip", "docx") for c in cands_zip)

    # Standard DOCX (ZIP container with [Content_Types].xml)
    docx_bytes = b"PK\x03\x04\x14\x00\x00\x00\x08\x00[Content_Types].xml" + b"\x00" * 100
    cands_docx = scan_evidence(docx_bytes)
    assert not any(c.format in ("zip", "docx") for c in cands_docx)


# ── 5. PDF Completeness and Validator Details ─────────────────────────────────

def test_pdf_completeness_and_validation_end_offset():
    """PDF validator accurately reports end_offset, and completeness assessment rejects
    PDF evidence with trailing unallocated noise."""
    pdf = build_minimal_pdf()

    # Valid intact PDF
    val_clean = validate_pdf(pdf)
    assert val_clean.valid is True
    assert val_clean.details.get("end_offset") == len(pdf.rstrip(b"\r\n\t "))

    assert assess_artifact_completeness("pdf", pdf, "blind") is True
    assert assess_artifact_completeness("pdf", pdf, "known_file") is True

    # PDF with trailing unallocated zero noise
    pdf_with_noise = pdf + b"\x00" * 200
    assert assess_artifact_completeness("pdf", pdf_with_noise, "blind") is False
    assert assess_artifact_completeness("pdf", pdf_with_noise, "known_file") is False
