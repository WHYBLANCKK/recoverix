"""tests/test_bifragment_candidate_isolation.py — Regression tests for bifragment candidate isolation.

Verifies:
1. Negative control: Two independent truncated PNG candidates in raw evidence are NOT paired as a bifragment.
   Each produces an independent RecoveryRun without swallowing the other.
2. Negative control: Two independent truncated JPEG candidates in raw evidence are NOT paired as a bifragment.
   Each produces an independent RecoveryRun without swallowing the other.
3. Negative control: Two independent truncated text candidates in blind mode are NOT paired as a bifragment.
4. Negative control: Two independent truncated PDF candidates are NOT paired as a bifragment.
5. Positive control: Authentic XML bifragment with resolvable gap is successfully paired and reconstructed.
6. Positive control: Authentic text bifragment in known_file mode is paired and preserves ambiguity.
7. Candidate coordinate isolation: Unpaired candidates maintain distinct physical boundaries and offsets.
"""

from __future__ import annotations

import pytest

from backend.app.recovery.scanner import Candidate, scan_evidence
from backend.app.recovery.tracer import execute_traced_recoveries
from tests.test_validators import _make_png_bytes, _make_jpeg_bytes
from tests.test_pdf_recovery import build_minimal_pdf


# ── 1. Two independent truncated PNGs ─────────────────────────────────────────

def test_01_two_independent_truncated_pngs_not_paired():
    """Two independent truncated PNGs in raw evidence produce 2 distinct recovery runs, not 1 fake bifragment."""
    # Build two separate truncated PNGs (strip IEND chunk from both)
    png1 = _make_png_bytes(width=8, height=8)[:-12]
    png2 = _make_png_bytes(width=16, height=16)[:-12]
    gap = b"\x00" * 200
    evidence = png1 + gap + png2

    runs = execute_traced_recoveries("dump_evidence.raw", evidence, detection_mode="blind")

    # Must produce exactly 2 recovery runs, not 1 merged bifragment run
    png_runs = [r for r in runs if r.format == "png"]
    assert len(png_runs) == 2, f"Expected 2 separate PNG runs, got {len(png_runs)}"

    r0, r1 = png_runs[0], png_runs[1]
    assert r0.candidate_id == "cand-0"
    assert r1.candidate_id == "cand-1"

    # Neither run is flagged as a bifragment pair
    assert not r0.provenance.get("bifragment_offsets")
    assert not r1.provenance.get("bifragment_offsets")

    # Offsets and spans are isolated
    assert r0.provenance["evidence_start"] == 0
    assert r1.provenance["evidence_start"] == len(png1) + len(gap)


# ── 2. Two independent truncated JPEGs ────────────────────────────────────────

def test_02_two_independent_truncated_jpegs_not_paired():
    """Two independent truncated JPEGs in raw evidence produce 2 distinct recovery runs, not 1 fake bifragment."""
    # Build two separate truncated JPEGs (strip EOI marker from both)
    jpg1 = _make_jpeg_bytes(width=8, height=8)[:-2]
    jpg2 = _make_jpeg_bytes(width=16, height=16)[:-2]
    gap = b"\x00" * 200
    evidence = jpg1 + gap + jpg2

    runs = execute_traced_recoveries("dump_evidence.raw", evidence, detection_mode="blind")

    jpeg_runs = [r for r in runs if r.format == "jpeg"]
    assert len(jpeg_runs) == 2, f"Expected 2 separate JPEG runs, got {len(jpeg_runs)}"

    r0, r1 = jpeg_runs[0], jpeg_runs[1]
    assert r0.candidate_id == "cand-0"
    assert r1.candidate_id == "cand-1"

    assert not r0.provenance.get("bifragment_offsets")
    assert not r1.provenance.get("bifragment_offsets")
    assert r0.provenance["evidence_start"] == 0
    assert r1.provenance["evidence_start"] == len(jpg1) + len(gap)


# ── 3. Two independent text candidates in blind mode ──────────────────────────

def test_03_two_independent_text_candidates_in_blind_mode_not_paired():
    """Unbounded text candidates in blind mode are not automatically combined into a bifragment."""
    cand1 = Candidate(
        candidate_id="txt-cand-0",
        format="txt",
        mime_type="text/plain",
        category="text",
        offset=0,
        detected_header_length=0,
        estimated_end_offset=None,
        detection_method="text_run",
    )
    cand2 = Candidate(
        candidate_id="txt-cand-1",
        format="txt",
        mime_type="text/plain",
        category="text",
        offset=250,
        detected_header_length=0,
        estimated_end_offset=None,
        detection_method="text_run",
    )
    text1 = b"Host: audit-server-alpha\nStatus: Operational\n" * 3
    gap = b"\x00" * (250 - len(text1))
    text2 = b"Host: backup-storage-beta\nStatus: Degraded\n" * 3
    evidence = text1 + gap + text2

    runs = execute_traced_recoveries(
        "evidence_dump.bin",
        evidence,
        candidates=[cand1, cand2],
        detection_mode="blind",
    )

    txt_runs = [r for r in runs if r.format == "txt"]
    assert len(txt_runs) == 2, f"Expected 2 separate text runs in blind mode, got {len(txt_runs)}"
    assert not txt_runs[0].provenance.get("bifragment_offsets")
    assert not txt_runs[1].provenance.get("bifragment_offsets")


# ── 4. Two independent truncated PDFs ─────────────────────────────────────────

def test_04_two_independent_truncated_pdfs_not_paired():
    """Two independent truncated PDFs with no EOF in raw evidence produce distinct runs."""
    pdf1 = build_minimal_pdf()[:-10]  # Strip %%EOF
    pdf2 = build_minimal_pdf()[:-10]  # Strip %%EOF
    gap = b"\x00" * 128
    evidence = pdf1 + gap + pdf2

    cand1 = Candidate(
        candidate_id="pdf-cand-0",
        format="pdf",
        mime_type="application/pdf",
        category="document",
        offset=0,
        detected_header_length=8,
        estimated_end_offset=None,
        detection_method="magic_bytes",
    )
    offset2 = len(pdf1) + len(gap)
    cand2 = Candidate(
        candidate_id="pdf-cand-1",
        format="pdf",
        mime_type="application/pdf",
        category="document",
        offset=offset2,
        detected_header_length=8,
        estimated_end_offset=None,
        detection_method="magic_bytes",
    )

    runs = execute_traced_recoveries(
        "forensic_dump.raw",
        evidence,
        candidates=[cand1, cand2],
        detection_mode="blind",
    )

    pdf_runs = [r for r in runs if r.format == "pdf"]
    assert len(pdf_runs) == 2, f"Expected 2 distinct PDF runs, got {len(pdf_runs)}"
    assert not pdf_runs[0].provenance.get("bifragment_offsets")
    assert not pdf_runs[1].provenance.get("bifragment_offsets")


# ── 5. Positive control: Authentic XML bifragment reconstruction ──────────────

def test_05_authentic_xml_bifragment_successfully_paired():
    """Authentic XML split document with resolvable gap is successfully paired and reconstructed."""
    cand1 = b'<?xml version="1.0"?><root><item>Head section of document.</item><!-- '
    gap = b"\x00" * 32
    cand2 = b'<?xml --> <item>Tail section of document.</item></root>'
    content = cand1 + gap + cand2

    runs = execute_traced_recoveries("bifragment.xml", content, detection_mode="known_file")

    xml_runs = [r for r in runs if r.format == "xml"]
    assert len(xml_runs) == 1, "Authentic XML bifragment must be paired into a single run"

    run = xml_runs[0]
    assert run.status == "PARTIALLY_RECOVERED"
    assert run.provenance.get("bifragment_offsets") == [0, len(cand1) + len(gap)]
    assert len(run.reconstruction_steps) >= 1
    assert run.reconstruction_steps[0].result == "SUCCESS"


# ── 6. Positive control: Authentic text bifragment in known_file mode ─────────

def test_06_authentic_text_bifragment_in_known_file_mode_paired():
    """Authentic text bifragment in known_file mode is paired and preserves ambiguity."""
    frag_a = b"First line of log\nSecond line of log\n"
    gap = b"\x00" * 30
    frag_b = b"Third line of log\nFourth line of log\n"
    content = frag_a + gap + frag_b

    runs = execute_traced_recoveries("server.txt", content, detection_mode="known_file")

    txt_runs = [r for r in runs if r.format == "txt"]
    assert len(txt_runs) >= 1
    run = txt_runs[0]
    assert run.status == "PARTIALLY_RECOVERED"
    assert run.total_missing_bytes == len(gap)
    assert len(run.fragments) == 2
    assert run.fragments[0].offset == 0
    assert run.fragments[1].offset == len(frag_a) + len(gap)


# ── 7. Candidate coordinate isolation ─────────────────────────────────────────

def test_07_candidate_coordinate_isolation_preserves_bounds():
    """Unpaired candidates correctly bound their search limits and do not claim downstream bytes."""
    png1 = _make_png_bytes(width=8, height=8)[:-12]
    png2 = _make_png_bytes(width=16, height=16)[:-12]
    gap = b"\x00" * 150
    evidence = png1 + gap + png2

    runs = execute_traced_recoveries("raw_disk.img", evidence, detection_mode="blind")

    png_runs = [r for r in runs if r.format == "png"]
    assert len(png_runs) == 2

    r0 = png_runs[0]
    r1 = png_runs[1]

    # Candidate 0 input bytes cannot swallow Candidate 1
    assert r0.total_input_bytes <= len(png1) + len(gap)
    assert r1.provenance["evidence_start"] == len(png1) + len(gap)
