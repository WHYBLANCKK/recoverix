"""
test_scanner.py — Tests for the Recoverix format-signature scanner.

Covers: TXT detection, CSV detection, PNG detection, multiple candidates,
correct offsets, correct MIME/category, malformed/truncated markers,
no-match evidence, empty evidence, determinism, boundary-at-zero,
boundary-at-end, input immutability, overlapping/duplicate markers.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure imports work from the project root.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.app.recovery.signatures import (
    FormatSignature,
    SIGNATURES,
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
    PNG_SIGNATURE,
)
from backend.app.recovery.scanner import (
    Candidate,
    scan_evidence,
    _classify_synthetic_content,
)


# ── Helpers ─────────────────────────────────────────────────────────

def _make_txt_artifact(body_lines: list[str]) -> bytes:
    """Build a synthetic TXT artifact matching generator conventions."""
    lines = [
        "[SYNTHETIC_ARTIFACT_START]",
        "filename: test.txt",
        *body_lines,
        "[SYNTHETIC_ARTIFACT_END]",
    ]
    return "\n".join(lines).encode("utf-8")


def _make_csv_artifact(rows: list[list[str]]) -> bytes:
    """Build a synthetic CSV artifact matching generator conventions."""
    lines = ["[SYNTHETIC_ARTIFACT_START]"]
    for row in rows:
        lines.append(",".join(row))
    lines.append("[SYNTHETIC_ARTIFACT_END]")
    return "\n".join(lines).encode("utf-8")


def _make_png_stub(extra: bytes = b"") -> bytes:
    """Build minimal PNG-signature bytes (no valid chunks)."""
    return PNG_SIGNATURE + extra


# ── 1. TXT candidate detection ─────────────────────────────────────

def test_txt_candidate_detection():
    artifact = _make_txt_artifact(["line: hello"])
    padding = b"\x00" * 100
    evidence = padding + artifact + padding

    candidates = scan_evidence(evidence)

    assert len(candidates) == 1
    c = candidates[0]
    assert c.format == "txt"
    assert c.mime_type == "text/plain"
    assert c.category == "text"
    assert c.offset == 100
    assert c.detection_method == "synthetic_boundary"
    assert c.detected_header_length == len(SYNTHETIC_START_MARKER)


# ── 2. CSV candidate detection ─────────────────────────────────────

def test_csv_candidate_detection():
    artifact = _make_csv_artifact([["col1", "col2"], ["a", "b"]])
    padding = b"\x00" * 50
    evidence = padding + artifact

    candidates = scan_evidence(evidence)

    assert len(candidates) == 1
    c = candidates[0]
    assert c.format == "csv"
    assert c.mime_type == "text/csv"
    assert c.category == "text"
    assert c.offset == 50


# ── 3. PNG signature detection ─────────────────────────────────────

def test_png_signature_detection():
    png = _make_png_stub(b"\x00" * 64)
    padding = b"\xff" * 200
    evidence = padding + png

    candidates = scan_evidence(evidence)

    assert len(candidates) == 1
    c = candidates[0]
    assert c.format == "png"
    assert c.mime_type == "image/png"
    assert c.category == "image"
    assert c.offset == 200
    assert c.detected_header_length == len(PNG_SIGNATURE)
    assert c.estimated_end_offset is None  # no PNG parser
    assert c.detection_method == "magic_bytes"


# ── 4. Multiple candidates ─────────────────────────────────────────

def test_multiple_candidates():
    txt = _make_txt_artifact(["data: value"])
    csv = _make_csv_artifact([["x", "y"]])
    png = _make_png_stub()
    gap = b"\x00" * 64

    evidence = txt + gap + csv + gap + png

    candidates = scan_evidence(evidence)

    assert len(candidates) == 3
    formats = [c.format for c in candidates]
    assert "txt" in formats
    assert "csv" in formats
    assert "png" in formats

    # Offsets must be strictly increasing (sorted).
    offsets = [c.offset for c in candidates]
    assert offsets == sorted(offsets)


# ── 5. Correct offsets ──────────────────────────────────────────────

def test_correct_offsets():
    txt = _make_txt_artifact(["key: val"])
    offset = 256
    evidence = b"\x00" * offset + txt

    candidates = scan_evidence(evidence)

    assert len(candidates) == 1
    assert candidates[0].offset == offset


# ── 6. Correct estimated_end_offset for synthetic markers ──────────

def test_estimated_end_offset_synthetic():
    artifact = _make_txt_artifact(["data: 123"])
    evidence = artifact + b"\x00" * 50

    candidates = scan_evidence(evidence)

    assert len(candidates) == 1
    c = candidates[0]
    assert c.estimated_end_offset is not None
    # The end offset should be right after [SYNTHETIC_ARTIFACT_END].
    assert c.estimated_end_offset == len(artifact)


# ── 7. Correct MIME type and category ───────────────────────────────

def test_mime_and_category():
    txt = _make_txt_artifact(["x: 1"])
    csv = _make_csv_artifact([["a", "b"]])
    png = _make_png_stub()

    for data, fmt, mime, cat in [
        (txt, "txt", "text/plain", "text"),
        (csv, "csv", "text/csv", "text"),
        (png, "png", "image/png", "image"),
    ]:
        candidates = scan_evidence(data)
        assert len(candidates) >= 1
        c = candidates[0]
        assert c.format == fmt, f"Expected format {fmt}, got {c.format}"
        assert c.mime_type == mime
        assert c.category == cat


# ── 8. Malformed / truncated start marker ───────────────────────────

def test_truncated_start_marker():
    """A partial start marker should not be detected."""
    evidence = b"[SYNTHETIC_ARTIFACT_STA" + b"\x00" * 100
    candidates = scan_evidence(evidence)
    assert len(candidates) == 0


# ── 9. Start marker without end marker (truncated artifact) ────────

def test_start_without_end_marker():
    """A start marker with no end marker → estimated_end_offset is None."""
    evidence = SYNTHETIC_START_MARKER + b"\nfilename: orphan.txt\ndata: hello"

    candidates = scan_evidence(evidence)

    assert len(candidates) == 1
    c = candidates[0]
    assert c.offset == 0
    assert c.estimated_end_offset is None
    assert c.format == "txt"


# ── 10. No signatures found ────────────────────────────────────────

def test_no_match():
    evidence = b"\xde\xad\xbe\xef" * 1000
    candidates = scan_evidence(evidence)
    assert candidates == []


# ── 11. Empty evidence ─────────────────────────────────────────────

def test_empty_evidence():
    candidates = scan_evidence(b"")
    assert candidates == []


# ── 12. Deterministic repeated scans ───────────────────────────────

def test_determinism():
    txt = _make_txt_artifact(["line: 1"])
    csv = _make_csv_artifact([["a", "b"]])
    png = _make_png_stub()
    evidence = txt + b"\x00" * 32 + csv + b"\x00" * 32 + png

    r1 = scan_evidence(evidence)
    r2 = scan_evidence(evidence)

    assert len(r1) == len(r2)
    for c1, c2 in zip(r1, r2):
        assert c1 == c2


# ── 13. Boundary at offset zero ────────────────────────────────────

def test_boundary_at_zero():
    artifact = _make_txt_artifact(["offset: zero"])
    candidates = scan_evidence(artifact)

    assert len(candidates) == 1
    assert candidates[0].offset == 0


# ── 14. Boundary at final bytes ────────────────────────────────────

def test_boundary_at_end():
    """Signature ending at the very last byte of evidence."""
    padding = b"\x00" * 500
    artifact = _make_txt_artifact(["at: end"])
    evidence = padding + artifact

    candidates = scan_evidence(evidence)

    assert len(candidates) == 1
    c = candidates[0]
    assert c.estimated_end_offset == len(evidence)


# ── 15. Input immutability ──────────────────────────────────────────

def test_input_not_mutated():
    evidence = bytearray(b"\x00" * 100 + _make_txt_artifact(["safe: yes"]))
    original = bytes(evidence)

    scan_evidence(bytes(evidence))

    assert bytes(evidence) == original


# ── 16. Overlapping / duplicate markers ─────────────────────────────

def test_duplicate_markers():
    """Two back-to-back artifacts should produce two candidates."""
    a1 = _make_txt_artifact(["item: one"])
    a2 = _make_csv_artifact([["x", "y"], ["1", "2"]])
    evidence = a1 + a2

    candidates = scan_evidence(evidence)

    assert len(candidates) == 2
    assert candidates[0].format == "txt"
    assert candidates[1].format == "csv"
    assert candidates[0].offset < candidates[1].offset


# ── 17. PNG at offset zero ──────────────────────────────────────────

def test_png_at_offset_zero():
    evidence = _make_png_stub(b"\x00" * 100)
    candidates = scan_evidence(evidence)

    assert len(candidates) == 1
    assert candidates[0].offset == 0
    assert candidates[0].format == "png"


# ── 18. Multiple PNGs ──────────────────────────────────────────────

def test_multiple_pngs():
    gap = b"\x00" * 128
    png1 = _make_png_stub(b"\x01" * 32)
    png2 = _make_png_stub(b"\x02" * 32)
    evidence = png1 + gap + png2

    candidates = scan_evidence(evidence)

    pngs = [c for c in candidates if c.format == "png"]
    assert len(pngs) == 2
    assert pngs[0].offset == 0
    assert pngs[1].offset == len(png1) + len(gap)


# ── 19. Mixed formats interleaved ──────────────────────────────────

def test_mixed_formats():
    txt = _make_txt_artifact(["type: memo"])
    png = _make_png_stub(b"\xAA" * 16)
    csv = _make_csv_artifact([["col1", "col2"], ["v1", "v2"]])
    gap = b"\x00" * 64

    evidence = txt + gap + png + gap + csv

    candidates = scan_evidence(evidence)

    assert len(candidates) == 3
    assert candidates[0].format == "txt"
    assert candidates[1].format == "png"
    assert candidates[2].format == "csv"


# ── 20. Candidate IDs are sequential ───────────────────────────────

def test_candidate_ids_sequential():
    a1 = _make_txt_artifact(["a: 1"])
    a2 = _make_csv_artifact([["x", "y"]])
    evidence = a1 + b"\x00" * 10 + a2

    candidates = scan_evidence(evidence)

    for idx, c in enumerate(candidates):
        assert c.candidate_id == f"cand-{idx}"


# ── 21. Candidate is frozen ────────────────────────────────────────

def test_candidate_is_frozen():
    c = Candidate(
        candidate_id="cand-0",
        format="txt",
        mime_type="text/plain",
        category="text",
        offset=0,
        detected_header_length=25,
        estimated_end_offset=100,
        detection_method="synthetic_boundary",
    )
    with pytest.raises(AttributeError):
        c.offset = 999  # type: ignore[misc]


# ── 22. FormatSignature is frozen ──────────────────────────────────

def test_signature_is_frozen():
    sig = SIGNATURES[0]
    with pytest.raises(AttributeError):
        sig.format = "jpg"  # type: ignore[misc]


# ── 23. Registry contains expected formats ─────────────────────────

def test_registry_contents():
    formats = {s.format for s in SIGNATURES}
    assert formats == {"txt", "csv", "json", "xml", "png", "jpeg", "pdf", "zip"}


# ── 24. Content heuristic — TXT classification ─────────────────────

def test_classify_txt():
    body = b"filename: test.txt\ntype: log"
    fmt, mime, cat = _classify_synthetic_content(body)
    assert fmt == "txt"
    assert mime == "text/plain"
    assert cat == "text"


# ── 25. Content heuristic — CSV classification ─────────────────────

def test_classify_csv():
    body = b"col1,col2,col3\na,b,c"
    fmt, mime, cat = _classify_synthetic_content(body)
    assert fmt == "csv"
    assert mime == "text/csv"
    assert cat == "text"


# ── 26. Content heuristic — empty body defaults to TXT ─────────────

def test_classify_empty_body():
    fmt1, _, _ = _classify_synthetic_content(b"")
    assert fmt1 == "txt"
    fmt2, _, _ = _classify_synthetic_content(b"\n\n")
    assert fmt2 == "txt"


# ── 27. Huge irrelevant evidence ───────────────────────────────────

def test_huge_irrelevant_bytes():
    """Scanner handles large evidence with no signatures."""
    evidence = b"\xAB" * 100_000
    candidates = scan_evidence(evidence)
    assert candidates == []


# ── 28. End marker without start marker ────────────────────────────

def test_end_marker_without_start():
    """A lone end marker should not produce a candidate."""
    evidence = b"\x00" * 50 + SYNTHETIC_END_MARKER + b"\x00" * 50
    candidates = scan_evidence(evidence)
    assert candidates == []


# ── 29. PNG signature too short (truncated at evidence end) ────────

def test_png_signature_truncated():
    """If not enough bytes remain for the full PNG signature, skip it."""
    evidence = PNG_SIGNATURE[:4]  # only half the signature
    candidates = scan_evidence(evidence)
    assert candidates == []


# ── 30. Public API re-exports ──────────────────────────────────────

def test_public_api_reexports():
    from backend.app import recovery

    assert hasattr(recovery, "FormatSignature")
    assert hasattr(recovery, "SIGNATURES")
    assert hasattr(recovery, "Candidate")
    assert hasattr(recovery, "scan_evidence")


# ── 31. Integration with generated evidence ────────────────────────

def test_scan_generated_evidence(tmp_path):
    """Scan a generated evidence image and verify expected candidates."""
    from backend.generate_case import generate_evidence

    generate_evidence(42, tmp_path)
    img = (tmp_path / "damaged.img").read_bytes()

    candidates = scan_evidence(img)

    # The generator creates 6 artifacts:
    #   clean (txt), deleted (csv), fragmented (txt, 3 frags),
    #   bifragment (txt, 2 frags), corrupted (txt), unrecoverable (txt).
    #
    # The scanner finds start markers.  The fragmented artifact has 3
    # fragments — only the first fragment contains the start marker.
    # The bifragment has 2 fragments — only the first contains the start
    # marker.  The corrupted artifact has random bytes overwriting part
    # of it, which may damage the start marker — whether it's detected
    # depends on the corruption offset.  The unrecoverable artifact has
    # only 20% surviving — the start marker should still be there since
    # it's at the beginning.
    #
    # We expect at least the clean, deleted, and unrecoverable start
    # markers, plus possibly fragmented frag-0, bifragment frag-0, and
    # corrupted if undamaged.
    assert len(candidates) >= 3, (
        f"Expected at least 3 candidates, got {len(candidates)}"
    )

    # All candidates should be text type (no PNG in the generator).
    for c in candidates:
        assert c.category == "text"
        assert c.detection_method == "synthetic_boundary"

    # Verify at least TXT and CSV are both detected.
    formats = {c.format for c in candidates}
    assert "txt" in formats, "Expected at least one TXT candidate"
    assert "csv" in formats, "Expected at least one CSV candidate"
