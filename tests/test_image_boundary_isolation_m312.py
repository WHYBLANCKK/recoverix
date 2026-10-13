"""tests/test_image_boundary_isolation_m312.py — Test suite for Milestone 3.12.0:
PNG/JPEG Boundary Isolation.

Verifies:
1. Single valid PNG candidate bounds (exact estimated_end_offset).
2. Two adjacent valid PNG candidates (isolated boundaries, zero overlap).
3. Truncated PNG followed by valid PNG (candidate 0 does not swallow candidate 1).
4. Truncated PNG + gap + valid PNG: execute_traced_recoveries has no verified-byte inflation.
5. PNG with fake IEND inside IDAT payload is NOT truncated early.
6. PNG with malformed chunk length or truncated chunk header (estimated_end_offset is None).
7. Single valid JPEG candidate bounds (exact estimated_end_offset).
8. Two adjacent valid JPEG candidates (isolated boundaries, zero overlap).
9. Truncated JPEG followed by valid JPEG (candidate 0 does not swallow candidate 1).
10. Truncated JPEG + gap + valid JPEG: execute_traced_recoveries has no verified-byte inflation.
11. JPEG with malformed marker stream / invalid segment length (estimated_end_offset is None).
12. Cross-format: Truncated PNG + gap with JSON + valid PNG (JSON is discovered, not suppressed).
13. Cross-format: Truncated JPEG + gap with JSON + valid JPEG (JSON is discovered, not suppressed).
14. Multi-format composite evidence accounting: V + R + M invariants preserved.
"""

from __future__ import annotations

import struct
import zlib
import pytest

from backend.app.recovery.scanner import scan_evidence
from backend.app.recovery.tracer import execute_traced_recoveries
from tests.test_validators import _make_png_bytes, _make_jpeg_bytes


def _make_png_with_fake_iend_in_idat() -> bytes:
    """Build a valid PNG where the IDAT chunk data contains a literal b'IEND' sequence."""
    png_magic = b"\x89PNG\r\n\x1a\n"

    # IHDR Chunk
    ihdr_data = struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

    # IDAT Chunk with literal b"IEND" in compressed payload
    raw_payload = b"prefix" + b"IEND" + b"suffix_data_12345678"
    idat_crc = zlib.crc32(b"IDAT" + raw_payload) & 0xFFFFFFFF
    idat_chunk = struct.pack(">I", len(raw_payload)) + b"IDAT" + raw_payload + struct.pack(">I", idat_crc)

    # Real IEND Chunk
    iend_crc = zlib.crc32(b"IEND") & 0xFFFFFFFF
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    return png_magic + ihdr_chunk + idat_chunk + iend_chunk


# ── Scenario 1: Single valid PNG candidate bounds ────────────────────────────

def test_01_single_valid_png_bounds():
    """Single valid PNG has exact estimated_end_offset matching its true length."""
    png_data = _make_png_bytes(width=8, height=8)
    padding = b"\x00" * 32
    evidence = padding + png_data + padding

    candidates = scan_evidence(evidence)
    png_cands = [c for c in candidates if c.format == "png"]

    assert len(png_cands) == 1
    cand = png_cands[0]
    assert cand.offset == len(padding)
    assert cand.estimated_end_offset == len(padding) + len(png_data)


# ── Scenario 2: Two adjacent valid PNG candidates ────────────────────────────

def test_02_two_adjacent_valid_pngs():
    """Two adjacent PNGs are isolated: candidate 0 stops at candidate 1 offset with zero overlap."""
    png1 = _make_png_bytes(width=8, height=8)
    png2 = _make_png_bytes(width=16, height=16)
    evidence = png1 + png2

    candidates = scan_evidence(evidence)
    png_cands = [c for c in candidates if c.format == "png"]

    assert len(png_cands) == 2
    c0 = png_cands[0]
    c1 = png_cands[1]

    assert c0.offset == 0
    assert c0.estimated_end_offset == len(png1)
    assert c1.offset == len(png1)
    assert c1.estimated_end_offset == len(evidence)
    assert c0.estimated_end_offset <= c1.offset


# ── Scenario 3: Truncated PNG followed by valid PNG ──────────────────────────

def test_03_truncated_png_followed_by_valid_png():
    """Truncated PNG does not swallow downstream valid PNG; candidate 0 estimated_end_offset is None."""
    full_png = _make_png_bytes(width=8, height=8)
    # Truncate PNG before IEND chunk (drop last 12 bytes)
    trunc_png = full_png[:-12]
    valid_png = _make_png_bytes(width=16, height=16)
    evidence = trunc_png + valid_png

    candidates = scan_evidence(evidence)
    png_cands = [c for c in candidates if c.format == "png"]

    assert len(png_cands) == 2
    c0 = png_cands[0]
    c1 = png_cands[1]

    assert c0.offset == 0
    assert c0.estimated_end_offset is None, "Truncated PNG must not claim downstream IEND"
    assert c1.offset == len(trunc_png)
    assert c1.estimated_end_offset == len(evidence)


# ── Scenario 4: Truncated PNG + gap + valid PNG accounting ───────────────────

def test_04_truncated_png_gap_valid_png_no_verified_byte_inflation():
    """Truncated PNG followed by zero gap and valid PNG does not inflate verified bytes."""
    full_png = _make_png_bytes(width=8, height=8)
    trunc_png = full_png[:-12]
    gap = b"\x00" * 500
    valid_png = _make_png_bytes(width=16, height=16)
    evidence = trunc_png + gap + valid_png

    runs = execute_traced_recoveries("dump.bin", evidence, detection_mode="blind")

    png_runs = [r for r in runs if r.format == "png"]
    assert len(png_runs) == 2

    r0 = [r for r in png_runs if r.candidate_id == "cand-0"][0]
    r1 = [r for r in png_runs if r.candidate_id == "cand-1"][0]

    # Valid downstream PNG is fully recovered with exact byte count
    assert r1.total_verified_bytes == len(valid_png)
    assert r1.status == "FULLY_RECOVERED"

    # Truncated upstream PNG cannot claim gap or valid PNG
    assert r0.total_verified_bytes == 0
    assert r0.status != "FULLY_RECOVERED"


# ── Scenario 5: Fake IEND inside IDAT payload ────────────────────────────────

def test_05_png_fake_iend_inside_idat_payload():
    """Sequential chunk parser does not prematurely end on fake b'IEND' inside IDAT payload."""
    png_data = _make_png_with_fake_iend_in_idat()
    candidates = scan_evidence(png_data)
    png_cands = [c for c in candidates if c.format == "png"]

    assert len(png_cands) == 1
    cand = png_cands[0]
    assert cand.offset == 0
    assert cand.estimated_end_offset == len(png_data)


# ── Scenario 6: PNG malformed chunk length ───────────────────────────────────

def test_06_png_malformed_chunk_length():
    """PNG with invalid chunk length exceeding buffer yields estimated_end_offset is None."""
    png_magic = b"\x89PNG\r\n\x1a\n"
    # Chunk with claimed length 999999
    bad_chunk = struct.pack(">I", 999999) + b"IHDR" + b"\x00" * 13 + b"\x00\x00\x00\x00"
    evidence = png_magic + bad_chunk

    candidates = scan_evidence(evidence)
    png_cands = [c for c in candidates if c.format == "png"]

    assert len(png_cands) == 1
    assert png_cands[0].estimated_end_offset is None


# ── Scenario 7: Single valid JPEG candidate bounds ───────────────────────────

def test_07_single_valid_jpeg_bounds():
    """Single valid JPEG has exact estimated_end_offset matching its true length."""
    jpeg_data = _make_jpeg_bytes(width=8, height=8)
    padding = b"\x00" * 40
    evidence = padding + jpeg_data + padding

    candidates = scan_evidence(evidence)
    jpeg_cands = [c for c in candidates if c.format == "jpeg"]

    assert len(jpeg_cands) == 1
    cand = jpeg_cands[0]
    assert cand.offset == len(padding)
    assert cand.estimated_end_offset == len(padding) + len(jpeg_data)


# ── Scenario 8: Two adjacent valid JPEG candidates ───────────────────────────

def test_08_two_adjacent_valid_jpegs():
    """Two adjacent JPEGs are isolated: candidate 0 stops at candidate 1 offset with zero overlap."""
    jpeg1 = _make_jpeg_bytes(width=8, height=8)
    jpeg2 = _make_jpeg_bytes(width=16, height=16)
    evidence = jpeg1 + jpeg2

    candidates = scan_evidence(evidence)
    jpeg_cands = [c for c in candidates if c.format == "jpeg"]

    assert len(jpeg_cands) == 2
    c0 = jpeg_cands[0]
    c1 = jpeg_cands[1]

    assert c0.offset == 0
    assert c0.estimated_end_offset == len(jpeg1)
    assert c1.offset == len(jpeg1)
    assert c1.estimated_end_offset == len(evidence)
    assert c0.estimated_end_offset <= c1.offset


# ── Scenario 9: Truncated JPEG followed by valid JPEG ────────────────────────

def test_09_truncated_jpeg_followed_by_valid_jpeg():
    """Truncated JPEG does not swallow downstream valid JPEG; candidate 0 estimated_end_offset is None."""
    full_jpeg = _make_jpeg_bytes(width=8, height=8)
    # Truncate before EOI (drop last 2 bytes)
    trunc_jpeg = full_jpeg[:-2]
    valid_jpeg = _make_jpeg_bytes(width=16, height=16)
    evidence = trunc_jpeg + valid_jpeg

    candidates = scan_evidence(evidence)
    jpeg_cands = [c for c in candidates if c.format == "jpeg"]

    assert len(jpeg_cands) == 2
    c0 = jpeg_cands[0]
    c1 = jpeg_cands[1]

    assert c0.offset == 0
    assert c0.estimated_end_offset is None, "Truncated JPEG must not claim downstream EOI"
    assert c1.offset == len(trunc_jpeg)
    assert c1.estimated_end_offset == len(evidence)


# ── Scenario 10: Truncated JPEG + gap + valid JPEG accounting ────────────────

def test_10_truncated_jpeg_gap_valid_jpeg_no_verified_byte_inflation():
    """Truncated JPEG followed by zero gap and valid JPEG does not inflate verified bytes."""
    full_jpeg = _make_jpeg_bytes(width=8, height=8)
    trunc_jpeg = full_jpeg[:-2]
    gap = b"\x00" * 500
    valid_jpeg = _make_jpeg_bytes(width=16, height=16)
    evidence = trunc_jpeg + gap + valid_jpeg

    runs = execute_traced_recoveries("dump.bin", evidence, detection_mode="blind")

    jpeg_runs = [r for r in runs if r.format == "jpeg"]
    assert len(jpeg_runs) == 2

    r0 = [r for r in jpeg_runs if r.candidate_id == "cand-0"][0]
    r1 = [r for r in jpeg_runs if r.candidate_id == "cand-1"][0]

    # Valid downstream JPEG is fully recovered with exact byte count
    assert r1.total_verified_bytes == len(valid_jpeg)
    assert r1.status == "FULLY_RECOVERED"

    # Truncated upstream JPEG cannot claim gap or valid JPEG
    assert r0.total_verified_bytes == 0
    assert r0.status != "FULLY_RECOVERED"


# ── Scenario 11: JPEG malformed segment length ───────────────────────────────

def test_11_jpeg_malformed_segment_length():
    """JPEG with corrupted segment length (< 2 or past territory) yields estimated_end_offset is None."""
    # SOI + SOF0 marker with segment_len = 1 (invalid per ITU-T T.81, min length is 2)
    bad_jpeg = b"\xff\xd8\xff\xc0\x00\x01\x00\x00\x00"
    candidates = scan_evidence(bad_jpeg)
    jpeg_cands = [c for c in candidates if c.format == "jpeg"]

    assert len(jpeg_cands) == 1
    assert jpeg_cands[0].estimated_end_offset is None


# ── Scenario 12: Cross-format: Truncated PNG + gap with JSON + valid PNG ─────

def test_12_truncated_png_gap_json_valid_png():
    """JSON candidate embedded between truncated PNG and valid PNG is discovered."""
    full_png = _make_png_bytes(width=8, height=8)
    trunc_png = full_png[:-12]
    json_bytes = b'{"metric": "disk_io", "value": 42, "unit": "ops"}\n'
    valid_png = _make_png_bytes(width=16, height=16)

    evidence = trunc_png + json_bytes + valid_png

    candidates = scan_evidence(evidence)
    formats = [c.format for c in candidates]

    assert "json" in formats, "JSON candidate between truncated PNG and valid PNG must be discovered"
    assert formats.count("png") == 2

    json_cand = [c for c in candidates if c.format == "json"][0]
    assert json_cand.offset == len(trunc_png)


# ── Scenario 13: Cross-format: Truncated JPEG + gap with JSON + valid JPEG ───

def test_13_truncated_jpeg_gap_json_valid_jpeg():
    """JSON candidate embedded between truncated JPEG and valid JPEG is discovered."""
    full_jpeg = _make_jpeg_bytes(width=8, height=8)
    trunc_jpeg = full_jpeg[:-2]
    json_bytes = b'{"status": "ok", "alert": false, "code": 200}\n'
    valid_jpeg = _make_jpeg_bytes(width=16, height=16)

    evidence = trunc_jpeg + json_bytes + valid_jpeg

    candidates = scan_evidence(evidence)
    formats = [c.format for c in candidates]

    assert "json" in formats, "JSON candidate between truncated JPEG and valid JPEG must be discovered"
    assert formats.count("jpeg") == 2

    json_cand = [c for c in candidates if c.format == "json"][0]
    assert json_cand.offset == len(trunc_jpeg)


# ── Scenario 14: Multi-format composite evidence accounting ──────────────────

def test_14_multi_format_image_composite_accounting():
    """Composite evidence with PNG, JPEG, and padding preserves V + R + M invariants."""
    valid_png = _make_png_bytes(width=8, height=8)
    valid_jpeg = _make_jpeg_bytes(width=8, height=8)
    padding = b"\x00" * 128

    evidence = valid_png + padding + valid_jpeg

    runs = execute_traced_recoveries("composite.bin", evidence, detection_mode="blind")

    png_runs = [r for r in runs if r.format == "png"]
    jpeg_runs = [r for r in runs if r.format == "jpeg"]

    assert len(png_runs) >= 1
    assert len(jpeg_runs) >= 1

    r_png = png_runs[0]
    r_jpeg = jpeg_runs[0]

    assert r_png.total_verified_bytes == len(valid_png)
    assert r_jpeg.total_verified_bytes == len(valid_jpeg)
    assert r_png.status == "FULLY_RECOVERED"
    assert r_jpeg.status == "FULLY_RECOVERED"

    total_verified = r_png.total_verified_bytes + r_jpeg.total_verified_bytes
    assert total_verified <= len(evidence)
    assert total_verified == len(valid_png) + len(valid_jpeg)
