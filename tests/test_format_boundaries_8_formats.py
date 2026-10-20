"""
tests/test_format_boundaries_8_formats.py — Exhaustive boundary tests across all 8 formats.

Exercises boundary conditions across PDF, JSON, CSV, TXT, XML, PNG, JPEG, and ZIP:
  1. Empty evidence inputs (0 bytes) -> safely UNRECOVERABLE, V=0, R=0, M=0.
  2. Minimal valid inputs -> FULLY_RECOVERED, V=len, R=0, M=0.
  3. Truncated inputs with deterministic closers/trailers -> PARTIALLY_RECOVERED, V+R=out, V+M=in.
  4. Mid-token/unrecoverable corruptions -> UNRECOVERABLE, V=0 or strictly valid prefix, never invented.
  5. Security-sensitive inputs (XXE, entity bombs, Zip Slip path traversal) -> strictly rejected.
  6. Independent parser verification for every recoverable output.
"""

import csv
import io
import json
import struct
import xml.etree.ElementTree as ET
import zipfile
import zlib
import pytest

from backend.app.recovery.reconstruction import reconstruct_artifact
from backend.app.recovery.validators.pdf import validate_pdf, reconstruct_pdf_xref
from backend.app.recovery.validators.json import validate_json
from backend.app.recovery.validators.csv import validate_csv
from backend.app.recovery.validators.text import validate_txt
from backend.app.recovery.validators.xml import validate_xml
from backend.app.recovery.validators.png import validate_png
from backend.app.recovery.validators.jpeg import validate_jpeg
from backend.app.recovery.validators.zip import validate_zip
from tests.test_jpeg_recovery import _make_test_jpeg


# ── 1. Empty Inputs (0 Bytes) ──────────────────────────────────────────────────


@pytest.mark.parametrize("fmt", ["pdf", "json", "csv", "txt", "xml", "png", "jpeg", "zip"])
def test_boundary_empty_input_rejected_safely(fmt: str):
    """Empty inputs across all 8 formats must be safely rejected as UNRECOVERABLE."""
    res = reconstruct_artifact(fmt, b"")
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0
    assert res.reconstructed_bytes == 0
    assert res.missing_bytes == 0
    assert res.recovered_bytes == b""


# ── 2. Minimal Valid Inputs ────────────────────────────────────────────────────


def test_boundary_minimal_valid_json():
    """Minimal valid JSON: empty object and empty array."""
    for payload in [b"{}", b"[]"]:
        res = reconstruct_artifact("json", payload)
        assert res.status == "FULLY_RECOVERED"
        assert res.verified_bytes == len(payload)
        assert res.reconstructed_bytes == 0
        assert res.missing_bytes == 0
        assert json.loads(res.recovered_bytes.decode("utf-8")) in ({}, [])


def test_boundary_minimal_valid_csv():
    """Minimal valid CSV: 2-line CSV (header + data row with newline)."""
    payload = b"id,name\n1,Alice\n"
    res = reconstruct_artifact("csv", payload)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(payload)
    assert res.reconstructed_bytes == 0
    assert res.missing_bytes == 0
    reader = list(csv.reader(io.StringIO(res.recovered_bytes.decode("utf-8"))))
    assert reader == [["id", "name"], ["1", "Alice"]]


def test_boundary_minimal_valid_txt():
    """Minimal valid TXT: 1 printable character with newline termination."""
    payload = b"A\n"
    res = reconstruct_artifact("txt", payload)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(payload)
    assert res.recovered_bytes.decode("utf-8") == "A\n"


def test_boundary_minimal_valid_xml():
    """Minimal valid XML: self-closing root tag."""
    payload = b"<root/>"
    res = reconstruct_artifact("xml", payload)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(payload)
    assert res.reconstructed_bytes == 0
    elem = ET.fromstring(res.recovered_bytes.decode("utf-8"))
    assert elem.tag == "root"


def test_boundary_minimal_valid_png():
    """Minimal valid PNG: 1x1 transparent pixel."""
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    ihdr_chunk = b"\x00\x00\x00\x0dIHDR" + ihdr_data + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    idat_raw = zlib.compress(b"\x00\x00\x00\x00\x00")
    idat_chunk = struct.pack(">I", len(idat_raw)) + b"IDAT" + idat_raw + struct.pack(">I", zlib.crc32(b"IDAT" + idat_raw) & 0xFFFFFFFF)
    iend_chunk = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    payload = b"\x89PNG\r\n\x1a\n" + ihdr_chunk + idat_chunk + iend_chunk

    res = reconstruct_artifact("png", payload)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(payload)
    assert res.reconstructed_bytes == 0
    val = validate_png(res.recovered_bytes)
    assert val.valid is True


def test_boundary_minimal_valid_jpeg():
    """Minimal valid JPEG: constructed via standard valid JPEG generator."""
    payload = _make_test_jpeg(width=16, height=16, include_eoi=True)
    res = reconstruct_artifact("jpeg", payload)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(payload)
    assert res.reconstructed_bytes == 0
    val = validate_jpeg(res.recovered_bytes)
    assert val.valid is True


def test_boundary_minimal_valid_zip():
    """Minimal valid ZIP: 1 empty file entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("empty.txt", b"")
    payload = buf.getvalue()

    res = reconstruct_artifact("zip", payload)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(payload)
    assert res.reconstructed_bytes == 0
    with zipfile.ZipFile(io.BytesIO(res.recovered_bytes), "r") as zf:
        assert zf.testzip() is None
        assert "empty.txt" in zf.namelist()


def test_boundary_minimal_valid_pdf():
    """Minimal valid PDF: Catalog -> Pages -> Page."""
    payload = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n0000000108 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n160\n%%EOF\n"
    )
    res = reconstruct_artifact("pdf", payload)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(payload)
    val = validate_pdf(res.recovered_bytes)
    assert val.valid is True


# ── 3. Truncated Structural Recovery & Accounting Invariants ───────────────────


def test_boundary_json_closable_truncation_invariant():
    """Truncated JSON prefix must append forced closers, preserving V + M = in, V + R = out."""
    prefix = b'{"case_id": "IR-200", "users": ["alice", "bob"'
    res = reconstruct_artifact("json", prefix)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes == 2  # Appends ']}'
    assert res.verified_bytes == len(prefix)
    assert res.missing_bytes == 0
    assert res.verified_bytes + res.missing_bytes == len(prefix)
    assert res.verified_bytes + res.reconstructed_bytes == len(res.recovered_bytes)
    # Independently validated with json.loads
    parsed = json.loads(res.recovered_bytes.decode("utf-8"))
    assert parsed["case_id"] == "IR-200"
    assert parsed["users"] == ["alice", "bob"]


def test_boundary_xml_closable_truncation_invariant():
    """Truncated XML missing closing tags must append closers in strict LIFO order."""
    prefix = b'<audit><record id="101"><status>active</status>'
    res = reconstruct_artifact("xml", prefix)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes > 0
    assert res.verified_bytes + res.missing_bytes == len(prefix)
    assert res.verified_bytes + res.reconstructed_bytes == len(res.recovered_bytes)
    elem = ET.fromstring(res.recovered_bytes.decode("utf-8"))
    assert elem.tag == "audit"
    assert elem.find("record").attrib["id"] == "101"
    assert elem.find("record/status").text == "active"


def test_boundary_csv_unclosed_quote_and_missing_newline():
    """CSV with unclosed quote on last line must append closing quote and newline."""
    damaged_csv = b"id,name,comment\n1,alice,intact\n2,bob,\"unclosed note"
    res = reconstruct_artifact("csv", damaged_csv)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.verified_bytes + res.missing_bytes == len(damaged_csv)
    assert res.verified_bytes + res.reconstructed_bytes == len(res.recovered_bytes)
    rows = list(csv.reader(io.StringIO(res.recovered_bytes.decode("utf-8"))))
    assert len(rows) == 3
    assert rows[2][2] == "unclosed note"


def test_boundary_txt_multibyte_tail_truncation():
    """UTF-8 text severed in middle of multi-byte sequence must trim tail without inventing bytes."""
    valid_text = "Incident Report: Forensics 2026 ".encode("utf-8")
    # Sever 3-byte character € (\xe2\x82\xac) after 1st byte \xe2
    severed_payload = valid_text + b"\xe2"
    res = reconstruct_artifact("txt", severed_payload)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.missing_bytes == 1
    assert res.verified_bytes == len(valid_text)
    assert res.verified_bytes + res.missing_bytes == len(severed_payload)
    assert res.recovered_bytes == valid_text
    assert res.recovered_bytes.decode("utf-8").startswith("Incident Report:")


def test_boundary_png_missing_iend_trailer():
    """PNG missing IEND must append exact 12-byte IEND chunk when IDAT is valid."""
    ihdr_data = struct.pack(">IIBBBBB", 2, 2, 8, 6, 0, 0, 0)
    ihdr_chunk = b"\x00\x00\x00\x0dIHDR" + ihdr_data + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    idat_raw = zlib.compress(b"\x00" * 20)
    idat_chunk = struct.pack(">I", len(idat_raw)) + b"IDAT" + idat_raw + struct.pack(">I", zlib.crc32(b"IDAT" + idat_raw) & 0xFFFFFFFF)
    truncated_png = b"\x89PNG\r\n\x1a\n" + ihdr_chunk + idat_chunk  # Missing IEND!

    res = reconstruct_artifact("png", truncated_png)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes == 12
    assert res.verified_bytes == len(truncated_png)
    assert res.verified_bytes + res.reconstructed_bytes == len(res.recovered_bytes)
    assert res.recovered_bytes.endswith(b"\x00\x00\x00\x00IEND\xaeB`\x82")


def test_boundary_jpeg_missing_eoi_trailer():
    """JPEG missing EOI must append 2-byte EOI (0xFFD9) when SOF/SOS are valid."""
    truncated_jpeg = _make_test_jpeg(width=16, height=16, include_eoi=False)

    res = reconstruct_artifact("jpeg", truncated_jpeg)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes == 2
    assert res.recovered_bytes.endswith(b"\xff\xd9")
    assert res.verified_bytes + res.reconstructed_bytes == len(res.recovered_bytes)


def test_boundary_zip_missing_central_directory():
    """ZIP truncated before Central Directory must rebuild CD and EOCD from local headers."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("doc.txt", b"Forensic audit record 2026")
    full_zip = buf.getvalue()
    cd_start = full_zip.find(b"PK\x01\x02")
    assert cd_start > 0
    truncated_zip = full_zip[:cd_start]

    res = reconstruct_artifact("zip", truncated_zip)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes > 0
    assert res.verified_bytes == len(truncated_zip)
    with zipfile.ZipFile(io.BytesIO(res.recovered_bytes), "r") as zf:
        assert zf.testzip() is None
        assert zf.read("doc.txt") == b"Forensic audit record 2026"


# ── 4. Malformed and Unrecoverable Input Rejection ─────────────────────────────


def test_boundary_json_mid_token_string_rejected_conservatively():
    """Mid-token truncated JSON string cannot be closed without inventing characters.

    The verified prefix is retained with success=False and PARTIALLY_RECOVERED,
    while non-prefix malformed input is strictly UNRECOVERABLE.
    """
    bad_json = b'{"case": "IR-500", "details": {"severi'
    res = reconstruct_artifact("json", bad_json)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is False
    assert res.reconstructed_bytes == 0
    assert res.verified_bytes == len(b'{"case": "IR-500"')
    assert res.missing_bytes == len(bad_json) - len(b'{"case": "IR-500"')
    assert res.recovered_bytes == b'{"case": "IR-500"'

    # When no verified prefix exists at all:
    bad_no_prefix = b'{"severi'
    res_no_prefix = reconstruct_artifact("json", bad_no_prefix)
    assert res_no_prefix.status == "UNRECOVERABLE"
    assert res_no_prefix.success is False


def test_boundary_xml_mismatched_hierarchy_rejected():
    """XML with mismatched closing tags must not be falsely closed."""
    bad_xml = b"<root><item>text</root></item>"
    res = reconstruct_artifact("xml", bad_xml)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


def test_boundary_csv_binary_noise_rejected():
    """Binary garbage with non-text bytes must be rejected as unrecoverable."""
    bad_csv = b"\x00\xff\xfe\x00\x99\x88\x77\x66\x55\x44"
    res = reconstruct_artifact("csv", bad_csv)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


def test_boundary_png_corrupted_idat_payload_rejected():
    """PNG with invalid IDAT zlib payload must fail decompression and be rejected."""
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    ihdr_chunk = b"\x00\x00\x00\x0dIHDR" + ihdr_data + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    idat_corrupted = b"\xff\xff\xff\xff\x00\x00\x00\x00"  # Invalid zlib stream!
    idat_chunk = struct.pack(">I", len(idat_corrupted)) + b"IDAT" + idat_corrupted + b"\x00\x00\x00\x00"
    bad_png = b"\x89PNG\r\n\x1a\n" + ihdr_chunk + idat_chunk + b"\x00\x00\x00\x00IEND\xaeB`\x82"

    res = reconstruct_artifact("png", bad_png)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


def test_boundary_jpeg_missing_sof_frame_rejected():
    """JPEG without SOF frame must be rejected because dimensions are unknown."""
    soi = b"\xff\xd8"
    sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x7f"
    eoi = b"\xff\xd9"
    bad_jpeg = soi + sos + eoi  # Missing SOF!

    res = reconstruct_artifact("jpeg", bad_jpeg)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


# ── 5. Hostile and Security-Sensitive Inputs ───────────────────────────────────


def test_boundary_xml_security_xxe_entity_injection_blocked():
    """XML with SYSTEM entity reference (XXE attack) must be rejected safely."""
    xxe_payload = b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    res = reconstruct_artifact("xml", xxe_payload)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    val = validate_xml(xxe_payload)
    assert val.valid is False
    assert any("XXE" in err or "External entity" in err for err in val.errors)


def test_boundary_xml_security_billion_laughs_bomb_blocked():
    """XML with nested entity expansion (Billion Laughs denial-of-service) must be rejected."""
    bomb_payload = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE lolz ['
        b' <!ENTITY lol "lol">'
        b' <!ENTITY lol1 "&lol;&lol;">'
        b' <!ENTITY lol2 "&lol1;&lol1;">'
        b' <!ENTITY lol3 "&lol2;&lol2;">'
        b']>'
        b'<root>&lol3;</root>'
    )
    res = reconstruct_artifact("xml", bomb_payload)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    val = validate_xml(bomb_payload)
    assert val.valid is False
    assert any("expansion" in err or "entity" in err.lower() for err in val.errors)


def test_boundary_zip_slip_path_traversal_blocked():
    """ZIP entries with directory traversal paths (../ or absolute paths) must be rejected."""
    for traversal_name in [b"../../root_passwd", b"..\\..\\system32\\cmd.exe", b"/etc/shadow"]:
        local_hdr = (
            b"PK\x03\x04"
            + struct.pack("<HHHHHIIIHH", 20, 0, 0, 0, 0, 0, 10, 10, len(traversal_name), 0)
            + traversal_name
            + b"COMPROMISED"
        )
        res = reconstruct_artifact("zip", local_hdr)
        assert res.status == "UNRECOVERABLE"
        assert res.success is False
        val = validate_zip(local_hdr)
        assert val.valid is False
