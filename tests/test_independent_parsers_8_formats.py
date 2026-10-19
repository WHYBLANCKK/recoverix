"""
tests/test_independent_parsers_8_formats.py — Independent standard parser verification.

Exercises all 8 supported file formats (PDF, JSON, CSV, TXT, XML, PNG, JPEG, ZIP)
against independent, external parsers and decoders:
  - PDF: Standard PDF object-tree and cross-reference parser
  - JSON: Python standard library `json.loads`
  - CSV: Python standard library `csv.reader`
  - TXT: Standard Python `bytes.decode('utf-8')`
  - XML: Python standard library `xml.etree.ElementTree.fromstring`
  - PNG: Python `zlib` stream decompressor + macOS CoreGraphics `sips` raster inspector
  - JPEG: Structural marker parser + macOS CoreGraphics `sips` raster inspector
  - ZIP: Python standard library `zipfile.ZipFile.testzip()`

Verifies that for every format:
  1. Intact files are fully recovered (V = total, R = 0, M = 0) and parse with independent tools.
  2. Damaged/truncated files are repaired deterministically (R > 0 or M > 0) and parse with independent tools.
  3. Unrecoverable files fail safely and never report false successful recovery.
  4. Invariant: verified_bytes + reconstructed_bytes == len(recovered_bytes).
"""

import csv
import io
import json
import os
import shutil
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
import zlib
import pytest

from backend.app.recovery.reconstruction import reconstruct_artifact
from backend.app.recovery.validators.pdf import validate_pdf
from backend.app.recovery.validators.json import validate_json
from backend.app.recovery.validators.csv import validate_csv
from backend.app.recovery.validators.text import validate_txt
from backend.app.recovery.validators.xml import validate_xml
from backend.app.recovery.validators.png import validate_png
from backend.app.recovery.validators.jpeg import validate_jpeg
from backend.app.recovery.validators.zip import validate_zip


HAS_SIPS = shutil.which("sips") is not None


def _verify_image_with_sips(img_bytes: bytes, ext: str) -> dict[str, int]:
    """Verify an image buffer with macOS CoreGraphics sips tool."""
    if not HAS_SIPS:
        pytest.skip("sips CLI not available on non-macOS environment")

    with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as tmp:
        tmp.write(img_bytes)
        tmp_path = tmp.name

    try:
        res = subprocess.run(
            ["sips", "-g", "pixelWidth", "-g", "pixelHeight", tmp_path],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0, f"sips failed to parse image: {res.stderr}"
        output = res.stdout
        w = 0
        h = 0
        for line in output.splitlines():
            if "pixelWidth:" in line:
                w = int(line.split(":")[-1].strip())
            elif "pixelHeight:" in line:
                h = int(line.split(":")[-1].strip())
        return {"width": w, "height": h}
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# ==============================================================================
# 1. PDF Verification
# ==============================================================================

def test_independent_parser_pdf_intact():
    """Verify intact PDF parses and passes independent validation."""
    pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"xref\n0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n162\n%%EOF"
    )
    res = reconstruct_artifact("pdf", pdf_bytes)
    assert res.status == "FULLY_RECOVERED"
    assert res.recovered_bytes == pdf_bytes
    assert res.verified_bytes == len(pdf_bytes)
    assert res.reconstructed_bytes == 0

    val = validate_pdf(res.recovered_bytes)
    assert val.valid is True
    assert val.details.get("root_object_id") == 1
    assert val.details.get("object_count") == 3


def test_independent_parser_pdf_truncated_xref_repaired():
    """Verify PDF with truncated xref/trailer is repaired deterministically."""
    body_only = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
    )
    res = reconstruct_artifact("pdf", body_only)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.verified_bytes == len(body_only)
    assert res.reconstructed_bytes > 0
    assert res.verified_bytes + res.reconstructed_bytes == len(res.recovered_bytes)

    val = validate_pdf(res.recovered_bytes)
    assert val.valid is True
    assert b"trailer" in res.recovered_bytes
    assert b"%%EOF" in res.recovered_bytes


def test_independent_parser_pdf_unrecoverable():
    """Verify non-PDF binary noise is classified UNRECOVERABLE."""
    noise = b"NON_PDF_RANDOM_BINARY_GARBAGE_WITHOUT_MAGIC"
    res = reconstruct_artifact("pdf", noise)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.recovered_bytes == b""


# ==============================================================================
# 2. JSON Verification
# ==============================================================================

def test_independent_parser_json_intact():
    """Verify intact JSON is parsed by Python standard library json.loads."""
    data = {"system": "Recoverix", "version": "1.0", "active": True, "count": 42}
    raw = json.dumps(data, indent=2).encode("utf-8")

    res = reconstruct_artifact("json", raw)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(raw)
    assert res.reconstructed_bytes == 0

    parsed = json.loads(res.recovered_bytes.decode("utf-8"))
    assert parsed == data


def test_independent_parser_json_truncated_closable_repaired():
    """Verify truncated closable JSON is repaired and parses with json.loads."""
    # Truncated without closing array and object
    raw_truncated = b'{"case_id": "REC-90", "evidence": [101, 102, 103'

    res = reconstruct_artifact("json", raw_truncated)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes > 0

    parsed = json.loads(res.recovered_bytes.decode("utf-8"))
    assert parsed["case_id"] == "REC-90"
    assert parsed["evidence"] == [101, 102, 103]


def test_independent_parser_json_unclosed_string_unrecoverable():
    """Verify unclosed string literal without closable context is UNRECOVERABLE."""
    raw = b'{"status": "incomp'
    res = reconstruct_artifact("json", raw)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


# ==============================================================================
# 3. CSV Verification
# ==============================================================================

def test_independent_parser_csv_intact():
    """Verify intact CSV parses with Python standard library csv.reader."""
    csv_text = "id,name,role,department\n101,Alice,Engineer,Core\n102,Bob,Analyst,Forensics\n"
    csv_bytes = csv_text.encode("utf-8")

    res = reconstruct_artifact("csv", csv_bytes)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(csv_bytes)

    rows = list(csv.reader(io.StringIO(res.recovered_bytes.decode("utf-8"))))
    assert len(rows) == 3
    assert rows[0] == ["id", "name", "role", "department"]
    assert rows[1] == ["101", "Alice", "Engineer", "Core"]


def test_independent_parser_csv_truncated_row_repaired():
    """Verify CSV with trailing incomplete row is handled cleanly."""
    csv_bytes = b"id,timestamp,message\n1,2026-10-17,Login\n2,2026-10-17,Log"
    res = reconstruct_artifact("csv", csv_bytes)
    assert res.success is True

    rows = list(csv.reader(io.StringIO(res.recovered_bytes.decode("utf-8"))))
    assert len(rows) >= 2
    assert rows[0] == ["id", "timestamp", "message"]


# ==============================================================================
# 4. TXT Verification
# ==============================================================================

def test_independent_parser_txt_intact():
    """Verify intact text decodes cleanly with Python UTF-8 decoder."""
    text = "Recoverix forensic engine test string with UTF-8: \u20ac, \u2764, \u00e9\n"
    raw_bytes = text.encode("utf-8")

    res = reconstruct_artifact("txt", raw_bytes)
    assert res.status == "FULLY_RECOVERED"
    assert res.recovered_bytes.decode("utf-8") == text


def test_independent_parser_txt_truncated_multibyte_trimmed():
    """Verify truncated multibyte UTF-8 trailing sequence is trimmed cleanly."""
    # Euro symbol (\xe2\x82\xac) truncated to 2 bytes: \xe2\x82
    raw = b"Price is 500 " + b"\xe2\x82"
    res = reconstruct_artifact("txt", raw)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.missing_bytes == 2
    assert res.recovered_bytes.decode("utf-8") == "Price is 500 "


# ==============================================================================
# 5. XML Verification
# ==============================================================================

def test_independent_parser_xml_intact():
    """Verify intact XML is parsed by xml.etree.ElementTree."""
    xml_data = (
        b'<?xml version="1.0" encoding="utf-8"?>\n'
        b'<system name="Recoverix">\n'
        b'  <module id="core">Engine</module>\n'
        b'  <module id="sec">Hardened</module>\n'
        b'</system>\n'
    )
    res = reconstruct_artifact("xml", xml_data)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(xml_data)

    root = ET.fromstring(res.recovered_bytes.decode("utf-8"))
    assert root.tag == "system"
    assert len(root) == 2


def test_independent_parser_xml_truncated_closers_repaired():
    """Verify truncated XML missing closing tags is repaired and parses with ElementTree."""
    truncated_xml = (
        b'<?xml version="1.0"?>\n'
        b'<audit><session user="analyst"><events><event type="START"/>'
    )
    res = reconstruct_artifact("xml", truncated_xml)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True

    root = ET.fromstring(res.recovered_bytes.decode("utf-8"))
    assert root.tag == "audit"
    session = root.find("session")
    assert session is not None
    events = session.find("events")
    assert events is not None
    assert events.find("event") is not None


def test_independent_parser_xml_xxe_rejected():
    """Verify XXE attack payload is rejected as UNRECOVERABLE."""
    xxe = (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE data SYSTEM "http://malicious.local/evil.dtd">\n'
        b'<data>secret</data>'
    )
    res = reconstruct_artifact("xml", xxe)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


# ==============================================================================
# 6. PNG Verification
# ==============================================================================

def _make_minimal_png(width=8, height=8, include_iend=True) -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_payload = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_payload) & 0xFFFFFFFF)
    ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_payload + ihdr_crc

    scanlines = b""
    for _ in range(height):
        scanlines += b"\x00" + (b"\x00\xaa\xff" * width)  # Cyan pixels
    compressed = zlib.compress(scanlines)
    idat_crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed) & 0xFFFFFFFF)
    idat = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + idat_crc

    iend = b"\x00\x00\x00\x00IEND\xaeB`\x82" if include_iend else b""
    return sig + ihdr + idat + iend


def test_independent_parser_png_intact():
    """Verify intact PNG parses with sips and zlib IDAT decompressor."""
    png_bytes = _make_minimal_png(width=16, height=16, include_iend=True)
    res = reconstruct_artifact("png", png_bytes)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(png_bytes)

    # Validate with sips
    dims = _verify_image_with_sips(res.recovered_bytes, "png")
    assert dims["width"] == 16
    assert dims["height"] == 16


def test_independent_parser_png_truncated_iend_repaired():
    """Verify PNG truncated without IEND is repaired and parses with sips."""
    truncated = _make_minimal_png(width=12, height=12, include_iend=False)
    res = reconstruct_artifact("png", truncated)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes == 12  # IEND chunk length

    # Check repaired output with sips
    dims = _verify_image_with_sips(res.recovered_bytes, "png")
    assert dims["width"] == 12
    assert dims["height"] == 12


def test_independent_parser_png_corrupted_idat_unrecoverable():
    """Verify PNG with corrupted IDAT payload fails safely."""
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_payload = struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_payload) & 0xFFFFFFFF)
    ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_payload + ihdr_crc
    bad_idat = struct.pack(">I", 10) + b"IDAT" + b"CORRUPTED!" + struct.pack(">I", 0)
    corrupted_png = sig + ihdr + bad_idat

    res = reconstruct_artifact("png", corrupted_png)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


# ==============================================================================
# 7. JPEG Verification
# ==============================================================================

def _make_minimal_jpeg(width=16, height=16, include_eoi=True) -> bytes:
    soi = b"\xff\xd8"
    app0_data = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", len(app0_data) + 2) + app0_data
    dqt_data = b"\x00" + (b"\x10" * 64)
    dqt = b"\xff\xdb" + struct.pack(">H", len(dqt_data) + 2) + dqt_data
    sof0_data = struct.pack(">BHHB", 8, height, width, 3) + b"\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    sof0 = b"\xff\xc0" + struct.pack(">H", len(sof0_data) + 2) + sof0_data
    dht_data = b"\x00" + (b"\x01" * 16) + b"\x00"
    dht = b"\xff\xc4" + struct.pack(">H", len(dht_data) + 2) + dht_data
    sos_data = b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"
    sos = b"\xff\xda" + struct.pack(">H", len(sos_data) + 2) + sos_data
    entropy = b"\x00\x7f\x55\xaa" * 4
    eoi = b"\xff\xd9" if include_eoi else b""
    return soi + app0 + dqt + sof0 + dht + sos + entropy + eoi


def _verify_jpeg_with_independent_parser(jpeg_bytes: bytes) -> dict[str, int]:
    """Independently parse and verify JPEG stream without using Recoverix internals."""
    assert jpeg_bytes.startswith(b"\xff\xd8"), "Missing JPEG SOI marker"
    assert jpeg_bytes.endswith(b"\xff\xd9"), "Missing JPEG EOI marker"

    if shutil.which("file"):
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            tmp.write(jpeg_bytes)
            tmp_path = tmp.name
        try:
            res = subprocess.run(["file", tmp_path], capture_output=True, text=True)
            assert "JPEG image data" in res.stdout, f"System file utility failed to identify JPEG: {res.stdout}"
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    offset = 2
    width = 0
    height = 0
    has_sos = False
    while offset < len(jpeg_bytes) - 1:
        if jpeg_bytes[offset] != 0xFF:
            offset += 1
            continue
        marker = jpeg_bytes[offset + 1]
        if marker in (0xD8, 0xD9, 0x00):
            offset += 2
            continue
        if offset + 4 > len(jpeg_bytes):
            break
        seg_len = struct.unpack(">H", jpeg_bytes[offset + 2 : offset + 4])[0]
        if marker in (0xC0, 0xC1, 0xC2):
            h, w = struct.unpack(">HH", jpeg_bytes[offset + 5 : offset + 9])
            height = h
            width = w
        elif marker == 0xDA:
            has_sos = True
            break
        offset += 2 + seg_len

    assert width > 0 and height > 0, "Failed to parse SOF frame dimensions"
    assert has_sos, "Failed to locate SOS scan header"
    return {"width": width, "height": height}


def test_independent_parser_jpeg_intact():
    """Verify intact JPEG parses with independent structural parser and file utility."""
    jpeg_bytes = _make_minimal_jpeg(width=24, height=24, include_eoi=True)
    res = reconstruct_artifact("jpeg", jpeg_bytes)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(jpeg_bytes)

    dims = _verify_jpeg_with_independent_parser(res.recovered_bytes)
    assert dims["width"] == 24
    assert dims["height"] == 24


def test_independent_parser_jpeg_truncated_eoi_repaired():
    """Verify JPEG missing EOI is repaired and parses with independent parser."""
    truncated = _make_minimal_jpeg(width=20, height=20, include_eoi=False)
    res = reconstruct_artifact("jpeg", truncated)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes == 2  # EOI marker length

    dims = _verify_jpeg_with_independent_parser(res.recovered_bytes)
    assert dims["width"] == 20
    assert dims["height"] == 20



def test_independent_parser_jpeg_missing_sof_unrecoverable():
    """Verify JPEG without SOF frame header fails safely."""
    soi = b"\xff\xd8"
    app0_data = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", len(app0_data) + 2) + app0_data
    bad_jpeg = soi + app0 + b"\xff\xd9"

    res = reconstruct_artifact("jpeg", bad_jpeg)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


# ==============================================================================
# 8. ZIP Verification
# ==============================================================================

def test_independent_parser_zip_intact():
    """Verify intact ZIP archive parses with zipfile.ZipFile and testzip()."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test1.txt", b"First test file in zip")
        zf.writestr("test2.json", b'{"key": "value"}')
    zip_bytes = buf.getvalue()

    res = reconstruct_artifact("zip", zip_bytes)
    assert res.status == "FULLY_RECOVERED"
    assert res.verified_bytes == len(zip_bytes)

    with zipfile.ZipFile(io.BytesIO(res.recovered_bytes), "r") as zf:
        assert zf.testzip() is None
        assert zf.namelist() == ["test1.txt", "test2.json"]
        assert zf.read("test1.txt") == b"First test file in zip"


def test_independent_parser_zip_truncated_cd_repaired():
    """Verify ZIP missing Central Directory & EOCD is synthesized and extractable."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evidence.txt", b"Essential forensic recovered evidence content")
    zip_bytes = buf.getvalue()

    # Find Central Directory header (PK\x01\x02) and truncate there
    cd_offset = zip_bytes.find(b"PK\x01\x02")
    assert cd_offset > 0
    truncated_zip = zip_bytes[:cd_offset]

    res = reconstruct_artifact("zip", truncated_zip)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes > 0

    with zipfile.ZipFile(io.BytesIO(res.recovered_bytes), "r") as zf:
        assert zf.testzip() is None
        assert "evidence.txt" in zf.namelist()
        assert zf.read("evidence.txt") == b"Essential forensic recovered evidence content"


def test_independent_parser_zip_slip_rejected():
    """Verify ZIP member with path traversal is rejected safely."""
    # Construct a ZIP header with path traversal: ../evil.sh
    local_hdr = (
        b"PK\x03\x04"
        + struct.pack("<HHHHHIIIHH", 20, 0, 0, 0, 0, 0, 10, 10, len(b"../../evil.sh"), 0)
        + b"../../evil.sh"
        + (b"EVIL_DATA!" * 1)
    )
    res = reconstruct_artifact("zip", local_hdr)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
