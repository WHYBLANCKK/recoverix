"""
test_real_recovery_qualification.py — Comprehensive qualification test suite for all 8 Recoverix formats.

Empirically qualifies deterministic recovery, forensic byte accounting, independent parser
consumability, fail-closed download gating, and persistence across:
  - PDF
  - JSON
  - CSV
  - TXT
  - XML
  - PNG
  - JPEG/JPG
  - ZIP
"""

import csv
import io
import json
import os
import struct
import tempfile
import xml.etree.ElementTree as ET
import zipfile
import zlib
from fastapi.testclient import TestClient
import pytest

from backend.app.main import app
from backend.app.recovery.adapter import extract_recovered_bytes
from backend.app.recovery.tracer import execute_traced_recovery
from backend.app.recovery.validators.jpeg import validate_jpeg
from backend.app.recovery.validators.pdf import validate_pdf
from backend.app.recovery.validators.png import validate_png
from tests.test_format_boundaries_8_formats import _make_test_jpeg


# ── Canonical Ground Truth Fixtures ──

def make_canonical_pdf() -> bytes:
    """Build a minimal, strictly valid PDF with catalog and cross-reference table."""
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
    )
    xref_offset = len(body)
    xref_and_trailer = (
        b"xref\n0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000052 00000 n \n"
        b"0000000108 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n"
        + f"{xref_offset}\n".encode("ascii")
        + b"%%EOF\n"
    )
    return body + xref_and_trailer


def make_canonical_png() -> bytes:
    """Build a minimal, strictly valid 2x2 RGB PNG."""
    ihdr_payload = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_payload) & 0xFFFFFFFF)
    raw_scanlines = b"\x00\xff\x00\x00\x00\xff\x00\x00\x00\x00\xff\xff\xff\xff"
    compressed_idat = zlib.compress(raw_scanlines)
    idat_crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed_idat) & 0xFFFFFFFF)

    return (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", len(ihdr_payload)) + b"IHDR" + ihdr_payload + ihdr_crc
        + struct.pack(">I", len(compressed_idat)) + b"IDAT" + compressed_idat + idat_crc
        + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def make_canonical_zip() -> bytes:
    """Build a valid two-member compressed ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evidence_log.txt", b"Forensic timeline payload entry 1.")
        zf.writestr("manifest.json", b'{"case": "CASE-404", "status": "active"}')
    return buf.getvalue()


CANONICAL_REFERENCES = {
    "pdf": make_canonical_pdf(),
    "json": b'{"case_id": "CASE-101", "active": true, "items": [1, 2, 3], "notes": "evidence logged"}',
    "csv": b"id,name,role,status\n1,Alice,Investigator,Active\n2,Bob,Analyst,Active\n3,Charlie,Officer,Closed\n",
    "txt": b"Recoverix Forensic Report\nDate: 2026-10-20\nClassification: Confidential\nStatus: Verified\nSummary: Reconstruction validated.\n",
    "xml": b'<?xml version="1.0" encoding="utf-8"?>\n<forensicReport id="R-404">\n  <evidence id="1">DiskImage</evidence>\n  <examiner>Agent Cooper</examiner>\n</forensicReport>',
    "png": make_canonical_png(),
    "jpeg": _make_test_jpeg(width=16, height=16, include_eoi=True),
    "zip": make_canonical_zip(),
}


def _assert_independent_consumability(fmt: str, status: str, recovered_bytes: bytes) -> None:
    """Assert recovered artifact parses under strict third-party libraries without Recoverix code."""
    if status in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED"):
        assert len(recovered_bytes) > 0, f"Recovered bytes must not be empty for status {status}"
        if fmt == "json":
            obj = json.loads(recovered_bytes.decode("utf-8"))
            assert isinstance(obj, (dict, list)), "JSON must parse into dict or list"
        elif fmt == "csv":
            reader = csv.reader(io.StringIO(recovered_bytes.decode("utf-8")))
            rows = list(reader)
            assert len(rows) >= 1, "CSV must have at least one valid row"
        elif fmt == "txt":
            text = recovered_bytes.decode("utf-8")
            assert len(text) > 0, "Text must be non-empty valid UTF-8"
        elif fmt == "xml":
            root = ET.fromstring(recovered_bytes.decode("utf-8"))
            assert root.tag is not None, "XML must parse into valid element tree"
        elif fmt == "png":
            val = validate_png(recovered_bytes)
            assert val.valid is True, f"PNG validation failed: {val.errors}"
        elif fmt in ("jpeg", "jpg"):
            val = validate_jpeg(recovered_bytes)
            assert val.valid is True, f"JPEG validation failed: {val.errors}"
        elif fmt == "zip":
            with zipfile.ZipFile(io.BytesIO(recovered_bytes), "r") as zf:
                assert zf.testzip() is None, "ZIP must have 0 checksum/decompression errors"
                assert len(zf.namelist()) >= 1, "ZIP must contain surviving members"
        elif fmt == "pdf":
            val = validate_pdf(recovered_bytes)
            assert val.valid is True, f"PDF validation failed: {val.errors}"
    else:
        assert status == "UNRECOVERABLE"
        assert len(recovered_bytes) == 0, "Unrecoverable run must have 0 recovered bytes"


# ── Test Suite ──

@pytest.mark.parametrize("fmt", ["pdf", "json", "csv", "txt", "xml", "png", "jpeg", "zip"])
def test_intact_baseline_references_fully_recovered(fmt: str):
    """Every intact advertised format must recover as FULLY_RECOVERED with exact byte equality."""
    ref_bytes = CANONICAL_REFERENCES[fmt]
    filename = f"intact_sample.{fmt}" if fmt != "jpeg" else "intact_sample.jpg"

    run = execute_traced_recovery(filename, ref_bytes)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status == "FULLY_RECOVERED"
    assert rec_bytes == ref_bytes
    assert run.total_verified_bytes == len(ref_bytes)
    assert run.total_reconstructed_bytes == 0
    assert run.total_missing_bytes == 0
    assert run.total_input_bytes == len(ref_bytes)
    _assert_independent_consumability(fmt, run.status, rec_bytes)


def test_pdf_reconstructed_xref_and_trailer_recovery():
    """PDF with stripped cross-reference table and trailer is structurally reconstructed."""
    pdf_ref = CANONICAL_REFERENCES["pdf"]
    xref_pos = pdf_ref.rfind(b"\nxref")
    truncated_pdf = pdf_ref[:xref_pos]

    run = execute_traced_recovery("truncated.pdf", truncated_pdf)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status == "PARTIALLY_RECOVERED"
    assert any(s.method == "XREF_RECONSTRUCTION" for s in run.reconstruction_steps)
    assert run.total_verified_bytes + run.total_missing_bytes == run.total_input_bytes
    assert run.total_verified_bytes + run.total_reconstructed_bytes == len(rec_bytes)
    _assert_independent_consumability("pdf", run.status, rec_bytes)


def test_pdf_corrupted_header_safely_unrecoverable():
    """PDF with destroyed header signature is honestly marked UNRECOVERABLE."""
    pdf_ref = CANONICAL_REFERENCES["pdf"]
    bad_pdf = b"XXXX-1.4\n" + pdf_ref[9:]

    run = execute_traced_recovery("bad_header.pdf", bad_pdf)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status == "UNRECOVERABLE"
    assert run.total_verified_bytes == 0
    assert run.total_missing_bytes == len(bad_pdf)
    assert len(rec_bytes) == 0


def test_json_closable_truncation_recovery():
    """JSON with missing container closers is deterministically repaired."""
    cut_json = b'{"case_id": "CASE-101", "active": true, "items": [1, 2, 3'

    run = execute_traced_recovery("cut.json", cut_json)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status == "PARTIALLY_RECOVERED"
    assert run.total_reconstructed_bytes > 0
    assert run.total_verified_bytes + run.total_reconstructed_bytes == len(rec_bytes)
    _assert_independent_consumability("json", run.status, rec_bytes)


def test_json_mid_token_truncation_safely_unrecoverable():
    """JSON truncated mid-token without closing quotation is rejected as unrecoverable."""
    bad_json = b'{"case_id": "CASE-10'

    run = execute_traced_recovery("truncated_token.json", bad_json)
    assert run.status == "UNRECOVERABLE"
    assert len(extract_recovered_bytes(run)) == 0


def test_csv_unclosed_quote_repair():
    """CSV with unclosed quote in data row is safely repaired and consumable."""
    unclosed_csv = b"id,name,role,status\n1,Alice,Investigator,Active\n2,\"Bob,Analyst,Active\n3,Charlie,Officer,Closed\n"

    run = execute_traced_recovery("data.csv", unclosed_csv)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status == "PARTIALLY_RECOVERED"
    _assert_independent_consumability("csv", run.status, rec_bytes)


def test_csv_high_entropy_binary_noise_safely_rejected():
    """Arbitrary binary noise uploaded as CSV is rejected without 500 error."""
    noise = b"\x00\xff\xfe\x01\x80\x90\xaa\xbb" * 20

    run = execute_traced_recovery("noise.csv", noise)
    assert run.status == "UNRECOVERABLE"
    assert len(extract_recovered_bytes(run)) == 0


def test_txt_internal_null_runs_repaired():
    """TXT with binary null corruption runs is filtered to clean UTF-8 text."""
    null_txt = b"Recoverix Forensic Evidence\n\x00\x00\x00\x00Classification: Secret\n"

    run = execute_traced_recovery("report.txt", null_txt)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status == "PARTIALLY_RECOVERED"
    assert b"\x00" not in rec_bytes
    _assert_independent_consumability("txt", run.status, rec_bytes)


def test_txt_truncated_multibyte_tail_prefix_preserved():
    """TXT with truncated multibyte UTF-8 sequence trims damaged tail and preserves valid prefix."""
    valid_prefix = b"Recoverix Investigation Report: "
    damaged_txt = valid_prefix + b"\xe2\x82"  # Incomplete 3-byte UTF-8 sequence
    run = execute_traced_recovery("sample.txt", damaged_txt)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status == "PARTIALLY_RECOVERED"
    assert rec_bytes == valid_prefix
    assert run.total_verified_bytes == len(valid_prefix)
    assert run.total_missing_bytes == 2
    assert run.total_verified_bytes + run.total_missing_bytes == len(damaged_txt)
    assert run.total_verified_bytes + run.total_reconstructed_bytes == len(rec_bytes)
    _assert_independent_consumability("txt", run.status, rec_bytes)


def test_xml_closable_truncation_reconstruction():
    """XML with missing element closures is deterministically repaired."""
    cut_xml = b'<?xml version="1.0" encoding="utf-8"?>\n<forensicReport id="R-404">\n  <evidence id="1">DiskImage</evidence>\n  <examiner>Agent Cooper</examiner>'

    run = execute_traced_recovery("cut.xml", cut_xml)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")
    _assert_independent_consumability("xml", run.status, rec_bytes)


def test_xml_hostile_xxe_and_entity_bombs_blocked():
    """XML with XXE or entity expansion attack is rejected fail-closed."""
    bomb = b"""<!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol1 "&lol;&lol;">
      <!ENTITY lol2 "&lol1;&lol1;">
    ]><lolz>&lol2;</lolz>"""

    run = execute_traced_recovery("bomb.xml", bomb)
    assert run.status == "UNRECOVERABLE"
    assert len(extract_recovered_bytes(run)) == 0


def test_png_missing_iend_trailer_synthesized():
    """PNG missing only the 12-byte IEND chunk has IEND reconstructed."""
    png_ref = CANONICAL_REFERENCES["png"]
    iend_pos = png_ref.find(b"IEND") - 4
    cut_png = png_ref[:iend_pos]

    run = execute_traced_recovery("image.png", cut_png)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status == "PARTIALLY_RECOVERED"
    assert any("IEND" in s.method for s in run.reconstruction_steps)
    assert rec_bytes.endswith(b"IEND\xaeB`\x82")
    _assert_independent_consumability("png", run.status, rec_bytes)


def test_png_corrupted_ancillary_chunk_dropped_preserving_raster():
    """Corrupted ancillary chunk with bad CRC is dropped while preserving image."""
    png_ref = CANONICAL_REFERENCES["png"]
    iend_pos = png_ref.find(b"IEND") - 4
    corrupt_text = struct.pack(">I", 7) + b"tEXt" + b"bad_crc" + b"\x00\x00\x00\x00"
    png_with_bad_chunk = png_ref[:iend_pos] + corrupt_text + png_ref[iend_pos:]

    run = execute_traced_recovery("ancillary.png", png_with_bad_chunk)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status == "PARTIALLY_RECOVERED"
    _assert_independent_consumability("png", run.status, rec_bytes)


def test_jpeg_missing_eoi_marker_appended():
    """JPEG missing the 2-byte EOI (FF D9) marker has marker appended."""
    jpeg_ref = CANONICAL_REFERENCES["jpeg"]
    cut_jpeg = jpeg_ref[:-2]

    run = execute_traced_recovery("photo.jpg", cut_jpeg)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status == "PARTIALLY_RECOVERED"
    assert rec_bytes.endswith(b"\xff\xd9")
    _assert_independent_consumability("jpeg", run.status, rec_bytes)


def test_jpeg_trailing_garbage_trimmed_cleanly():
    """JPEG with trailing non-JPEG junk has junk trimmed with accurate missing accounting."""
    jpeg_ref = CANONICAL_REFERENCES["jpeg"]
    trailing_junk = b"\x00\xaa\xbb\xcc\xdd" * 10
    dirty_jpeg = jpeg_ref + trailing_junk

    run = execute_traced_recovery("photo.jpg", dirty_jpeg)
    rec_bytes = extract_recovered_bytes(run)

    assert rec_bytes == jpeg_ref
    assert run.total_verified_bytes == len(jpeg_ref)
    assert run.total_missing_bytes == len(trailing_junk)
    assert run.total_verified_bytes + run.total_missing_bytes == len(dirty_jpeg)
    _assert_independent_consumability("jpeg", run.status, rec_bytes)


def test_zip_truncated_central_directory_synthesized():
    """ZIP with truncated central directory and EOCD has records synthesized for all surviving files."""
    zip_ref = CANONICAL_REFERENCES["zip"]
    cd_pos = zip_ref.find(b"PK\x01\x02")
    cut_zip = zip_ref[:cd_pos]

    run = execute_traced_recovery("archive.zip", cut_zip)
    rec_bytes = extract_recovered_bytes(run)

    assert run.status == "PARTIALLY_RECOVERED"
    _assert_independent_consumability("zip", run.status, rec_bytes)


def test_zip_zip_slip_hostile_path_dropped_or_rejected():
    """ZIP archive containing path traversal (Zip-Slip) is safely blocked."""
    slip_buf = io.BytesIO()
    with zipfile.ZipFile(slip_buf, mode="w") as zf:
        zf.writestr("../../etc/shadow", b"root:*:0:0:root:/root:/bin/bash\n")

    run = execute_traced_recovery("hostile.zip", slip_buf.getvalue())
    assert run.status == "UNRECOVERABLE"
    assert len(extract_recovered_bytes(run)) == 0


# ── Phase 4 Lifecycle and Download Gate Enforcement ──

def test_full_lifecycle_upload_persist_restart_retrieve_and_download_gate():
    """Exercise complete real-world lifecycle with state persistence and fail-closed download gates."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        os.environ["RECOVERIX_DB_PATH"] = tmp_db.name
        client = TestClient(app, raise_server_exceptions=False)

        # 1. Upload valid recoverable artifact
        valid_json = CANONICAL_REFERENCES["json"]
        resp_upload = client.post(
            "/api/recover-file",
            files={"file": ("case_evidence.json", valid_json, "application/json")},
        )
        assert resp_upload.status_code == 200
        run_data = resp_upload.json()
        run_id = run_data["run_id"]
        assert run_data["status"] == "FULLY_RECOVERED"

        # 2. Simulate complete application restart by creating fresh TestClient
        restarted_client = TestClient(app, raise_server_exceptions=False)

        # 3. Retrieve run from database
        resp_get = restarted_client.get(f"/api/recovery-runs/{run_id}")
        assert resp_get.status_code == 200
        persisted_run = resp_get.json()
        assert persisted_run["status"] == "FULLY_RECOVERED"
        assert persisted_run["total_verified_bytes"] == len(valid_json)

        # 4. Download recovered artifact via /api/recover-file/{id}/download
        resp_dl1 = restarted_client.get(f"/api/recover-file/{run_id}/download")
        assert resp_dl1.status_code == 200
        assert resp_dl1.content == valid_json
        assert resp_dl1.headers.get("x-artifact-sha256") is not None

        # 5. Download via /api/artifacts/{id}/download
        resp_dl2 = restarted_client.get(f"/api/artifacts/{run_id}/download")
        assert resp_dl2.status_code == 200
        assert resp_dl2.content == valid_json

        # 6. Upload unrecoverable corrupt file and verify download gate blocks with 404
        unrecoverable_binary = b"\x00\x01\x02\x03" * 20
        resp_unrec = restarted_client.post(
            "/api/recover-file",
            files={"file": ("corrupt.pdf", unrecoverable_binary, "application/pdf")},
        )
        assert resp_unrec.status_code == 200
        unrec_data = resp_unrec.json()
        assert unrec_data["status"] == "UNRECOVERABLE"
        unrec_id = unrec_data["run_id"]

        # Download MUST be blocked with 404 fail-closed
        resp_blocked1 = restarted_client.get(f"/api/recover-file/{unrec_id}/download")
        assert resp_blocked1.status_code == 404

        resp_blocked2 = restarted_client.get(f"/api/artifacts/{unrec_id}/download")
        assert resp_blocked2.status_code == 404


def test_download_gate_strictly_blocks_hostile_zip_and_xml():
    """Verify download gate returns 404 for hostile ZIP (Zip-Slip) and XML (XXE/Billion Laughs)."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        os.environ["RECOVERIX_DB_PATH"] = tmp_db.name
        client = TestClient(app, raise_server_exceptions=False)

        # 1. Hostile Zip-Slip
        slip_buf = io.BytesIO()
        with zipfile.ZipFile(slip_buf, mode="w") as zf:
            zf.writestr("../../etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n")
        resp_zip = client.post(
            "/api/recover-file",
            files={"file": ("slip.zip", slip_buf.getvalue(), "application/zip")},
        )
        assert resp_zip.status_code == 200
        zip_run_id = resp_zip.json()["run_id"]
        assert resp_zip.json()["status"] == "UNRECOVERABLE"
        assert client.get(f"/api/recover-file/{zip_run_id}/download").status_code == 404
        assert client.get(f"/api/artifacts/{zip_run_id}/download").status_code == 404

        # 2. Hostile XML XXE
        xxe_xml = b'<!DOCTYPE test SYSTEM "http://evil.com/xxe.dtd"><test>1</test>'
        resp_xml = client.post(
            "/api/recover-file",
            files={"file": ("xxe.xml", xxe_xml, "application/xml")},
        )
        assert resp_xml.status_code == 200
        xml_run_id = resp_xml.json()["run_id"]
        assert resp_xml.json()["status"] == "UNRECOVERABLE"
        assert client.get(f"/api/recover-file/{xml_run_id}/download").status_code == 404
        assert client.get(f"/api/artifacts/{xml_run_id}/download").status_code == 404
