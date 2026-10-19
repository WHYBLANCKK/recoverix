"""
test_zip_recovery.py — Comprehensive test suite for deterministic ZIP recovery in Recoverix.

Verifies:
  1. Intact ZIP archive recovery (FULLY_RECOVERED, exact bytes, zero reconstruction).
  2. Truncated ZIP missing Central Directory & EOCD (PARTIALLY_RECOVERED, CD/EOCD synthesis, extractable).
  3. Intact ZIP with trailing non-ZIP garbage (FULLY_RECOVERED, trimmed cleanly).
  4. Zip-Slip path traversal protection (dropped / unrecoverable).
  5. Corrupted member payload integrity failure (UNRECOVERABLE).
  6. Invalid signature / non-ZIP evidence (UNRECOVERABLE).
  7. End-to-end single-file API upload and download of damaged ZIP.
"""

import io
import struct
import zipfile
import zlib
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.recovery.reconstructors.zip import reconstruct_zip
from backend.app.recovery.validators.zip import validate_zip

client = TestClient(app)


def _make_test_zip(files: dict[str, bytes], compress_type: int = zipfile.ZIP_DEFLATED) -> bytes:
    """Construct an in-memory ZIP archive from a dict of {filename: content}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=compress_type) as zf:
        for fname, content in files.items():
            zf.writestr(fname, content)
    return buf.getvalue()


def test_zip_intact_full_recovery():
    files = {
        "report.txt": b"Confidential forensic audit report content.\n",
        "metadata.json": b'{"case": "4029", "status": "verified"}\n',
    }
    intact_zip = _make_test_zip(files)
    res = reconstruct_zip(intact_zip)

    assert res.status == "FULLY_RECOVERED"
    assert res.success is True
    assert res.recovered_bytes == intact_zip
    assert res.verified_bytes == len(intact_zip)
    assert res.reconstructed_bytes == 0
    assert res.missing_bytes == 0
    assert res.validation_result.valid is True


def test_zip_truncated_central_directory_synthesis():
    # Build valid zip
    files = {
        "document.txt": b"Recoverix does not guess what was lost. It proves what can be recovered.\n",
        "config.json": b'{"version": "1.0", "engine": "Recoverix"}\n',
    }
    full_zip = _make_test_zip(files, compress_type=zipfile.ZIP_DEFLATED)

    # Find start of Central Directory (PK\x01\x02) and truncate there
    cd_start = full_zip.find(b"PK\x01\x02")
    assert cd_start != -1
    truncated_zip = full_zip[:cd_start]

    # Confirm it fails standard zip opening before recovery
    import pytest
    with pytest.raises(zipfile.BadZipFile):
        with zipfile.ZipFile(io.BytesIO(truncated_zip), mode="r") as zf:
            pass

    # Execute deterministic reconstruction
    res = reconstruct_zip(truncated_zip)

    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes > 0
    assert res.verified_bytes == len(truncated_zip)
    assert res.missing_bytes == 0

    # Invariants
    assert res.verified_bytes + res.reconstructed_bytes == len(res.recovered_bytes)
    assert res.verified_bytes + res.missing_bytes == len(truncated_zip)
    assert res.validation_result.valid is True

    # Verify extracted contents match original exactly
    with zipfile.ZipFile(io.BytesIO(res.recovered_bytes), mode="r") as zf:
        assert zf.testzip() is None
        assert zf.read("document.txt") == files["document.txt"]
        assert zf.read("config.json") == files["config.json"]


def test_zip_trailing_garbage_trimmed():
    files = {"sample.txt": b"Data stream.\n"}
    intact_zip = _make_test_zip(files)
    garbage = b"\xaa\xbb\xcc\xdd" * 32
    with_garbage = intact_zip + garbage

    res = reconstruct_zip(with_garbage)

    assert res.status == "FULLY_RECOVERED"
    assert res.success is True
    assert res.recovered_bytes == intact_zip
    assert res.verified_bytes == len(intact_zip)
    assert res.reconstructed_bytes == 0
    assert res.missing_bytes == len(garbage)
    assert res.validation_result.valid is True


def test_zip_slip_security_mitigation():
    # Construct a ZIP containing path traversal ../../evil.sh
    files = {"../../evil.sh": b"echo attack\n"}
    malicious_zip = _make_test_zip(files, compress_type=zipfile.ZIP_STORED)

    # Validator must flag security error
    val = validate_zip(malicious_zip)
    assert val.valid is False
    assert any("Zip-Slip" in err for err in val.errors)

    # Reconstructor must not reconstruct malicious member
    # Truncate CD
    cd_start = malicious_zip.find(b"PK\x01\x02")
    trunc_malicious = malicious_zip[:cd_start]
    res = reconstruct_zip(trunc_malicious)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


def test_zip_corrupted_payload_unrecoverable():
    files = {"test.txt": b"Compressible repetitive payload " * 20}
    full_zip = _make_test_zip(files, compress_type=zipfile.ZIP_DEFLATED)
    cd_start = full_zip.find(b"PK\x01\x02")
    trunc_zip = bytearray(full_zip[:cd_start])

    # Corrupt compressed payload bytes in the middle of data
    trunc_zip[40:50] = b"\xff" * 10

    res = reconstruct_zip(bytes(trunc_zip))
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0


def test_zip_invalid_signature():
    res = reconstruct_zip(b"NOT_A_ZIP_ARCHIVE")
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0


def test_zip_api_upload_and_download():
    # End-to-end API upload of truncated ZIP
    files = {"archive_test.txt": b"Single-file web recovery test content\n"}
    full_zip = _make_test_zip(files)
    cd_start = full_zip.find(b"PK\x01\x02")
    truncated_zip = full_zip[:cd_start]

    upload_files = {"file": ("damaged_archive.zip", truncated_zip, "application/zip")}
    response = client.post("/api/recover-file", files=upload_files)
    assert response.status_code == 200
    data = response.json()

    assert data["format"] == "zip"
    assert data["status"] == "PARTIALLY_RECOVERED"
    assert data["is_downloadable"] is True
    assert data["verified_bytes"] == len(truncated_zip)
    assert data["reconstructed_bytes"] > 0

    # Download recovered ZIP archive
    dl_resp = client.get(data["download_url"])
    assert dl_resp.status_code == 200
    assert dl_resp.content.startswith(b"PK\x03\x04")

    # Extract member from downloaded ZIP buffer
    with zipfile.ZipFile(io.BytesIO(dl_resp.content), mode="r") as zf:
        assert zf.testzip() is None
        assert zf.read("archive_test.txt") == files["archive_test.txt"]
