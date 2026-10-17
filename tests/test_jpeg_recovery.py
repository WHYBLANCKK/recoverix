"""
test_jpeg_recovery.py — Comprehensive test suite for deterministic JPEG recovery in Recoverix.

Verifies:
  1. Intact JPEG recovery (FULLY_RECOVERED, exact bytes, zero reconstruction).
  2. Truncated JPEG missing EOI (PARTIALLY_RECOVERED, EOI synthesis, strict V/R/M accounting).
  3. Truncated JPEG with solitary 0xFF tail rollback before EOI synthesis.
  4. Intact JPEG with trailing non-JPEG garbage (FULLY_RECOVERED, trimmed cleanly).
  5. JPEG missing SOF frame header (UNRECOVERABLE).
  6. JPEG missing SOS scan header (UNRECOVERABLE).
  7. Non-JPEG / invalid SOI evidence (UNRECOVERABLE).
  8. End-to-end single-file API upload and download of damaged JPEG.
"""

import struct
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.recovery.reconstructors.jpeg import reconstruct_jpeg
from backend.app.recovery.validators.jpeg import validate_jpeg
from backend.app.recovery.tracer import execute_traced_recovery

client = TestClient(app)


def _make_test_jpeg(width: int = 16, height: int = 16, include_eoi: bool = True, entropy_data: bytes = b"\x00\x7f\x55\xaa") -> bytes:
    """Construct minimal structurally valid JPEG binary data stream."""
    soi = b"\xff\xd8"
    eoi = b"\xff\xd9" if include_eoi else b""

    # APP0 (JFIF)
    app0_payload = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", len(app0_payload) + 2) + app0_payload

    # DQT
    dqt_payload = b"\x00" + (b"\x10" * 64)
    dqt = b"\xff\xdb" + struct.pack(">H", len(dqt_payload) + 2) + dqt_payload

    # SOF0 (Start of Frame 0 - Baseline DCT)
    sof0_payload = struct.pack(">BHHB", 8, height, width, 3) + b"\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    sof0 = b"\xff\xc0" + struct.pack(">H", len(sof0_payload) + 2) + sof0_payload

    # DHT (Huffman table)
    dht_payload = b"\x00" + (b"\x01" * 16) + b"\x00"
    dht = b"\xff\xc4" + struct.pack(">H", len(dht_payload) + 2) + dht_payload

    # SOS (Start of Scan)
    sos_payload = b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"
    sos = b"\xff\xda" + struct.pack(">H", len(sos_payload) + 2) + sos_payload

    return soi + app0 + dqt + sof0 + dht + sos + entropy_data + eoi


def test_jpeg_intact_full_recovery():
    full_jpeg = _make_test_jpeg(width=32, height=32, include_eoi=True)
    res = reconstruct_jpeg(full_jpeg)

    assert res.status == "FULLY_RECOVERED"
    assert res.success is True
    assert res.recovered_bytes == full_jpeg
    assert res.verified_bytes == len(full_jpeg)
    assert res.reconstructed_bytes == 0
    assert res.missing_bytes == 0
    assert res.validation_result.valid is True


def test_jpeg_missing_eoi_deterministic_synthesis():
    # Truncated JPEG missing EOI marker
    truncated_jpeg = _make_test_jpeg(width=32, height=32, include_eoi=False)
    assert not truncated_jpeg.endswith(b"\xff\xd9")

    res = reconstruct_jpeg(truncated_jpeg)

    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.recovered_bytes.endswith(b"\xff\xd9")
    assert res.reconstructed_bytes == 2  # Synthesized EOI
    assert res.verified_bytes == len(truncated_jpeg)
    assert res.missing_bytes == 0
    # Invariants
    assert res.verified_bytes + res.reconstructed_bytes == len(res.recovered_bytes)
    assert res.verified_bytes + res.missing_bytes == len(truncated_jpeg)
    assert res.validation_result.valid is True


def test_jpeg_truncated_with_solitary_ff_tail():
    # Truncated JPEG ending in solitary 0xFF (incomplete marker)
    truncated_jpeg = _make_test_jpeg(width=16, height=16, include_eoi=False) + b"\xff"
    res = reconstruct_jpeg(truncated_jpeg)

    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.recovered_bytes.endswith(b"\xff\xd9")
    assert res.reconstructed_bytes == 2
    assert res.missing_bytes == 1  # The solitary 0xFF was rolled back
    assert res.verified_bytes == len(truncated_jpeg) - 1
    # Invariants
    assert res.verified_bytes + res.reconstructed_bytes == len(res.recovered_bytes)
    assert res.verified_bytes + res.missing_bytes == len(truncated_jpeg)
    assert res.validation_result.valid is True


def test_jpeg_trailing_garbage_trimmed():
    full_jpeg = _make_test_jpeg(width=16, height=16, include_eoi=True)
    garbage = b"\xde\xad\xbe\xef" * 16
    with_garbage = full_jpeg + garbage

    res = reconstruct_jpeg(with_garbage)

    assert res.status == "FULLY_RECOVERED"
    assert res.success is True
    assert res.recovered_bytes == full_jpeg
    assert res.verified_bytes == len(full_jpeg)
    assert res.reconstructed_bytes == 0
    assert res.missing_bytes == len(garbage)
    assert res.validation_result.valid is True


def test_jpeg_missing_sof_unrecoverable():
    # Construct invalid JPEG missing SOF
    soi = b"\xff\xd8"
    sos = b"\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"
    entropy = b"\x00\x7f"
    eoi = b"\xff\xd9"
    no_sof = soi + sos + entropy + eoi

    res = reconstruct_jpeg(no_sof)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0
    assert res.reconstructed_bytes == 0


def test_jpeg_missing_sos_unrecoverable():
    # Construct JPEG missing SOS
    soi = b"\xff\xd8"
    sof0_payload = struct.pack(">BHHB", 8, 16, 16, 3) + b"\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    sof0 = b"\xff\xc0" + struct.pack(">H", len(sof0_payload) + 2) + sof0_payload
    eoi = b"\xff\xd9"
    no_sos = soi + sof0 + eoi

    res = reconstruct_jpeg(no_sos)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0
    assert res.reconstructed_bytes == 0


def test_jpeg_invalid_signature():
    res = reconstruct_jpeg(b"NOT_A_JPEG_FILE")
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0


def test_jpeg_api_upload_and_download():
    # End-to-end API upload of truncated JPEG
    truncated_jpeg = _make_test_jpeg(width=16, height=16, include_eoi=False)
    files = {"file": ("damaged_sample.jpg", truncated_jpeg, "image/jpeg")}
    response = client.post("/api/recover-file", files=files)
    assert response.status_code == 200
    data = response.json()

    assert data["format"] == "jpeg"
    assert data["status"] == "PARTIALLY_RECOVERED"
    assert data["is_downloadable"] is True
    assert data["verified_bytes"] == len(truncated_jpeg)
    assert data["reconstructed_bytes"] == 2

    # Download recovered file
    dl_resp = client.get(data["download_url"])
    assert dl_resp.status_code == 200
    assert dl_resp.content.startswith(b"\xff\xd8")
    assert dl_resp.content.endswith(b"\xff\xd9")
    assert len(dl_resp.content) == len(truncated_jpeg) + 2
    val = validate_jpeg(dl_resp.content)
    assert val.valid is True
