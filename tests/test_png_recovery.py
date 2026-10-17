"""
tests/test_png_recovery.py — Comprehensive tests for Phase 3 PNG recovery engine.

Tests:
  - Intact PNG image
  - Truncated PNG missing IEND trailer chunk
  - PNG with damaged ancillary chunk (e.g. tEXt with invalid CRC)
  - PNG with damaged critical chunk (corrupted IHDR)
  - PNG with damaged raster (corrupted IDAT decompression failure)
  - Random binary noise / non-PNG input
  - End-to-end API upload and download of recovered PNG
"""

import struct
import zlib
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.recovery.reconstruction import reconstruct_artifact
from backend.app.recovery.validators.png import validate_png


client = TestClient(app)


def _build_test_png(
    width: int = 4,
    height: int = 4,
    include_text_chunk: bool = False,
    text_crc_corrupt: bool = False,
    corrupt_idat: bool = False,
    include_iend: bool = True,
) -> bytes:
    """Deterministically synthesize a valid or damaged PNG fixture."""
    sig = b"\x89PNG\r\n\x1a\n"

    # IHDR
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc

    chunks = [sig, ihdr_chunk]

    # Optional ancillary tEXt chunk
    if include_text_chunk:
        t_data = b"Comment\x00Recoverix test fixture"
        t_crc_val = zlib.crc32(b"tEXt" + t_data) & 0xFFFFFFFF
        if text_crc_corrupt:
            t_crc_val ^= 0xFFFFFFFF  # Flip bits to invalidate CRC
        t_crc = struct.pack(">I", t_crc_val)
        text_chunk = struct.pack(">I", len(t_data)) + b"tEXt" + t_data + t_crc
        chunks.append(text_chunk)

    # IDAT
    raw_scanlines = b""
    for _ in range(height):
        raw_scanlines += b"\x00" + (b"\x00\xff\x00" * width)  # Green pixels

    if corrupt_idat:
        idat_payload = b"non_zlib_corrupted_garbage_bytes"
    else:
        idat_payload = zlib.compress(raw_scanlines)

    idat_crc = struct.pack(">I", zlib.crc32(b"IDAT" + idat_payload) & 0xFFFFFFFF)
    idat_chunk = struct.pack(">I", len(idat_payload)) + b"IDAT" + idat_payload + idat_crc
    chunks.append(idat_chunk)

    # IEND
    if include_iend:
        iend_crc = struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
        iend_chunk = struct.pack(">I", 0) + b"IEND" + iend_crc
        chunks.append(iend_chunk)

    return b"".join(chunks)


def test_png_intact_image():
    png_bytes = _build_test_png(width=4, height=4, include_iend=True)
    res = reconstruct_artifact("png", png_bytes)
    assert res.status == "FULLY_RECOVERED"
    assert res.success is True
    assert res.verified_bytes == len(png_bytes)
    assert res.reconstructed_bytes == 0
    assert res.missing_bytes == 0
    val = validate_png(res.recovered_bytes)
    assert val.valid is True
    assert val.details.get("width") == 4
    assert val.details.get("height") == 4


def test_png_truncated_missing_iend():
    # File truncated right after IDAT chunk (missing 12-byte IEND)
    png_bytes = _build_test_png(width=4, height=4, include_iend=False)
    val_before = validate_png(png_bytes)
    assert val_before.valid is False
    assert any("IEND" in err for err in val_before.errors)

    res = reconstruct_artifact("png", png_bytes)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes == 12  # Appended IEND chunk
    assert res.missing_bytes == 0
    assert res.verified_bytes == len(png_bytes)
    val_after = validate_png(res.recovered_bytes)
    assert val_after.valid is True
    assert b"IEND" in res.recovered_bytes


def test_png_damaged_ancillary_chunk_dropped():
    # PNG with an ancillary tEXt chunk that has corrupted CRC
    png_bytes = _build_test_png(
        width=4, height=4, include_text_chunk=True, text_crc_corrupt=True, include_iend=True
    )
    res = reconstruct_artifact("png", png_bytes)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert "ANCILLARY_CHUNK_DROPPED" in res.reconstruction_methods
    assert res.missing_bytes > 0
    val = validate_png(res.recovered_bytes)
    assert val.valid is True


def test_png_damaged_critical_ihdr_unrecoverable():
    # Corrupt IHDR magic chunk
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rBADH\x00\x00\x00\x04\x00\x00\x00\x04\x08\x02\x00\x00\x00"
    res = reconstruct_artifact("png", png_bytes)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0


def test_png_corrupted_idat_decompression_unrecoverable():
    # IDAT containing corrupted non-zlib payload
    png_bytes = _build_test_png(width=4, height=4, corrupt_idat=True, include_iend=True)
    res = reconstruct_artifact("png", png_bytes)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0


def test_png_binary_noise_unrecoverable():
    payload = b"\x00\x01\x02\x03\x04\x05\x06\x07" * 32
    res = reconstruct_artifact("png", payload)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


def test_png_api_upload_and_download():
    # Test end-to-end API upload of truncated PNG
    truncated_png = _build_test_png(width=4, height=4, include_iend=False)
    files = {"file": ("damaged_sample.png", truncated_png, "image/png")}
    response = client.post("/api/recover-file", files=files)
    assert response.status_code == 200
    data = response.json()

    assert data["format"] == "png"
    assert data["status"] == "PARTIALLY_RECOVERED"
    assert data["is_downloadable"] is True
    assert data["reconstructed_bytes"] == 12

    # Download recovered PNG
    dl_url = data["download_url"]
    dl_response = client.get(dl_url)
    assert dl_response.status_code == 200
    val = validate_png(dl_response.content)
    assert val.valid is True
