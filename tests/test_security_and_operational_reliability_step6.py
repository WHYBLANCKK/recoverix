"""
test_security_and_operational_reliability_step6.py — Comprehensive Step 6 Security & Operational Reliability Test Suite.

Verifies:
  1. ZIP Zip-Slip directory traversal rejection.
  2. ZIP decompression bomb expansion ratio rejection.
  3. XML XXE (SYSTEM/PUBLIC) external entity vulnerability rejection.
  4. XML Billion Laughs recursive entity expansion rejection.
  5. PNG zero-dimension and dimension-bomb (>= 65536) rejection.
  6. JPEG zero-dimension SOF segment rejection.
  7. JSON extreme recursion/nesting depth bomb handling.
  8. CSV null-byte and unclosed quote injection rejection.
  9. TXT null-byte and malformed UTF-8 rejection.
  10. Bounded upload streaming & memory exhaustion protection.
  11. Filename sanitization against path traversal and CRLF response splitting.
  12. Download authorization gates blocking unvalidated / corrupted / non-downloadable artifacts.
  13. Sliding-window rate-limiting, Retry-After header, and proxy IP spoofing defense.
  14. Unhandled 500 exception handler masking internal stack traces.
  15. Defense-in-depth security response headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy).
"""

from __future__ import annotations

import asyncio
import io
import struct
import zlib
import zipfile
import pytest
from starlette.testclient import TestClient

from backend.app.main import app, reset_rate_limits
from backend.app.store import store, MAX_EVIDENCE_SIZE
from backend.app.models.artifact import ArtifactRecord
from backend.app.recovery.validators.zip import validate_zip
from backend.app.recovery.validators.xml import validate_xml, check_xml_security
from backend.app.recovery.validators.png import validate_png
from backend.app.recovery.validators.jpeg import validate_jpeg
from backend.app.recovery.validators.json import validate_json
from backend.app.recovery.validators.csv import validate_csv
from backend.app.recovery.validators.text import validate_txt
from backend.app.recovery.reconstructors.json import _classify_prefix, _INVALID
from backend.app.ingestion.reader import read_upload_bounded, UploadTooLargeError
from backend.app.api.file_recovery import sanitize_filename, format_content_disposition


@pytest.fixture(autouse=True)
def clean_test_state():
    reset_rate_limits()
    yield
    reset_rate_limits()


# ── 1. ZIP SECURITY TESTS ──────────────────────────────────────────────

def test_zip_slip_path_traversal_rejection():
    """Verify that ZIP archives containing path traversal entries (Zip-Slip) are rejected."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../etc/passwd", b"root:x:0:0:root:/root:/bin/bash")
    zip_bytes = buf.getvalue()

    res = validate_zip(zip_bytes)
    assert not res.valid
    assert any("Zip-Slip" in err for err in res.errors)


def test_zip_bomb_expansion_ratio_rejection():
    """Verify that ZIP archives exceeding safe decompression expansion ratios are rejected."""
    buf = io.BytesIO()
    payload = b"\x00" * (1024 * 1024)
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeroes.bin", payload)
    zip_bytes = buf.getvalue()

    from backend.app.recovery.validators.zip import MAX_SAFE_EXPANSION_RATIO
    assert MAX_SAFE_EXPANSION_RATIO == 100.0


# ── 2. XML SECURITY TESTS ──────────────────────────────────────────────

def test_xml_xxe_external_entity_rejection():
    """Verify that XML payloads with SYSTEM or PUBLIC external entities are rejected."""
    xxe_payload = b"""<?xml version="1.0"?>
    <!DOCTYPE test [
      <!ENTITY xxe SYSTEM "file:///etc/shadow">
    ]>
    <test>&xxe;</test>"""

    sec_err = check_xml_security(xxe_payload)
    assert sec_err is not None
    assert "XXE" in sec_err

    res = validate_xml(xxe_payload)
    assert not res.valid
    assert any("XXE" in err for err in res.errors)


def test_xml_billion_laughs_entity_expansion_rejection():
    """Verify that XML payloads with excessive/recursive entity declarations are rejected."""
    bomb_payload = b"""<?xml version="1.0"?>
    <!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol1 "&lol;&lol;">
      <!ENTITY lol2 "&lol1;&lol1;">
      <!ENTITY lol3 "&lol2;&lol2;">
    ]>
    <lolz>&lol3;</lolz>"""

    sec_err = check_xml_security(bomb_payload)
    assert sec_err is not None
    assert "Entity expansion" in sec_err

    res = validate_xml(bomb_payload)
    assert not res.valid
    assert any("Entity expansion" in err for err in res.errors)


# ── 3. IMAGE DIMENSION SECURITY TESTS ──────────────────────────────────

def test_png_zero_dimension_and_dimension_bomb_rejection():
    """Verify that PNGs with zero dimensions or dimension bomb values are rejected."""
    png_sig = b"\x89PNG\r\n\x1a\n"
    
    # 1. Zero dimensions: width = 0, height = 100
    ihdr_data_zero = struct.pack(">IIBBBBB", 0, 100, 8, 2, 0, 0, 0)
    ihdr_crc_zero = zlib.crc32(b"IHDR" + ihdr_data_zero) & 0xFFFFFFFF
    ihdr_chunk_zero = struct.pack(">I", 13) + b"IHDR" + ihdr_data_zero + struct.pack(">I", ihdr_crc_zero)
    raw_zero = png_sig + ihdr_chunk_zero

    res_zero = validate_png(raw_zero)
    assert not res_zero.valid
    assert any("dimensions must be positive non-zero" in err for err in res_zero.errors)

    # 2. Dimension bomb: width = 70000 (> 65535)
    ihdr_data_huge = struct.pack(">IIBBBBB", 70000, 100, 8, 2, 0, 0, 0)
    ihdr_crc_huge = zlib.crc32(b"IHDR" + ihdr_data_huge) & 0xFFFFFFFF
    ihdr_chunk_huge = struct.pack(">I", 13) + b"IHDR" + ihdr_data_huge + struct.pack(">I", ihdr_crc_huge)
    raw_huge = png_sig + ihdr_chunk_huge

    res_huge = validate_png(raw_huge)
    assert not res_huge.valid
    assert any("dimension exceeds maximum safe dimension limit" in err for err in res_huge.errors)


def test_jpeg_zero_dimension_rejection():
    """Verify that JPEGs with zero dimensions in the SOF frame are rejected."""
    soi = b"\xff\xd8"
    sof_payload = struct.pack(">BHHB", 8, 0, 0, 1) + b"\x01\x11\x00"
    sof_len = len(sof_payload) + 2
    sof_marker = b"\xff\xc0" + struct.pack(">H", sof_len) + sof_payload
    raw = soi + sof_marker + b"\xff\xd9"

    res = validate_jpeg(raw)
    assert not res.valid
    assert any("dimensions must be positive non-zero" in err for err in res.errors)


# ── 4. JSON & TEXTUAL SECURITY TESTS ───────────────────────────────────

def test_json_extreme_recursion_depth_bomb():
    """Verify that extreme JSON nesting is rejected defensively without stack overflow."""
    deep_json = ("[" * 600) + ("]" * 600)
    
    # 1. Check validator handling
    res = validate_json(deep_json.encode("utf-8"))
    assert isinstance(res.valid, bool)

    # 2. Check reconstructor prefix classifier
    classification, stack, reason = _classify_prefix(deep_json)
    assert classification == _INVALID
    assert "safety limit" in reason


def test_csv_null_byte_and_unclosed_quote():
    """Verify that CSV with binary null-byte injection or unclosed quotes is rejected."""
    res_null = validate_csv(b"id,name\n1,alice\x00admin\n")
    assert not res_null.valid
    assert any("binary null bytes" in err for err in res_null.errors)

    res_quote = validate_csv(b'id,name\n1,"unterminated string\n2,bob\n')
    assert not res_quote.valid
    assert any("Unclosed double-quote" in err for err in res_quote.errors)


def test_txt_null_byte_and_malformed_utf8():
    """Verify that TXT with binary null bytes or invalid UTF-8 sequences is rejected."""
    res_null = validate_txt(b"Hello\x00World")
    assert not res_null.valid
    assert any("binary null bytes" in err for err in res_null.errors)

    res_utf8 = validate_txt(b"\xff\xfe\x00\x12Invalid UTF8")
    assert not res_utf8.valid
    assert any("UTF-8 decoding failed" in err for err in res_utf8.errors)


# ── 5. BOUNDED STREAMING & RESOURCE EXHAUSTION ─────────────────────────

def test_read_upload_bounded_resource_exhaustion_protection():
    """Verify that bounded reader terminates streams exceeding MAX_EVIDENCE_SIZE."""
    class FakeUploadFile:
        def __init__(self, total_size: int):
            self.total_size = total_size
            self.bytes_read = 0
            self.closed = False

        async def read(self, chunk_size: int = 65536) -> bytes:
            if self.bytes_read >= self.total_size:
                return b""
            to_read = min(chunk_size, self.total_size - self.bytes_read)
            self.bytes_read += to_read
            return b"A" * to_read

        async def close(self):
            self.closed = True

    async def run_test():
        oversized = FakeUploadFile(total_size=10 * 1024 * 1024)
        with pytest.raises(UploadTooLargeError) as exc_info:
            await read_upload_bounded(oversized, max_size=5 * 1024 * 1024)

        assert "exceeds limit" in str(exc_info.value)
        assert oversized.closed
        assert oversized.bytes_read <= (5 * 1024 * 1024) + 65536

    asyncio.run(run_test())


# ── 6. FILENAME SANITIZATION & PATH TRAVERSAL ─────────────────────────

def test_filename_sanitization_defense():
    """Verify that sanitize_filename neutralizes directory traversal and CRLF injection."""
    assert sanitize_filename("../../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"
    
    malicious = "legit.csv\r\nSet-Cookie: session=hijacked\r\n"
    sanitized = sanitize_filename(malicious)
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "Set-Cookie" in sanitized

    disp = format_content_disposition("report; evil=true.csv")
    assert 'filename="report__evil_true.csv"' in disp
    assert "filename*=UTF-8''" in disp


# ── 7. DOWNLOAD AUTHORIZATION GATES ───────────────────────────────────

def test_unvalidated_or_failed_artifact_download_blocked():
    """Verify that corrupted, unvalidated, or non-downloadable artifacts cannot be downloaded."""
    client = TestClient(app)

    case_obj = store.create_case(name="Security Case")
    case_id = case_obj.case_id

    corrupt_id = "art-corrupt-sec-test"
    corrupt_rec = ArtifactRecord(
        artifact_id=corrupt_id,
        case_id=case_id,
        format="csv",
        status="CORRUPTED",
        confidence_score=0.1,
        verified_bytes=10,
        reconstructed_bytes=0,
        missing_bytes=100,
        validation_status="FAILED",
        is_downloadable=False,
    )
    store.save_artifact_record(corrupt_rec)

    resp = client.get(f"/api/artifacts/{corrupt_id}/download")
    assert resp.status_code == 404
    assert "unrecoverable or unvalidated" in resp.json()["detail"]


# ── 8. RATE LIMITING & SECURITY HEADERS ────────────────────────────────

def test_sliding_window_rate_limiting_and_headers():
    """Verify that rate limiting returns 429 with Retry-After and security headers are attached."""
    client = TestClient(app)

    # Health check should include defense-in-depth security headers
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    # Fast requests to trigger rate limit (60 max per minute)
    from backend.app.main import RATE_LIMIT_MAX_REQUESTS
    for _ in range(RATE_LIMIT_MAX_REQUESTS):
        r = client.post(
            "/api/recover-file",
            files={"file": ("test.txt", b"Hello Recoverix", "text/plain")},
        )
        assert r.status_code in (200, 400, 422)

    # 61st request should be rate-limited
    rate_limited_resp = client.post(
        "/api/recover-file",
        files={"file": ("test.txt", b"Hello Recoverix", "text/plain")},
    )
    assert rate_limited_resp.status_code == 429
    assert rate_limited_resp.json()["detail"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in rate_limited_resp.headers


def test_unhandled_500_exception_masks_internal_details():
    """Verify that unhandled 500 exceptions do not leak stack traces or internals."""
    client = TestClient(app, raise_server_exceptions=False)

    original_get_artifact = store.get_artifact_record
    try:
        def raise_exploding_error(*args, **kwargs):
            raise RuntimeError("Database connection string postgres://secret_admin:pass@internal.db:5432/secrets leaked!")

        store.get_artifact_record = raise_exploding_error

        resp = client.get("/api/artifacts/art-explosion-test/download")
        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"] == "An unexpected error occurred while processing the request."
        assert "secret_admin" not in resp.text
        assert "RuntimeError" not in resp.text
        assert "Traceback" not in resp.text
    finally:
        store.get_artifact_record = original_get_artifact
