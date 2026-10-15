"""
test_upload_memory_safety.py — Verification and regression tests for evidence upload memory safety.

Validates that:
1. Valid uploads below 5 MiB succeed on all endpoints (/api/recover-file, /api/recover/file, /api/cases/{case_id}/evidence).
2. Uploads exactly at 5 MiB (5,242,880 bytes) succeed.
3. Uploads exceeding 5 MiB by 1 byte are rejected with HTTP 413 without unbounded buffering.
4. Requests with oversized Content-Length headers are rejected before body reading/buffering.
5. Requests without Content-Length (chunked streaming) reject if exceeding 5 MiB.
6. Requests with misleading Content-Length headers (small header, large body) reject with 413 upon exceeding limit.
7. Stream readers (read_upload_bounded, read_request_stream_bounded) properly close files and abort iteration.
8. Defensive limits in chunk_evidence prevent processing oversized buffers.
9. Oversized/rejected uploads leave zero orphaned rows or unlinked blobs in SQLite.
10. Spooled and temporary files are cleaned up upon rejection.
"""

from __future__ import annotations

import io
import tempfile
from typing import AsyncGenerator
import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import UploadFile

from backend.app.main import app
from backend.app.store import store, MAX_EVIDENCE_SIZE
from backend.app.ingestion.reader import (
    read_upload_bounded,
    read_request_stream_bounded,
    UploadTooLargeError,
)
from backend.app.ingestion.chunker import chunk_evidence
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_store():
    """Ensure clean store before and after each test."""
    store.clear()
    yield
    store.clear()


# ==============================================================================
# 1. Valid uploads below 5 MiB
# ==============================================================================


def test_valid_upload_below_limit_recover_file():
    """Valid small file uploaded to /api/recover-file succeeds."""
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Test\nBody: Valid upload below limit\n" + SYNTHETIC_END_MARKER
    response = client.post(
        "/api/recover-file",
        files={"file": ("small.txt", payload, "text/plain")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "FULLY_RECOVERED"
    assert data["confidence_score"] == 100.0


def test_valid_upload_below_limit_recover_file_alias():
    """Valid small file uploaded to /api/recover/file alias succeeds."""
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Test\nBody: Valid alias\n" + SYNTHETIC_END_MARKER
    response = client.post(
        "/api/recover/file",
        files={"file": ("alias.txt", payload, "text/plain")},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "FULLY_RECOVERED"


def test_valid_upload_below_limit_case_evidence_multipart():
    """Valid multipart file uploaded to /api/cases/{case_id}/evidence succeeds."""
    create_res = client.post("/api/cases", json={"name": "Valid Case Multipart"})
    case_id = create_res.json()["case_id"]

    evidence_data = b"Case evidence payload bytes below limit"
    response = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("disk.raw", evidence_data, "application/octet-stream")},
    )
    assert response.status_code == 200
    meta = response.json()["evidence"]
    assert meta["file_size"] == len(evidence_data)
    assert meta["filename"] == "disk.raw"


def test_valid_upload_below_limit_case_evidence_raw_body():
    """Valid raw octet-stream body uploaded to /api/cases/{case_id}/evidence succeeds."""
    create_res = client.post("/api/cases", json={"name": "Valid Case Raw"})
    case_id = create_res.json()["case_id"]

    raw_data = b"Raw octet-stream bytes for case evidence"
    response = client.post(
        f"/api/cases/{case_id}/evidence",
        content=raw_data,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 200
    meta = response.json()["evidence"]
    assert meta["file_size"] == len(raw_data)


# ==============================================================================
# 2. Valid upload exactly at limit (5 MiB = 5,242,880 bytes)
# ==============================================================================


def test_valid_upload_exactly_at_limit_case_evidence_multipart():
    """Evidence file exactly 5 MiB (5,242,880 bytes) multipart upload is accepted."""
    create_res = client.post("/api/cases", json={"name": "Exact Limit Case Multipart"})
    case_id = create_res.json()["case_id"]

    exact_data = b"E" * MAX_EVIDENCE_SIZE
    response = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("exact.raw", exact_data, "application/octet-stream")},
    )
    assert response.status_code == 200
    meta = response.json()["evidence"]
    assert meta["file_size"] == MAX_EVIDENCE_SIZE


def test_valid_upload_exactly_at_limit_case_evidence_raw_body():
    """Evidence file exactly 5 MiB raw body upload is accepted."""
    create_res = client.post("/api/cases", json={"name": "Exact Limit Case Raw"})
    case_id = create_res.json()["case_id"]

    exact_data = b"R" * MAX_EVIDENCE_SIZE
    response = client.post(
        f"/api/cases/{case_id}/evidence",
        content=exact_data,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 200
    meta = response.json()["evidence"]
    assert meta["file_size"] == MAX_EVIDENCE_SIZE


def test_valid_upload_exactly_at_limit_recover_file():
    """Single file recovery upload of exactly 5 MiB is accepted (processed without 413)."""
    exact_data = b"S" * MAX_EVIDENCE_SIZE
    response = client.post(
        "/api/recover-file",
        files={"file": ("exact.bin", exact_data, "application/octet-stream")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["original_filename"] == "exact.bin"


# ==============================================================================
# 3. Upload exceeding limit by 1 byte (5 MiB + 1 = 5,242,881 bytes)
# ==============================================================================


def test_upload_exceeding_limit_by_1_byte_recover_file():
    """Upload exceeding 5 MiB by 1 byte to /api/recover-file returns 413 FILE_TOO_LARGE."""
    oversized = b"X" * (MAX_EVIDENCE_SIZE + 1)
    response = client.post(
        "/api/recover-file",
        files={"file": ("oversized.bin", oversized, "application/octet-stream")},
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "FILE_TOO_LARGE"


def test_upload_exceeding_limit_by_1_byte_case_evidence_multipart():
    """Multipart upload exceeding 5 MiB by 1 byte returns 413 Payload Too Large."""
    create_res = client.post("/api/cases", json={"name": "Oversized Case Multipart"})
    case_id = create_res.json()["case_id"]

    oversized = b"M" * (MAX_EVIDENCE_SIZE + 1)
    response = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("oversized.raw", oversized, "application/octet-stream")},
    )
    assert response.status_code == 413
    detail = response.json()["detail"].lower()
    assert "exceeds" in detail or "5 mib" in detail


def test_upload_exceeding_limit_by_1_byte_case_evidence_raw_body():
    """Raw body upload exceeding 5 MiB by 1 byte returns 413 Payload Too Large."""
    create_res = client.post("/api/cases", json={"name": "Oversized Case Raw"})
    case_id = create_res.json()["case_id"]

    oversized = b"B" * (MAX_EVIDENCE_SIZE + 1)
    response = client.post(
        f"/api/cases/{case_id}/evidence",
        content=oversized,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 413
    detail = response.json()["detail"].lower()
    assert "exceeds" in detail or "5 mib" in detail


# ==============================================================================
# 4. Request with oversized Content-Length header (rejected before reading body)
# ==============================================================================


def test_oversized_content_length_rejected_before_reading_recover_file():
    """Oversized Content-Length header to /api/recover-file is rejected with 413."""
    response = client.post(
        "/api/recover-file",
        content=b"small payload",
        headers={
            "Content-Length": "104857600",  # 100 MB
            "Content-Type": "multipart/form-data; boundary=---boundary",
        },
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "FILE_TOO_LARGE"


def test_oversized_content_length_rejected_before_reading_case_evidence():
    """Oversized Content-Length header to /api/cases/{case_id}/evidence is rejected with 413."""
    create_res = client.post("/api/cases", json={"name": "Content-Length Case"})
    case_id = create_res.json()["case_id"]

    response = client.post(
        f"/api/cases/{case_id}/evidence",
        content=b"small payload",
        headers={
            "Content-Length": "104857600",  # 100 MB
            "Content-Type": "application/octet-stream",
        },
    )
    assert response.status_code == 413
    detail = response.json()["detail"].lower()
    assert "exceeds" in detail or "5 mib" in detail


# ==============================================================================
# 5. Request without Content-Length (chunked generator stream)
# ==============================================================================


def test_chunked_stream_under_limit_case_evidence():
    """Chunked generator streaming under limit succeeds."""
    create_res = client.post("/api/cases", json={"name": "Chunked Under Limit"})
    case_id = create_res.json()["case_id"]

    def chunk_generator():
        for _ in range(5):
            yield b"1234567890" * 100  # 1000 bytes each -> 5000 bytes total

    response = client.post(
        f"/api/cases/{case_id}/evidence",
        content=chunk_generator(),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 200
    meta = response.json()["evidence"]
    assert meta["file_size"] == 5000


def test_chunked_stream_over_limit_case_evidence_rejected():
    """Chunked generator streaming over limit is aborted and rejected with 413."""
    create_res = client.post("/api/cases", json={"name": "Chunked Over Limit"})
    case_id = create_res.json()["case_id"]

    chunk_size = 1024 * 1024  # 1 MiB per chunk
    num_chunks = 6  # 6 MiB total (> 5 MiB)

    def large_generator():
        for _ in range(num_chunks):
            yield b"C" * chunk_size

    response = client.post(
        f"/api/cases/{case_id}/evidence",
        content=large_generator(),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 413
    detail = response.json()["detail"].lower()
    assert "exceeds" in detail or "5 mib" in detail


# ==============================================================================
# 6. Misleading Content-Length (header says small, stream transmits large)
# ==============================================================================


def test_misleading_content_length_rejected_when_streaming():
    """Header specifies Content-Length: 50, but body streams 6 MiB -> 413 rejection."""
    create_res = client.post("/api/cases", json={"name": "Misleading CL Case"})
    case_id = create_res.json()["case_id"]

    def large_body_generator():
        for _ in range(6):
            yield b"M" * (1024 * 1024)

    # Note: TestClient with content generator stream
    response = client.post(
        f"/api/cases/{case_id}/evidence",
        content=large_body_generator(),
        headers={
            "Content-Length": "50",
            "Content-Type": "application/octet-stream",
        },
    )
    # The reader terminates as soon as received bytes exceed 5 MiB
    assert response.status_code == 413
    detail = response.json()["detail"].lower()
    assert "exceeds" in detail or "5 mib" in detail


# ==============================================================================
# 7. Unit tests for bounded streaming reader functions
# ==============================================================================


def test_read_upload_bounded_normal_file():
    """read_upload_bounded successfully reads a small UploadFile within limit."""
    import asyncio

    async def _test():
        content = b"Small test content"
        bio = io.BytesIO(content)
        upload = UploadFile(file=bio, filename="test.txt")

        result = await read_upload_bounded(upload, max_size=1024)
        assert result == content

    asyncio.run(_test())


def test_read_upload_bounded_oversized_spooled_fast_path():
    """read_upload_bounded checks seek/tell of underlying spooled file and rejects O(1)."""
    import asyncio

    async def _test():
        large_data = b"Z" * (1024 * 1024 + 10)  # ~1 MB with 512-byte limit
        bio = io.BytesIO(large_data)
        closed = False

        class MockUpload:
            def __init__(self, f):
                self.file = f
                self.filename = "mock.bin"

            async def close(self):
                nonlocal closed
                closed = True
                self.file.close()

            async def read(self, size: int = -1):
                pytest.fail("read() should not be called when spooled size already exceeds limit!")

        mock = MockUpload(bio)
        with pytest.raises(UploadTooLargeError) as exc_info:
            await read_upload_bounded(mock, max_size=512)

        assert exc_info.value.actual_size == len(large_data)
        assert closed is True

    asyncio.run(_test())


def test_read_upload_bounded_streaming_chunks_aborts_on_limit():
    """read_upload_bounded aborts incrementally when stream exceeds limit."""
    import asyncio

    async def _test():
        closed = False

        class NonSeekableStream:
            """Stream without seek/tell support."""
            def __init__(self):
                self.chunks_yielded = 0

            async def read(self, size: int = 65536):
                if self.chunks_yielded >= 5:
                    return b""
                self.chunks_yielded += 1
                return b"A" * 1000  # 1000 bytes per chunk

            async def close(self):
                nonlocal closed
                closed = True

        stream = NonSeekableStream()
        # Limit to 2500 bytes; chunk 3 (3000 bytes) triggers rejection
        with pytest.raises(UploadTooLargeError) as exc_info:
            await read_upload_bounded(stream, max_size=2500, chunk_size=1000)

        assert exc_info.value.actual_size == 3000
        assert closed is True
        # Verify stream was not fully read (only 3 chunks consumed, not 5)
        assert stream.chunks_yielded == 3

    asyncio.run(_test())


def test_read_request_stream_bounded():
    """read_request_stream_bounded aborts as soon as limit is exceeded."""
    import asyncio

    async def _test():
        chunks_sent = 0

        class MockRequest:
            async def stream(self) -> AsyncGenerator[bytes, None]:
                nonlocal chunks_sent
                for _ in range(10):
                    chunks_sent += 1
                    yield b"X" * 1000

        req = MockRequest()
        with pytest.raises(UploadTooLargeError) as exc_info:
            await read_request_stream_bounded(req, max_size=3500)

        assert exc_info.value.actual_size == 4000
        assert chunks_sent == 4  # Aborted at chunk 4 without reading remaining 6 chunks

    asyncio.run(_test())


# ==============================================================================
# 8. Defensive limit in chunk_evidence
# ==============================================================================


def test_chunk_evidence_defensive_size_limit():
    """chunk_evidence raises ValueError if data exceeds MAX_EVIDENCE_SIZE."""
    oversized = b"D" * (MAX_EVIDENCE_SIZE + 1)
    with pytest.raises(ValueError, match="exceeds limit"):
        chunk_evidence(oversized)


def test_chunk_evidence_empty_rejection():
    """chunk_evidence raises ValueError if data is empty."""
    with pytest.raises(ValueError, match="Cannot chunk empty evidence"):
        chunk_evidence(b"")


# ==============================================================================
# 9. Zero partial DB records or orphaned blobs in SQLite after 413 rejection
# ==============================================================================


def test_zero_partial_state_in_sqlite_after_oversized_evidence_rejection():
    """Rejected uploads leave zero orphaned records in SQLite."""
    create_res = client.post("/api/cases", json={"name": "Zero Partial State Case"})
    case_id = create_res.json()["case_id"]

    # 1. Attempt oversized multipart upload
    oversized = b"O" * (MAX_EVIDENCE_SIZE + 1024)
    res1 = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("oversized.img", oversized, "application/octet-stream")},
    )
    assert res1.status_code == 413

    # 2. Attempt oversized raw body upload
    res2 = client.post(
        f"/api/cases/{case_id}/evidence",
        content=oversized,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert res2.status_code == 413

    # 3. Query SQLite directly to verify zero evidence rows or chunks were stored
    with store._engine.transaction() as cursor:
        cursor.execute("SELECT COUNT(*) FROM evidence_files WHERE case_id = ?", (case_id,))
        ev_count = cursor.fetchone()[0]
        assert ev_count == 0, f"Expected 0 evidence_files rows, got {ev_count}"

        cursor.execute("SELECT COUNT(*) FROM evidence_chunks WHERE case_id = ?", (case_id,))
        chunk_count = cursor.fetchone()[0]
        assert chunk_count == 0, f"Expected 0 evidence_chunks rows, got {chunk_count}"

        cursor.execute("SELECT COUNT(*) FROM blobs WHERE blob_key LIKE ?", (f"%{case_id}%",))
        blob_count = cursor.fetchone()[0]
        assert blob_count == 0, f"Expected 0 blobs matching case_id, got {blob_count}"

    # Verify the case itself is unchanged with evidence=None
    case_res = client.get(f"/api/cases/{case_id}")
    assert case_res.status_code == 200
    assert case_res.json()["evidence"] is None
    assert case_res.json()["artifact_count"] == 0


def test_zero_partial_state_in_sqlite_after_oversized_recover_file_rejection():
    """Rejected /api/recover-file upload creates no database artifacts or recovery runs."""
    oversized = b"R" * (MAX_EVIDENCE_SIZE + 1024)
    res = client.post(
        "/api/recover-file",
        files={"file": ("bad_recovery.bin", oversized, "application/octet-stream")},
    )
    assert res.status_code == 413

    # Verify nothing was added to SQLite
    with store._engine.transaction() as cursor:
        cursor.execute("SELECT COUNT(*) FROM recovery_runs")
        run_count = cursor.fetchone()[0]
        assert run_count == 0, f"Expected 0 recovery_runs, got {run_count}"

        cursor.execute("SELECT COUNT(*) FROM artifacts")
        art_count = cursor.fetchone()[0]
        assert art_count == 0, f"Expected 0 artifacts, got {art_count}"

        cursor.execute("SELECT COUNT(*) FROM blobs")
        blob_count = cursor.fetchone()[0]
        assert blob_count == 0, f"Expected 0 blobs, got {blob_count}"


# ==============================================================================
# 10. Temporary file cleanup verification
# ==============================================================================


def test_temporary_spooled_file_cleanup_on_oversized_upload():
    """Verify that a temporary spooled file is closed when rejected."""
    import asyncio

    async def _test():
        # Create real NamedTemporaryFile backed UploadFile
        with tempfile.NamedTemporaryFile(delete=True) as tf:
            tf.write(b"T" * (MAX_EVIDENCE_SIZE + 100))
            tf.flush()
            tf.seek(0)

            upload_file = UploadFile(file=tf, filename="temp_oversized.bin")
            assert not tf.closed

            with pytest.raises(UploadTooLargeError):
                await read_upload_bounded(upload_file, max_size=MAX_EVIDENCE_SIZE)

            # Confirm the file handle was closed
            assert tf.closed

    asyncio.run(_test())
