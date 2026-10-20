"""
tests/test_api_contracts_and_error_normalization_step4.py — Step 4 Regression Suite.

Verifies API contract correctness, identifier cross-resolution (run_id vs artifact_id),
error normalization, download security hardening, and rate-limiting integrity:
  1. GET /api/artifacts/{id} resolves standalone recovered file without AttributeError.
  2. GET /api/artifacts/{run_id}/download resolves payload when queried by run_id.
  3. GET /api/recover-file/{run_id}/download resolves payload when queried by run_id.
  4. Content-Disposition filename sanitization prevents header injection in download routes.
  5. Global exception handler returns structured 500 JSON without exposing internal paths.
  6. GET /api/cases/{case_id}/groundtruth returns 404 for non-existent cases.
  7. Rate limit 429 response structure, retry_after value, and Retry-After header.
  8. Rate limit dictionary memory pruning on expired IP histories.
  9. Artifact explanation endpoint persists ai_summary to SQLite database.
  10. Strict 404 rejection on unvalidated or unrecoverable downloads across all download endpoints.
"""

from __future__ import annotations

import io
import time
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app, reset_rate_limits, _ip_request_history
from backend.app.models.artifact import ArtifactRecord
from backend.app.models.recovery_run import RecoveryRun
from backend.app.store import store


@pytest.fixture(autouse=True)
def clean_rate_limits():
    """Ensure rate-limit state is reset before and after each test."""
    reset_rate_limits()
    yield
    reset_rate_limits()


@pytest.fixture
def client():
    """FastAPI test client with server exceptions captured by handlers."""
    return TestClient(app, raise_server_exceptions=False)


# ── 1. GET /api/artifacts/{id} Standalone File Resolution ────────────────────


def test_01_get_artifact_resolves_standalone_file_without_attribute_error(client: TestClient):
    """GET /api/artifacts/{id} on a standalone file must use to_artifact_response()
    and must not crash with AttributeError: 'ArtifactRecord' object has no attribute 'to_response'.
    """
    file_id = "rec_file_step4_test01"
    meta = {
        "file_id": file_id,
        "original_filename": "standalone_doc.txt",
        "recovered_filename": "recovered_standalone_doc.txt",
        "format": "txt",
        "status": "FULLY_RECOVERED",
        "confidence_score": 95.0,
        "verified_bytes": 100,
        "reconstructed_bytes": 0,
        "missing_bytes": 0,
        "reconstruction_method": "NONE",
        "validation_status": "PASSED",
        "is_downloadable": True,
        "content_preview": "Valid recovered text",
    }
    store.store_recovered_file(file_id, meta, b"Valid recovered text payload")

    resp = client.get(f"/api/artifacts/{file_id}")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["artifact_id"] == file_id
    assert data["status"] == "FULLY_RECOVERED"
    assert data["format"] == "txt"


# ── 2. GET /api/artifacts/{run_id}/download Payload Resolution ───────────────


def test_02_download_artifact_by_run_id_resolves_payload(client: TestClient):
    """GET /api/artifacts/{run_id}/download must retrieve the payload byte buffer
    even when called with run_id rather than artifact_id.
    """
    art_id = "art_step4_case_run_02"
    run_id = "run_step4_case_02"

    rec = ArtifactRecord(
        artifact_id=art_id,
        run_id=run_id,
        format="json",
        status="FULLY_RECOVERED",
        confidence_score=90.0,
        verified_bytes=50,
        is_downloadable=True,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes(art_id, b'{"status": "ok", "recovered": true}')

    run = RecoveryRun(
        run_id=run_id,
        artifact_id=art_id,
        filename="payload.json",
        format="json",
        status="FULLY_RECOVERED",
        started_at=datetime.now(timezone.utc),
        total_input_bytes=50,
        total_verified_bytes=50,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
    )
    store.add_recovery_run(run)

    # Download querying by run_id
    resp = client.get(f"/api/artifacts/{run_id}/download")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.content == b'{"status": "ok", "recovered": true}'
    assert "attachment" in resp.headers.get("content-disposition", "")


# ── 3. GET /api/recover-file/{run_id}/download Payload Resolution ─────────────


def test_03_download_recovered_file_by_run_id_resolves_payload(client: TestClient):
    """GET /api/recover-file/{run_id}/download must retrieve the payload byte buffer
    even when queried using run_id instead of file_id.
    """
    file_id = "rec_file_step4_03"
    run_id = "run_step4_03"
    meta = {
        "file_id": file_id,
        "run_id": run_id,
        "original_filename": "data.csv",
        "recovered_filename": "recovered_data.csv",
        "format": "csv",
        "status": "PARTIALLY_RECOVERED",
        "confidence_score": 80.0,
        "verified_bytes": 40,
        "reconstructed_bytes": 0,
        "missing_bytes": 10,
        "reconstruction_method": "NONE",
        "validation_status": "PASSED",
        "is_downloadable": True,
    }
    store.store_recovered_file(file_id, meta, b"id,name\n1,Alice\n2,Bob\n")

    run = RecoveryRun(
        run_id=run_id,
        artifact_id=file_id,
        filename="data.csv",
        format="csv",
        status="PARTIALLY_RECOVERED",
        started_at=datetime.now(timezone.utc),
        total_input_bytes=50,
        total_verified_bytes=40,
        total_reconstructed_bytes=0,
        total_missing_bytes=10,
    )
    store.add_recovery_run(run)

    resp = client.get(f"/api/recover-file/{run_id}/download")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.content == b"id,name\n1,Alice\n2,Bob\n"
    assert "text/csv" in resp.headers.get("content-type", "")


# ── 4. Download Header Sanitization & Injection Defense ───────────────────────


def test_04_download_header_sanitization_prevents_injection(client: TestClient):
    """Filenames with CRLF, path traversal, or quotation marks must be sanitized
    to prevent HTTP header injection.
    """
    art_id = "art_step4_injection_04"
    malicious_filename = "report\r\nInjected-Header: evil\r\nfilename=hack.exe"

    rec = ArtifactRecord(
        artifact_id=art_id,
        recovered_filename=malicious_filename,
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=100.0,
        verified_bytes=10,
        is_downloadable=True,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes(art_id, b"safe payload")

    resp = client.get(f"/api/artifacts/{art_id}/download")
    assert resp.status_code == 200
    cd = resp.headers.get("content-disposition", "")
    assert "\r" not in cd
    assert "\n" not in cd
    assert "Injected-Header" not in resp.headers


# ── 5. Global Exception Handler Normalization ─────────────────────────────────


def test_05_global_exception_handler_returns_safe_500(client: TestClient, monkeypatch):
    """Unhandled internal errors must return structured JSON 500 without leaking secrets or filepaths."""
    # Monkeypatch a route or store method to raise an unexpected runtime error
    def broken_get_case(case_id: str):
        raise RuntimeError("Database connection lost at /private/var/keys/secret.pem")

    monkeypatch.setattr(store, "get_case", broken_get_case)

    resp = client.get("/api/cases/test_broken_case")
    assert resp.status_code == 500
    data = resp.json()
    assert "detail" in data
    assert "secret.pem" not in resp.text
    assert "private" not in resp.text


# ── 6. GET /api/cases/{case_id}/groundtruth Non-Existent Case ─────────────────


def test_06_groundtruth_returns_404_on_missing_case(client: TestClient):
    """GET /api/cases/{case_id}/groundtruth must return 404 if the case does not exist."""
    resp = client.get("/api/cases/non_existent_case_step4_999/groundtruth")
    assert resp.status_code == 404
    data = resp.json()
    assert "not found" in data["detail"].lower()


# ── 7. Rate Limit 429 Response Details and Headers ───────────────────────────


def test_07_rate_limit_429_detail_and_headers(client: TestClient):
    """Submitting more than 60 recovery requests per minute from a client IP
    must trigger HTTP 429 with RATE_LIMIT_EXCEEDED, retry_after, and Retry-After header.
    """
    reset_rate_limits()
    test_file = io.BytesIO(b"Hello forensic world")

    # Fast forward request count to limit
    for _ in range(60):
        test_file.seek(0)
        resp = client.post("/api/recover-file", files={"file": ("test.txt", test_file, "text/plain")})
        assert resp.status_code in (200, 429)
        if resp.status_code == 429:
            break

    # 61st request must be 429
    test_file.seek(0)
    resp = client.post("/api/recover-file", files={"file": ("test.txt", test_file, "text/plain")})
    assert resp.status_code == 429
    data = resp.json()
    assert data["detail"] == "RATE_LIMIT_EXCEEDED"
    assert "retry_after" in data
    assert "Retry-After" in resp.headers
    assert int(resp.headers["Retry-After"]) >= 1


# ── 8. Rate Limit IP History Pruning ─────────────────────────────────────────


def test_08_rate_limit_history_pruning(monkeypatch):
    """Expired timestamps must be pruned from _ip_request_history to prevent unbounded memory growth."""
    reset_rate_limits()
    client_ip = "192.168.1.100"
    old_time = time.time() - 120.0  # 2 minutes ago (beyond 60s window)

    # Configure testclient as a trusted proxy so X-Forwarded-For is respected
    monkeypatch.setenv("RECOVERIX_TRUSTED_PROXIES", "testclient")
    _ip_request_history[client_ip] = [old_time]

    # Trigger rate limit middleware via client
    client = TestClient(app)
    test_file = io.BytesIO(b"Valid evidence")
    resp = client.post(
        "/api/recover-file",
        files={"file": ("test.txt", test_file, "text/plain")},
        headers={"X-Forwarded-For": client_ip},
    )
    assert resp.status_code == 200

    # Old timestamp must be evicted and only fresh timestamp retained
    history = _ip_request_history.get(client_ip)
    assert history is not None
    assert old_time not in history
    assert len(history) == 1


# ── 9. Artifact Explanation SQLite Persistence ────────────────────────────────


def test_09_artifact_explain_persists_to_sqlite(client: TestClient):
    """POST /api/artifacts/{id}/explain must persist generated ai_summary to SQLite."""
    art_id = "art_step4_explain_09"
    rec = ArtifactRecord(
        artifact_id=art_id,
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=95.0,
        verified_bytes=30,
        is_downloadable=True,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes(art_id, b"Investigation notes for court")

    resp = client.post(f"/api/artifacts/{art_id}/explain")
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data

    # Reload directly from SQLite store
    loaded_art = store.get_artifact(art_id)
    assert loaded_art is not None
    assert loaded_art.ai_summary is not None


# ── 10. Strict 404 Rejection on Unvalidated or Unrecoverable Downloads ────────


def test_10_strict_rejection_on_unvalidated_or_failed_downloads(client: TestClient):
    """Unvalidated, FAILED, or UNRECOVERABLE artifacts must never be downloadable
    on either case artifact or single file download routes.
    """
    art_id = "art_step4_failed_10"
    rec = ArtifactRecord(
        artifact_id=art_id,
        format="json",
        status="UNRECOVERABLE",
        confidence_score=10.0,
        verified_bytes=0,
        validation_status="FAILED",
        is_downloadable=False,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes(art_id, b"{corrupted")

    # Case artifact download
    r1 = client.get(f"/api/artifacts/{art_id}/download")
    assert r1.status_code == 404

    # Single-file recovery download
    r2 = client.get(f"/api/recover-file/{art_id}/download")
    assert r2.status_code == 404
