"""
tests/test_consumer_web_workflow.py — Consumer web workflow and API integration audit.

Verifies:
  1. Complete 1-step single file upload, analysis, metadata retrieval, and download.
  2. Safe error states: empty file (400), oversized file (413), missing file ID (404), unrecoverable file download (404).
  3. Grounded explanation endpoint: /api/recover-file/{file_id}/explain.
  4. Response models and headers across desktop and mobile scenarios.
"""

from fastapi.testclient import TestClient
import pytest

from backend.app.main import app, reset_rate_limits
from backend.app.store import store, MAX_EVIDENCE_SIZE
from backend.app.recovery.signatures import SYNTHETIC_START_MARKER, SYNTHETIC_END_MARKER

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_state():
    store.clear()
    reset_rate_limits()
    yield
    store.clear()
    reset_rate_limits()


def test_consumer_web_full_happy_path_txt():
    """Verify consumer web workflow: upload -> analyze -> metadata -> download -> explain."""
    file_bytes = b"Sample diagnostic evidence report for mobile/desktop recovery audit.\n"
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Audit\nBody: " + file_bytes + SYNTHETIC_END_MARKER

    # 1. Upload & Analyze
    res = client.post(
        "/api/recover-file",
        files={"file": ("mobile_upload_evidence.txt", payload, "text/plain")},
        headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"},
    )
    assert res.status_code == 200
    data = res.json()
    file_id = data["file_id"]
    assert file_id.startswith("rec_file_")
    assert len(file_id) >= 32  # 128-bit unguessable identifier
    assert data["status"] in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")
    assert data["is_downloadable"] is True
    assert data["download_url"] == f"/api/recover-file/{file_id}/download"
    assert data["original_filename"] == "mobile_upload_evidence.txt"
    assert data["recovered_filename"] == "recovered_mobile_upload_evidence.txt"
    assert data["verified_bytes"] > 0
    assert data["total_input_bytes"] == len(payload)

    # 2. Retrieve Metadata
    meta_res = client.get(f"/api/recover-file/{file_id}")
    assert meta_res.status_code == 200
    meta_data = meta_res.json()
    assert meta_data["file_id"] == file_id
    assert meta_data["confidence_score"] == data["confidence_score"]

    # 3. Download Recovered Raw Bytes
    dl_res = client.get(data["download_url"])
    assert dl_res.status_code == 200
    assert dl_res.content == payload
    assert dl_res.headers["content-type"] == "text/plain; charset=utf-8" or "text/plain" in dl_res.headers["content-type"]
    assert 'attachment; filename="recovered_mobile_upload_evidence.txt"' in dl_res.headers["Content-Disposition"]

    # 4. Grounded AI Explanation
    explain_res = client.post(f"/api/recover-file/{file_id}/explain")
    assert explain_res.status_code == 200
    explain_data = explain_res.json()
    assert "summary" in explain_data
    assert "assessment" in explain_data
    assert "details" in explain_data
    assert "why_it_matters" in explain_data
    assert explain_data.get("available") is True




def test_consumer_web_empty_file_rejected_400():
    """Verify empty evidence upload returns 400 with honest error detail."""
    res = client.post(
        "/api/recover-file",
        files={"file": ("empty.json", b"", "application/json")},
    )
    assert res.status_code == 400
    assert res.json()["detail"] == "EMPTY_FILE"


def test_consumer_web_oversized_file_rejected_413():
    """Verify upload exceeding 5 MiB ceiling is rejected with 413."""
    oversized = b"X" * (MAX_EVIDENCE_SIZE + 1024)
    res = client.post(
        "/api/recover-file",
        files={"file": ("huge.zip", oversized, "application/zip")},
    )
    assert res.status_code == 413
    assert res.json()["detail"] == "FILE_TOO_LARGE"


def test_consumer_web_unrecoverable_file_download_rejected_404():
    """Verify unrecoverable files cannot be downloaded."""
    garbage = b"\x00\x01\x02\x03\x04\x05\x06\x07" * 32
    res = client.post(
        "/api/recover-file",
        files={"file": ("garbage.bin", garbage, "application/octet-stream")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "UNRECOVERABLE"
    assert data["is_downloadable"] is False

    dl_res = client.get(data["download_url"])
    assert dl_res.status_code == 404


def test_consumer_web_nonexistent_file_metadata_and_download_404():
    """Verify non-existent file ID returns 404."""
    meta_res = client.get("/api/recover-file/rec_file_nonexistent_12345")
    assert meta_res.status_code == 404

    dl_res = client.get("/api/recover-file/rec_file_nonexistent_12345/download")
    assert dl_res.status_code == 404
