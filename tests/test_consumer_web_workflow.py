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
    assert "not found or unrecoverable" in dl_res.json()["detail"]


def test_consumer_web_purged_file_download_returns_clear_404():
    """Verify that when a recovered file has expired or was purged, download fails with clear 404 detail."""
    payload = b'{"case_id":"CASE-77","target":"purge_test"}'
    res = client.post(
        "/api/recover-file",
        files={"file": ("purge_test.json", payload, "application/json")},
    )
    assert res.status_code == 200
    file_id = res.json()["file_id"]

    # Verify download succeeds initially
    dl1 = client.get(f"/api/recover-file/{file_id}/download")
    assert dl1.status_code == 200

    # Purge file from store (simulating 24h TTL expiration)
    store.clear()

    # Verify subsequent download fails with honest 404 detail
    dl2 = client.get(f"/api/recover-file/{file_id}/download")
    assert dl2.status_code == 404
    assert "not found or unrecoverable" in dl2.json()["detail"]


def test_consumer_web_alias_endpoints_match():
    """Verify that alias endpoints /api/recover/file and /api/recover/file/{id}/download function identically."""
    payload = b"id,name,role\n1,Alice,Lead\n2,Bob,Analyst\n"
    res = client.post(
        "/api/recover/file",
        files={"file": ("alias_test.csv", payload, "text/csv")},
    )
    assert res.status_code == 200
    data = res.json()
    file_id = data["file_id"]
    assert data["format"] == "csv"
    assert data["status"] == "FULLY_RECOVERED"

    # Download via alias path
    dl_alias = client.get(f"/api/recover/file/{file_id}/download")
    assert dl_alias.status_code == 200
    assert dl_alias.content == payload
    assert "text/csv" in dl_alias.headers["content-type"]


def test_consumer_web_all_8_formats_single_file_recovery_matrix():
    """Verify single-file consumer workflow for all 8 supported evidence formats."""
    from tests.test_independent_parsers_8_formats import _make_minimal_png
    from tests.test_pdf_recovery import build_minimal_pdf
    valid_png = _make_minimal_png(width=8, height=8, include_iend=True)
    valid_pdf = build_minimal_pdf()

    test_cases = [
        ("evidence.txt", b"Incident report log text.\n", "txt", "text/plain"),
        ("config.json", b'{"service":"proxy","port":8080}', "json", "application/json"),
        ("metrics.csv", b"timestamp,cpu,mem\n1000,12.5,45.2\n", "csv", "text/csv"),
        ("report.xml", b'<?xml version="1.0"?><note><to>IR</to></note>', "xml", "application/xml"),
        ("photo.png", valid_png, "png", "image/png"),
        ("photo.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00\xff\xd9", "jpeg", "image/jpeg"),
        ("document.pdf", valid_pdf, "pdf", "application/pdf"),
        ("archive.zip", b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00testPK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00testPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x002\x00\x00\x00\x1e\x00\x00\x00\x00\x00", "zip", "application/zip"),
    ]

    for fname, content, expected_fmt, mime in test_cases:
        res = client.post(
            "/api/recover-file",
            files={"file": (fname, content, mime)},
        )
        assert res.status_code == 200, f"Failed recovery for {fname}: {res.text}"
        data = res.json()
        assert data["format"] == expected_fmt
        assert data["is_downloadable"] is True, f"Format {fname} ({expected_fmt}) was not downloadable. Details: {data}"
        assert data["verified_bytes"] > 0
        assert data["status"] in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")

        # Verify download
        dl = client.get(data["download_url"])
        assert dl.status_code == 200
        assert len(dl.content) > 0
        assert mime in dl.headers["content-type"]


def test_consumer_web_download_endpoint_path_traversal_protection():
    """Verify backend rejects traversal attempts on download endpoints with 404."""
    res1 = client.get("/api/recover-file/..%2f..%2fetc%2fpasswd/download")
    assert res1.status_code in (404, 422)

    res2 = client.get("/api/recover-file/rec_file_invalid_99999/download")
    assert res2.status_code == 404
    assert "not found or unrecoverable" in res2.json()["detail"]
