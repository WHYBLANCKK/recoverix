"""
test_file_recovery.py — Integration test suite for single-file recovery and download endpoints.
"""

import io
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app, reset_rate_limits
from backend.app.store import store
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_store():
    store.clear()
    reset_rate_limits()
    yield
    store.clear()
    reset_rate_limits()


def test_recover_single_file_success_txt():
    """Test recovering a single TXT file with synthetic markers."""
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Test\nBody: Hello Single File Recovery\n" + SYNTHETIC_END_MARKER

    response = client.post(
        "/api/recover-file",
        files={"file": ("damaged_sample.txt", payload, "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["original_filename"] == "damaged_sample.txt"
    assert data["recovered_filename"] == "recovered_damaged_sample.txt"
    assert data["format"] == "txt"
    assert data["status"] == "FULLY_RECOVERED"
    assert data["confidence_score"] == 100.0
    assert data["is_downloadable"] is True
    assert "download_url" in data
    assert "Hello Single File Recovery" in (data["content_preview"] or "")


def test_recover_single_file_download_exact_bytes():
    """Test downloading the recovered file buffer and asserting exact byte equality."""
    expected_recovered = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Test\nBody: Exact Bytes Test\n" + SYNTHETIC_END_MARKER
    evidence_with_padding = b"PADDING_BEFORE" + expected_recovered + b"PADDING_AFTER"

    response = client.post(
        "/api/recover-file",
        files={"file": ("evidence.bin", evidence_with_padding, "application/octet-stream")},
    )

    assert response.status_code == 200
    data = response.json()
    file_id = data["file_id"]
    download_url = data["download_url"]

    # Perform byte download
    dl_response = client.get(download_url)
    assert dl_response.status_code == 200
    assert "text/plain" in dl_response.headers["content-type"]
    assert "attachment; filename=\"recovered_evidence.bin\"" in dl_response.headers["content-disposition"]
    assert dl_response.content == expected_recovered


def test_recover_single_file_unrecoverable():
    """Test uploading random unrecoverable corrupt bytes."""
    corrupt_bytes = b"\x00\x99\xff\xfe\xdc\xba\x88\x77\x66\x55\x44"

    response = client.post(
        "/api/recover-file",
        files={"file": ("corrupt.raw", corrupt_bytes, "application/octet-stream")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNRECOVERABLE"
    assert data["confidence_score"] == 0.0
    assert data["is_downloadable"] is False
    assert data["verified_bytes"] == 0


def test_recover_single_file_download_unrecoverable_404():
    """Test downloading an unrecoverable file ID returns 404."""
    corrupt_bytes = b"\x00\x99\xff\xfe\xdc\xba"

    response = client.post(
        "/api/recover-file",
        files={"file": ("corrupt.raw", corrupt_bytes, "application/octet-stream")},
    )

    data = response.json()
    file_id = data["file_id"]

    dl_response = client.get(f"/api/recover-file/{file_id}/download")
    assert dl_response.status_code == 404


def test_recover_single_file_empty_400():
    """Test uploading an empty file returns 400 Bad Request."""
    response = client.post(
        "/api/recover-file",
        files={"file": ("empty.txt", b"", "text/plain")},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "EMPTY_FILE"


def test_recover_single_file_too_large_413():
    """Test uploading a file larger than 5 MB returns 413 Payload Too Large."""
    oversized = b"A" * (5 * 1024 * 1024 + 1)
    response = client.post(
        "/api/recover-file",
        files={"file": ("large.txt", oversized, "text/plain")},
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "FILE_TOO_LARGE"


def test_download_case_artifact():
    """Test downloading a case artifact directly via /api/artifacts/{artifact_id}/download."""
    case_resp = client.post("/api/cases", json={"name": "Case Download Test"}).json()
    case_id = case_resp["case_id"]

    artifact_payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Case\nBody: Artifact Download\n" + SYNTHETIC_END_MARKER
    client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("evidence.img", artifact_payload, "application/octet-stream")},
    )

    analysis_res = client.post(f"/api/cases/{case_id}/analyze").json()
    assert analysis_res["artifact_count"] >= 1
    artifact_id = analysis_res["artifacts"][0]["artifact_id"]

    dl_res = client.get(f"/api/artifacts/{artifact_id}/download")
    assert dl_res.status_code == 200
    assert dl_res.content == artifact_payload


def test_rate_limiting_single_file_recovery(monkeypatch):
    """Test that rate limiting enforces 60 requests/minute per IP and can be disabled."""
    from backend.app.main import _ip_request_history, RATE_LIMIT_MAX_REQUESTS

    # Pre-populate history with 60 requests for test client IP
    test_ip = "testclient"
    import time
    now = time.time()
    _ip_request_history[test_ip] = [now - 10.0] * RATE_LIMIT_MAX_REQUESTS

    # The 61st request should be rejected with 429
    res = client.post(
        "/api/recover-file",
        files={"file": ("test.txt", b"dummy", "text/plain")},
    )
    assert res.status_code == 429
    data = res.json()
    assert data["detail"] == "RATE_LIMIT_EXCEEDED"
    assert "retry_after" in data
    assert "Retry-After" in res.headers

    # With RECOVERIX_DISABLE_RATE_LIMIT=1, the request should proceed past rate limit
    monkeypatch.setenv("RECOVERIX_DISABLE_RATE_LIMIT", "1")
    res_disabled = client.post(
        "/api/recover-file",
        files={"file": ("test.txt", b"FORMAT=txt\nHeader: H\nBody: B\n", "text/plain")},
    )
    assert res_disabled.status_code == 200


def test_filename_sanitization_and_content_disposition():
    """Verify malicious filenames are safely sanitized and headers prevent injection."""
    from backend.app.api.file_recovery import sanitize_filename, format_content_disposition

    # 1. Path traversal
    assert sanitize_filename("../../../etc/shadow") == "shadow"
    assert sanitize_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"

    # 2. Control characters & CRLF
    assert sanitize_filename("file\r\nSet-Cookie: evil=1\r\n.txt") == "fileSet-Cookie_ evil=1.txt" or "evil" in sanitize_filename("file\r\nSet-Cookie: evil=1\r\n.txt")
    assert "\r" not in sanitize_filename("foo\r\nbar.pdf")
    assert "\n" not in sanitize_filename("foo\r\nbar.pdf")

    # 3. Quotes and dangerous symbols
    clean = sanitize_filename('my"dangerous\\file:name;test<>.json')
    assert '"' not in clean
    assert '\\' not in clean
    assert ':' not in clean
    assert ';' not in clean
    assert '<' not in clean
    assert '>' not in clean

    # 4. Long filenames (> 128 chars) truncated safely
    long_name = "a" * 200 + ".pdf"
    sanitized_long = sanitize_filename(long_name)
    assert len(sanitized_long) <= 128
    assert sanitized_long.endswith(".pdf")

    # 5. Empty / whitespace fallbacks
    assert sanitize_filename("") == "recovered_file.bin"
    assert sanitize_filename("   ") == "recovered_file.bin"
    assert sanitize_filename("..") == "recovered_file.bin"

    # 6. Content-Disposition formatting
    header = format_content_disposition('test "quote" & unicode \u2764.txt')
    assert "\r" not in header
    assert "\n" not in header
    assert 'filename="' in header
    assert "filename*=UTF-8''" in header

    # 7. End-to-end download header test
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: H\nBody: Sanitized Name\n" + SYNTHETIC_END_MARKER
    res = client.post(
        "/api/recover-file",
        files={"file": ("../../evil\r\nfilename.txt", payload, "text/plain")},
    )
    assert res.status_code == 200
    data = res.json()
    assert "\r" not in data["original_filename"]
    assert "\n" not in data["original_filename"]
    assert "/" not in data["original_filename"]
    assert "\\" not in data["original_filename"]

    # Download check
    dl_res = client.get(data["download_url"])
    assert dl_res.status_code == 200
    cd = dl_res.headers.get("Content-Disposition", "")
    assert "\r" not in cd
    assert "\n" not in cd
    assert 'filename="' in cd


def test_trusted_proxy_rate_limit_spoof_defense(monkeypatch):
    """Verify X-Forwarded-For is only respected when client IP matches RECOVERIX_TRUSTED_PROXIES."""
    from backend.app.main import resolve_client_ip
    from starlette.datastructures import Headers

    class DummyClient:
        def __init__(self, host):
            self.host = host

    class DummyRequest:
        def __init__(self, client_host, headers_dict):
            self.client = DummyClient(client_host)
            self.headers = Headers(headers_dict)

    # 1. Untrusted client attempting to spoof IP via X-Forwarded-For
    req_untrusted = DummyRequest("203.0.113.5", {"x-forwarded-for": "198.51.100.1"})
    assert resolve_client_ip(req_untrusted) == "203.0.113.5"

    # 2. Trusted proxy forwarding real client IP
    monkeypatch.setenv("RECOVERIX_TRUSTED_PROXIES", "127.0.0.1,10.0.0.1")
    req_trusted = DummyRequest("10.0.0.1", {"x-forwarded-for": "198.51.100.2, 10.0.0.1"})
    assert resolve_client_ip(req_trusted) == "198.51.100.2"

    # 3. Client attempting to prepend spoofed IP to XFF through trusted proxy (must pick real rightmost client)
    req_spoof_attempt = DummyRequest("10.0.0.1", {"x-forwarded-for": "8.8.8.8, 198.51.100.2, 10.0.0.1"})
    assert resolve_client_ip(req_spoof_attempt) == "198.51.100.2"

    # 4. Cloudflare edge header (cf-connecting-ip) takes precedence and cannot be spoofed
    req_cf = DummyRequest("10.0.0.1", {
        "cf-connecting-ip": "198.51.100.2",
        "x-forwarded-for": "8.8.8.8, 198.51.100.2, 10.0.0.1"
    })
    assert resolve_client_ip(req_cf) == "198.51.100.2"

    # 5. Private network proxy trust (recommended for Render internal mesh)
    monkeypatch.setenv("RECOVERIX_TRUSTED_PROXIES", "private")
    req_cloud_proxy = DummyRequest("10.123.45.67", {"x-forwarded-for": "203.0.113.99, 10.123.45.67"})
    assert resolve_client_ip(req_cloud_proxy) == "203.0.113.99"

    # 6. Direct public client when RECOVERIX_TRUSTED_PROXIES=private must NOT be trusted
    req_direct_public = DummyRequest("142.250.190.46", {"x-forwarded-for": "8.8.8.8"})
    assert resolve_client_ip(req_direct_public) == "142.250.190.46"


def test_standalone_file_purge_24h_ttl():
    """Verify that standalone recovered files older than 24 hours are purged."""
    import time
    from backend.app.storage.memory_store import InMemoryStore

    mem_store = InMemoryStore()
    file_id = "test_purge_file_1"
    meta = {
        "file_id": file_id,
        "format": "txt",
        "status": "FULLY_RECOVERED",
        "confidence_score": 100.0,
        "verified_bytes": 10,
        "reconstructed_bytes": 0,
        "missing_bytes": 0,
    }
    mem_store.store_recovered_file(file_id, meta, b"test payload")
    assert mem_store.get_recovered_file_metadata(file_id) is not None

    # Simulate 25 hours elapsed
    mem_store._artifact_timestamps[file_id] = time.time() - (25 * 3600)

    purged_count = mem_store.purge_expired_recovered_files(ttl_hours=24)
    assert purged_count == 1
    assert mem_store.get_recovered_file_metadata(file_id) is None
    assert mem_store.get_recovered_file_bytes(file_id) is None


def test_recover_single_file_metadata_persistence():
    """Verify that case_name, investigator, and notes form fields persist in SQLite and are returned across endpoints."""
    payload = b'{"case":"IR-500","severity":"HIGH","active":true}'
    res = client.post(
        "/api/recover-file",
        files={"file": ("evidence.json", payload, "application/json")},
        data={
            "case_name": "Operation Blackbird",
            "investigator": "Agent Fox",
            "notes": "Found on seized flash drive partition.",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["case_name"] == "Operation Blackbird"
    assert data["investigator"] == "Agent Fox"
    assert data["notes"] == "Found on seized flash drive partition."
    file_id = data["file_id"]
    run_id = data["run_id"]

    # Verify GET /api/recover-file/{file_id} returns the metadata
    file_res = client.get(f"/api/recover-file/{file_id}")
    assert file_res.status_code == 200
    file_data = file_res.json()
    assert file_data["case_name"] == "Operation Blackbird"
    assert file_data["investigator"] == "Agent Fox"
    assert file_data["notes"] == "Found on seized flash drive partition."

    # Verify GET /api/recovery-runs/{run_id} returns the metadata
    run_res = client.get(f"/api/recovery-runs/{run_id}")
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["case_name"] == "Operation Blackbird"
    assert run_data["investigator"] == "Agent Fox"
    assert run_data["notes"] == "Found on seized flash drive partition."

    # Verify lookup by artifact_id (file_id) works on /api/recovery-runs/{file_id}
    run_by_art_res = client.get(f"/api/recovery-runs/{file_id}")
    assert run_by_art_res.status_code == 200
    assert run_by_art_res.json()["run_id"] == run_id

    # Verify GET /api/artifacts/{file_id} resolves without 404
    art_res = client.get(f"/api/artifacts/{file_id}")
    assert art_res.status_code == 200
    assert art_res.json()["status"] == "FULLY_RECOVERED"


def test_recover_single_file_omitted_and_whitespace_metadata_returns_null():
    """Verify that omitting metadata or supplying whitespace-only fields normalizes cleanly to None."""
    payload = b'{"case":"OMITTED_TEST","valid":true}'
    res = client.post(
        "/api/recover-file",
        files={"file": ("omitted.json", payload, "application/json")},
        data={
            "case_name": "   ",
            "investigator": "",
            "notes": "  \t\n  ",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["case_name"] is None
    assert data["investigator"] is None
    assert data["notes"] is None
    file_id = data["file_id"]
    run_id = data["run_id"]

    # Verify GET /api/recover-file/{file_id}
    file_res = client.get(f"/api/recover-file/{file_id}")
    assert file_res.status_code == 200
    file_data = file_res.json()
    assert file_data["case_name"] is None
    assert file_data["investigator"] is None
    assert file_data["notes"] is None

    # Verify GET /api/recovery-runs/{run_id}
    run_res = client.get(f"/api/recovery-runs/{run_id}")
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["case_name"] is None
    assert run_data["investigator"] is None
    assert run_data["notes"] is None


def test_recover_single_file_metadata_sanitization_and_truncation():
    """Verify that dangerous control characters are stripped and oversized metadata is safely bounded."""
    oversized_case = "Case-\x00\x07\x1b" + ("A" * 200)
    oversized_investigator = "Analyst-\x00" + ("B" * 200)
    oversized_notes = "Notes-\x00" + ("C" * 1500)

    payload = b'{"status":"sanitization_test"}'
    res = client.post(
        "/api/recover-file",
        files={"file": ("sanitized.json", payload, "application/json")},
        data={
            "case_name": oversized_case,
            "investigator": oversized_investigator,
            "notes": oversized_notes,
        },
    )
    assert res.status_code == 200
    data = res.json()

    # Bounded length checks
    assert len(data["case_name"]) <= 128
    assert len(data["investigator"]) <= 128
    assert len(data["notes"]) <= 1000

    # Control character elimination checks
    assert "\x00" not in data["case_name"]
    assert "\x07" not in data["case_name"]
    assert "\x1b" not in data["case_name"]
    assert "\x00" not in data["investigator"]
    assert "\x00" not in data["notes"]

    assert data["case_name"].startswith("Case-")
    assert data["investigator"].startswith("Analyst-")
    assert data["notes"].startswith("Notes-")


def test_recover_single_file_metadata_with_download_safety_invariants():
    """Verify that attaching metadata preserves download safety invariants across valid and invalid recoveries."""
    # 1. Unrecoverable file with metadata: must NOT be downloadable
    corrupt_bytes = b"\x00\x99\xff\xfe\xdc\xba\x88\x77"
    res_unrec = client.post(
        "/api/recover-file",
        files={"file": ("corrupt.raw", corrupt_bytes, "application/octet-stream")},
        data={
            "case_name": "Dead Evidence Case",
            "investigator": "Analyst Zero",
            "notes": "Severe medium damage; salvage attempted.",
        },
    )
    assert res_unrec.status_code == 200
    data_unrec = res_unrec.json()
    assert data_unrec["status"] == "UNRECOVERABLE"
    assert data_unrec["is_downloadable"] is False
    assert data_unrec["case_name"] == "Dead Evidence Case"

    # Attempting to download must return 404
    dl_unrec = client.get(data_unrec["download_url"])
    assert dl_unrec.status_code == 404

    # 2. Fully recovered file with metadata: must download exact expected bytes
    valid_payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: MetaTest\nBody: Safe Download\n" + SYNTHETIC_END_MARKER
    res_valid = client.post(
        "/api/recover-file",
        files={"file": ("safe_evidence.txt", valid_payload, "text/plain")},
        data={
            "case_name": "Integrity Test Case",
            "investigator": "Lead Auditor",
            "notes": "Verified download check.",
        },
    )
    assert res_valid.status_code == 200
    data_valid = res_valid.json()
    assert data_valid["is_downloadable"] is True
    assert data_valid["case_name"] == "Integrity Test Case"

    dl_valid = client.get(data_valid["download_url"])
    assert dl_valid.status_code == 200
    assert dl_valid.content == valid_payload
    assert "safe_evidence.txt" in dl_valid.headers.get("Content-Disposition", "")


def test_workbench_contract_file_id_lookup():
    """Verify Phase 2B.2 contract harmonization: both /api/recover-file and /api/artifacts resolve file_id."""
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: WorkbenchTest\nBody: Investigation Trace\n" + SYNTHETIC_END_MARKER
    post_res = client.post(
        "/api/recover-file",
        files={"file": ("workbench_doc.txt", payload, "text/plain")},
        data={"case_name": "Audit Case 99", "investigator": "Forensic Lead", "notes": "Contract check"},
    )
    assert post_res.status_code == 200
    file_data = post_res.json()
    file_id = file_data["file_id"]
    run_id = file_data["run_id"]

    # 1. Fetch by file_id on /api/recover-file/{file_id}
    res_rec = client.get(f"/api/recover-file/{file_id}")
    assert res_rec.status_code == 200
    rec_data = res_rec.json()
    assert rec_data["file_id"] == file_id
    assert rec_data["run_id"] == run_id
    assert rec_data["status"] == "FULLY_RECOVERED"
    assert rec_data["validation_status"] == "PASSED"
    assert rec_data["is_downloadable"] is True
    assert rec_data["verified_bytes"] > 0
    assert rec_data["missing_bytes"] == 0
    assert rec_data["case_name"] == "Audit Case 99"
    assert rec_data["investigator"] == "Forensic Lead"

    # 2. Fetch by file_id on /api/artifacts/{file_id} (Universal Artifact Resolver)
    res_art = client.get(f"/api/artifacts/{file_id}")
    assert res_art.status_code == 200
    art_data = res_art.json()
    assert art_data["artifact_id"] == file_id
    assert art_data["status"] == "FULLY_RECOVERED"
    assert art_data["provenance"]["validation_status"] == "PASSED"
    assert art_data["provenance"]["verified_bytes"] == rec_data["verified_bytes"]


def test_workbench_contract_run_id_lookup():
    """Verify Phase 2B.2 contract harmonization: /api/recovery-runs resolves by run_id and artifact/file_id."""
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: RunTrace\nBody: Trace Verification\n" + SYNTHETIC_END_MARKER
    post_res = client.post(
        "/api/recover-file",
        files={"file": ("trace_doc.txt", payload, "text/plain")},
    )
    assert post_res.status_code == 200
    data = post_res.json()
    file_id = data["file_id"]
    run_id = data["run_id"]

    # Fetch by run_id
    res_run = client.get(f"/api/recovery-runs/{run_id}")
    assert res_run.status_code == 200
    run_data = res_run.json()
    assert run_data["run_id"] == run_id
    assert run_data["status"] == "FULLY_RECOVERED"
    assert len(run_data["fragments"]) > 0

    # Fetch by file_id / artifact_id alias on /api/recovery-runs
    res_alias = client.get(f"/api/recovery-runs/{file_id}")
    assert res_alias.status_code == 200
    alias_data = res_alias.json()
    assert alias_data["run_id"] == run_id


def test_workbench_contract_unknown_and_expired_404():
    """Verify unknown or expired IDs return 404 without crashing or returning mock fallbacks."""
    fake_id = "non_existent_workbench_id_9999"

    # 1. /api/recover-file/{id} -> 404
    assert client.get(f"/api/recover-file/{fake_id}").status_code == 404

    # 2. /api/recover-file/{id}/download -> 404
    assert client.get(f"/api/recover-file/{fake_id}/download").status_code == 404

    # 3. /api/artifacts/{id} -> 404
    assert client.get(f"/api/artifacts/{fake_id}").status_code == 404

    # 4. /api/recovery-runs/{id} -> 404
    assert client.get(f"/api/recovery-runs/{fake_id}").status_code == 404


def test_workbench_contract_unrecoverable_and_failed_validation_download_block():
    """Verify download safety: unrecoverable or validation-failed files are strictly non-downloadable."""
    garbage = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xaa\xbb\xcc"
    post_res = client.post(
        "/api/recover-file",
        files={"file": ("dead_bytes.bin", garbage, "application/octet-stream")},
    )
    assert post_res.status_code == 200
    data = post_res.json()
    file_id = data["file_id"]
    assert data["status"] == "UNRECOVERABLE"
    assert data["is_downloadable"] is False

    # Download endpoint must reject with 404
    dl_res = client.get(f"/api/recover-file/{file_id}/download")
    assert dl_res.status_code == 404

    # Artifact download endpoint must also reject with 404
    art_dl_res = client.get(f"/api/artifacts/{file_id}/download")
    assert art_dl_res.status_code == 404
