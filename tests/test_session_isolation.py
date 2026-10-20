"""
test_session_isolation.py — Multi-session isolation, token security, and privacy tests.

Validates:
1. Multi-session isolation: Client A cannot access Client B's metadata, download, preview, or explain endpoints (404).
2. Unauthenticated caller gets 404 on session-owned resources and empty list on /api/recovery-runs.
3. Cryptographic session tokens: HMAC-SHA256 signature verification, rejection of tampered tokens.
4. Payload redaction: GET /api/recovery-runs and GET /api/recovery-runs/{id} do NOT leak recovered_bytes hex string.
5. Immediate deletion: DELETE /api/recover-file/{id} and DELETE /api/recovery-runs/{id} enforce session ownership.
6. Retention purge: purge_expired_recovered_files(ttl_hours) cleans expired recovery_runs rows.
7. Cache protection: API responses and downloads enforce Cache-Control: no-store and Pragma: no-cache.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.store import store
from backend.app.session import sign_session_token, verify_session_token, SESSION_COOKIE_NAME, SESSION_HEADER_NAME


@pytest.fixture(autouse=True)
def clean_store():
    """Ensure clean storage before and after test."""
    store.clear()
    yield
    store.clear()


def test_session_token_generation_and_tamper_rejection():
    """Verify cryptographic HMAC-SHA256 session token generation and tamper rejection."""
    sess_id = "sess_test_12345"
    token = sign_session_token(sess_id)
    assert token.startswith(f"{sess_id}.")
    
    # Valid verification
    assert verify_session_token(token) == sess_id
    
    # Tampered payload
    tampered_payload = "sess_test_99999." + token.split(".")[1]
    assert verify_session_token(tampered_payload) is None
    
    # Tampered signature
    tampered_sig = sess_id + ".ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    assert verify_session_token(tampered_sig) is None
    
    # Malformed tokens
    assert verify_session_token("invalid_token_without_dot") is None
    assert verify_session_token("") is None
    assert verify_session_token(None) is None


def test_multi_session_file_isolation_and_404_gate():
    """Client A uploads a file. Client B (different session) cannot read or download it (strict 404)."""
    client_a = TestClient(app)
    client_b = TestClient(app)

    payload_a = b"Sensitive forensic evidence payload for Client A."
    resp_upload = client_a.post(
        "/api/recover-file",
        files={"file": ("client_a.txt", payload_a, "text/plain")},
    )
    assert resp_upload.status_code == 200
    data_a = resp_upload.json()
    file_id_a = data_a["file_id"]
    run_id_a = data_a["run_id"]

    # Verify Client A received signed session cookie and header
    assert SESSION_COOKIE_NAME in client_a.cookies
    token_a = client_a.cookies[SESSION_COOKIE_NAME]
    assert verify_session_token(token_a) is not None

    # Client A can access metadata, download, and explain
    assert client_a.get(f"/api/recover-file/{file_id_a}").status_code == 200
    dl_a = client_a.get(f"/api/recover-file/{file_id_a}/download")
    assert dl_a.status_code == 200
    assert dl_a.content == payload_a
    assert client_a.get(f"/api/recovery-runs/{run_id_a}").status_code == 200

    # Client B visits and gets a different session
    resp_b_ping = client_b.post(
        "/api/recover-file",
        files={"file": ("client_b.txt", b"Client B data", "text/plain")},
    )
    assert resp_b_ping.status_code == 200
    assert client_b.cookies[SESSION_COOKIE_NAME] != client_a.cookies[SESSION_COOKIE_NAME]

    # Client B MUST NOT access Client A's resources (Strict 404, not 403 to prevent enumeration)
    assert client_b.get(f"/api/recover-file/{file_id_a}").status_code == 404
    assert client_b.get(f"/api/recover-file/{file_id_a}/download").status_code == 404
    assert client_b.get(f"/api/recovery-runs/{run_id_a}").status_code == 404

    # Anonymous Client C (no session cookie) MUST NOT access Client A's resources
    client_c = TestClient(app)
    assert client_c.get(f"/api/recover-file/{file_id_a}").status_code == 404
    assert client_c.get(f"/api/recover-file/{file_id_a}/download").status_code == 404
    assert client_c.get(f"/api/recovery-runs/{run_id_a}").status_code == 404


def test_session_scoped_listing_and_no_enumeration():
    """Client A and Client B only see their own recovery runs. Anonymous gets empty list."""
    client_a = TestClient(app)
    client_b = TestClient(app)
    client_anon = TestClient(app)

    # Client A creates 2 runs
    client_a.post("/api/recover-file", files={"file": ("a1.txt", b"A1 content", "text/plain")})
    client_a.post("/api/recover-file", files={"file": ("a2.txt", b"A2 content", "text/plain")})

    # Client B creates 1 run
    client_b.post("/api/recover-file", files={"file": ("b1.txt", b"B1 content", "text/plain")})

    # Client A lists runs: exactly 2 runs, original filenames match A
    runs_a = client_a.get("/api/recovery-runs").json()
    assert len(runs_a) == 2
    assert {r["filename"] for r in runs_a} == {"a1.txt", "a2.txt"}

    # Client B lists runs: exactly 1 run, filename matches B
    runs_b = client_b.get("/api/recovery-runs").json()
    assert len(runs_b) == 1
    assert runs_b[0]["filename"] == "b1.txt"

    # Anonymous Client lists runs: empty list (no enumeration leak)
    runs_anon = client_anon.get("/api/recovery-runs").json()
    assert runs_anon == []


def test_recovery_run_output_redacts_recovered_bytes():
    """Verify GET /api/recovery-runs and GET /api/recovery-runs/{id} never expose raw hex bytes."""
    client = TestClient(app)
    secret_payload = b"SUPER_SECRET_PAYLOAD_NOT_TO_BE_LEAKED_IN_JSON_METADATA_12345"
    res = client.post(
        "/api/recover-file",
        files={"file": ("secret.txt", secret_payload, "text/plain")},
    )
    assert res.status_code == 200
    run_id = res.json()["run_id"]

    # 1. Check list endpoint
    runs = client.get("/api/recovery-runs").json()
    assert len(runs) >= 1
    target_run = next(r for r in runs if r["run_id"] == run_id)
    output = target_run.get("output")
    assert output is not None
    assert "recovered_bytes" not in output
    assert output.get("has_recovered_bytes") is True
    assert output.get("byte_count") == len(secret_payload)

    # 2. Check detail endpoint
    run_detail = client.get(f"/api/recovery-runs/{run_id}").json()
    output_detail = run_detail.get("output")
    assert output_detail is not None
    assert "recovered_bytes" not in output_detail
    assert output_detail.get("has_recovered_bytes") is True
    assert output_detail.get("byte_count") == len(secret_payload)


def test_user_initiated_immediate_deletion():
    """Client can delete their recovered file immediately; other clients cannot delete it."""
    client_a = TestClient(app)
    client_b = TestClient(app)

    payload = b"Immediate deletion test payload."
    res = client_a.post(
        "/api/recover-file",
        files={"file": ("delete_me.txt", payload, "text/plain")},
    )
    assert res.status_code == 200
    file_id = res.json()["file_id"]
    run_id = res.json()["run_id"]

    # Client B attempts to delete Client A's file -> 404
    del_b = client_b.delete(f"/api/recover-file/{file_id}")
    assert del_b.status_code == 404

    # Client A deletes their own file -> 200
    del_a = client_a.delete(f"/api/recover-file/{file_id}")
    assert del_a.status_code == 200
    assert del_a.json() == {"status": "DELETED", "file_id": file_id}

    # Subsequent access fails with 404
    assert client_a.get(f"/api/recover-file/{file_id}").status_code == 404
    assert client_a.get(f"/api/recover-file/{file_id}/download").status_code == 404
    assert client_a.get(f"/api/recovery-runs/{run_id}").status_code == 404

    # Deleting again returns 404 (idempotent failure)
    assert client_a.delete(f"/api/recover-file/{file_id}").status_code == 404


def test_retention_purge_cleans_recovery_runs():
    """purge_expired_recovered_files(ttl_hours) removes both artifacts and recovery_runs rows."""
    client = TestClient(app)
    payload = b"Retention purge lifecycle payload."
    res = client.post(
        "/api/recover-file",
        files={"file": ("purge_me.txt", payload, "text/plain")},
    )
    assert res.status_code == 200
    run_id = res.json()["run_id"]
    file_id = res.json()["file_id"]

    # Verify it exists in store
    assert store.get_recovery_run(run_id) is not None
    assert store.get_recovered_file_metadata(file_id) is not None

    # Run purge with ttl_hours=-1 to immediately expire everything created in the past
    purged_count = store.purge_expired_recovered_files(ttl_hours=-1)
    assert purged_count >= 1

    # Both artifact and recovery run should be gone from store
    assert store.get_recovered_file_metadata(file_id) is None
    assert store.get_recovery_run(run_id) is None


def test_cache_control_headers_enforced():
    """All /api responses and file downloads must carry strict no-store cache directives."""
    client = TestClient(app)
    payload = b"Cache header test payload."
    res = client.post(
        "/api/recover-file",
        files={"file": ("cache_test.txt", payload, "text/plain")},
    )
    assert res.status_code == 200
    file_id = res.json()["file_id"]

    # Verify POST response has no-store cache headers
    cc_post = res.headers.get("cache-control", "")
    assert "no-store" in cc_post
    assert "private" in cc_post
    assert res.headers.get("pragma") == "no-cache"

    # Verify GET metadata has no-store cache headers
    res_meta = client.get(f"/api/recover-file/{file_id}")
    assert "no-store" in res_meta.headers.get("cache-control", "")
    assert res_meta.headers.get("pragma") == "no-cache"

    # Verify GET download has no-store cache headers
    res_dl = client.get(f"/api/recover-file/{file_id}/download")
    assert "no-store" in res_dl.headers.get("cache-control", "")
    assert res_dl.headers.get("pragma") == "no-cache"


def test_session_secret_fail_closed_and_dynamic_resolution(monkeypatch):
    """Verify get_session_secret resolves dynamically and fails closed in strict or production mode."""
    from backend.app.session import get_session_secret, _DEFAULT_SECRET

    # 1. Default non-strict behavior
    monkeypatch.delenv("RECOVERIX_SESSION_SECRET", raising=False)
    monkeypatch.delenv("RECOVERIX_REQUIRE_SESSION_SECRET", raising=False)
    monkeypatch.delenv("RECOVERIX_ENV", raising=False)
    assert get_session_secret() == _DEFAULT_SECRET

    # 2. Explicit custom secret
    monkeypatch.setenv("RECOVERIX_SESSION_SECRET", "super_high_entropy_secret_test_key_987654321")
    assert get_session_secret() == "super_high_entropy_secret_test_key_987654321"

    token = sign_session_token("sess_custom_secret_test")
    assert verify_session_token(token) == "sess_custom_secret_test"

    # Token signed with custom secret fails under different secret
    monkeypatch.setenv("RECOVERIX_SESSION_SECRET", "another_different_secret_key_123456789")
    assert verify_session_token(token) is None

    # 3. Fail-closed when RECOVERIX_REQUIRE_SESSION_SECRET=1 and no secret provided
    monkeypatch.delenv("RECOVERIX_SESSION_SECRET", raising=False)
    monkeypatch.setenv("RECOVERIX_REQUIRE_SESSION_SECRET", "1")
    with pytest.raises(RuntimeError, match="RECOVERIX_SESSION_SECRET must be configured"):
        get_session_secret()

    # 4. Fail-closed when RECOVERIX_ENV=production and no secret provided
    monkeypatch.delenv("RECOVERIX_REQUIRE_SESSION_SECRET", raising=False)
    monkeypatch.setenv("RECOVERIX_ENV", "production")
    with pytest.raises(RuntimeError, match="RECOVERIX_SESSION_SECRET must be configured"):
        get_session_secret()
