"""
test_cors_and_api_exposure.py — Security tests for CORS configuration and API exposure.

Verifies:
1. Approved local frontend origins (localhost:3000, 127.0.0.1:3000) receive CORS allow headers.
2. Unapproved origins (e.g. https://attacker.com) do NOT receive Access-Control-Allow-Origin headers.
3. Preflight OPTIONS requests succeed for approved origins and are rejected (400) for unapproved origins.
4. Missing, whitespace, or malformed RECOVERIX_CORS_ORIGINS values fall back safely to defaults.
5. Trailing slashes and duplicate origins are normalized.
6. Non-browser clients (requests without Origin headers) pass through unaffected.
7. CORS headers are properly attached to early error responses (e.g. 413 upload limit rejections) for approved origins.
8. Sensitive endpoints (cases, evidence, artifacts, downloads, interpretations) enforce CORS boundary.
9. Clarification: Demonstrates that CORS is a browser-side policy and does NOT substitute for backend authentication.
"""

from __future__ import annotations

import io
import os
import pytest
from fastapi.testclient import TestClient

from backend.app.main import (
    app,
    DEFAULT_ALLOWED_ORIGINS,
    get_allowed_origins,
    is_valid_origin,
)
from backend.app.store import store, MAX_EVIDENCE_SIZE
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
# 1. Allowed Local Frontend Origins
# ==============================================================================


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
)
def test_allowed_origins_receive_cors_headers_on_get(origin: str):
    """Approved frontend origins receive Access-Control-Allow-Origin header matching their origin."""
    response = client.get("/health", headers={"Origin": origin})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == origin


def test_allowed_origin_on_case_creation_and_retrieval():
    """Approved frontend origin receives CORS headers on case API interactions."""
    origin = "http://localhost:3000"

    # POST /api/cases
    create_res = client.post(
        "/api/cases",
        json={"name": "CORS Test Case"},
        headers={"Origin": origin},
    )
    assert create_res.status_code == 201
    assert create_res.headers.get("access-control-allow-origin") == origin
    case_id = create_res.json()["case_id"]

    # GET /api/cases/{case_id}
    get_res = client.get(
        f"/api/cases/{case_id}",
        headers={"Origin": origin},
    )
    assert get_res.status_code == 200
    assert get_res.headers.get("access-control-allow-origin") == origin


# ==============================================================================
# 2. Unapproved Origins Blocked from Reading Responses via CORS
# ==============================================================================


@pytest.mark.parametrize(
    "unapproved_origin",
    [
        "*",
        "https://malicious-attacker.com",
        "http://evil.local:3000",
        "http://localhost:9999",
        "http://192.168.1.100:3000",
        "null",
    ],
)
def test_unapproved_origins_do_not_receive_allow_origin_header(unapproved_origin: str):
    """Unapproved origins must NOT receive Access-Control-Allow-Origin header."""
    response = client.get("/health", headers={"Origin": unapproved_origin})
    assert response.status_code == 200
    # Browser requires Access-Control-Allow-Origin matching the origin to allow JS to read.
    # When None, the browser blocks the response from being accessed.
    assert response.headers.get("access-control-allow-origin") is None


def test_unapproved_origin_blocked_on_sensitive_artifact_download():
    """Unapproved origin cannot access recovered evidence download through browser CORS."""
    # Seed a case with an artifact
    create_res = client.post("/api/cases", json={"name": "Sensitive Artifact Case"})
    case_id = create_res.json()["case_id"]

    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Sensitive\nBody: Forensic Data\n" + SYNTHETIC_END_MARKER
    client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("evidence.img", payload, "application/octet-stream")},
    )
    analysis = client.post(f"/api/cases/{case_id}/analyze").json()
    artifact_id = analysis["artifacts"][0]["artifact_id"]

    # Attacker site attempts to fetch the download
    attacker_origin = "https://evil-exfiltrator.org"
    dl_res = client.get(
        f"/api/artifacts/{artifact_id}/download",
        headers={"Origin": attacker_origin},
    )
    assert dl_res.status_code == 200
    assert dl_res.headers.get("access-control-allow-origin") is None


def test_unapproved_origin_blocked_on_interpretation_endpoints():
    """Unapproved origin cannot access AI or grounded interpretation through browser CORS."""
    create_res = client.post("/api/cases", json={"name": "Interpretation Case"})
    case_id = create_res.json()["case_id"]

    attacker_origin = "https://unauthorized-dashboard.net"
    interp_res = client.get(
        f"/api/cases/{case_id}/interpretation",
        headers={"Origin": attacker_origin},
    )
    assert interp_res.headers.get("access-control-allow-origin") is None


# ==============================================================================
# 3. Preflight OPTIONS Requests
# ==============================================================================


def test_preflight_options_allowed_origin():
    """Preflight OPTIONS request from approved origin returns 200 and allowed methods/headers."""
    response = client.options(
        "/api/cases",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    methods = response.headers.get("access-control-allow-methods", "")
    assert "POST" in methods
    assert "GET" in methods


def test_preflight_options_unapproved_origin_rejected():
    """Preflight OPTIONS request from unapproved origin is rejected with 400 Bad Request."""
    response = client.options(
        "/api/cases",
        headers={
            "Origin": "https://malicious-site.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 400
    assert response.headers.get("access-control-allow-origin") is None


def test_preflight_options_methods_restricted_to_safe_set():
    """Verify preflight Access-Control-Allow-Methods is strictly restricted to GET, POST, OPTIONS, HEAD."""
    response = client.options(
        "/api/cases",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    raw_methods = response.headers.get("access-control-allow-methods", "")
    methods = [m.strip() for m in raw_methods.split(",") if m.strip()]
    assert set(methods) == {"GET", "POST", "OPTIONS", "HEAD"}
    assert "PUT" not in methods
    assert "DELETE" not in methods
    assert "PATCH" not in methods


# ==============================================================================
# 4. Origin Configuration Resolution and Validation (get_allowed_origins)
# ==============================================================================


def test_get_allowed_origins_default_when_unset_or_empty():
    """When RECOVERIX_CORS_ORIGINS is unset or empty, safe local defaults are returned."""
    assert get_allowed_origins(None) == DEFAULT_ALLOWED_ORIGINS
    assert get_allowed_origins("") == DEFAULT_ALLOWED_ORIGINS
    assert get_allowed_origins("   ") == DEFAULT_ALLOWED_ORIGINS


def test_get_allowed_origins_comma_separated_valid():
    """Comma-separated valid origins are parsed, normalized, and returned."""
    raw = "http://localhost:3000,http://127.0.0.1:3000,https://analyst-workstation.local:8443"
    result = get_allowed_origins(raw)
    assert result == [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://analyst-workstation.local:8443",
    ]


def test_get_allowed_origins_normalizes_trailing_slashes_and_deduplicates():
    """Trailing slashes are removed and duplicate origins are removed preserving order."""
    raw = "http://localhost:3000/, http://localhost:3000, http://127.0.0.1:3000/"
    result = get_allowed_origins(raw)
    assert result == ["http://localhost:3000", "http://127.0.0.1:3000"]


def test_get_allowed_origins_json_array_support():
    """JSON array strings are supported as valid origin configuration."""
    raw = '["http://localhost:3000", "https://forensics.corp.internal:443"]'
    result = get_allowed_origins(raw)
    assert result == [
        "http://localhost:3000",
        "https://forensics.corp.internal:443",
    ]


def test_get_allowed_origins_filters_malformed_entries():
    """Malformed entries (no scheme, embedded path, query strings) are filtered out."""
    raw = "localhost:3000, http://valid.local:3000, ftp://bad.com, http://bad.com/path, http://bad.com?query=1"
    result = get_allowed_origins(raw)
    assert result == ["http://valid.local:3000"]


def test_get_allowed_origins_falls_back_to_defaults_if_all_malformed():
    """If all configured origins are malformed, it safely falls back to defaults without breaking."""
    raw = "not_a_valid_url_1, not_a_valid_url_2"
    result = get_allowed_origins(raw)
    assert result == DEFAULT_ALLOWED_ORIGINS


def test_get_allowed_origins_explicit_disable():
    """Explicitly passing 'none' or 'disabled' returns empty list to disable CORS entirely."""
    assert get_allowed_origins("none") == []
    assert get_allowed_origins("disabled") == []
    assert get_allowed_origins("FALSE") == []


def test_is_valid_origin_helper():
    """Unit test for is_valid_origin validation helper."""
    assert is_valid_origin("http://localhost:3000") is True
    assert is_valid_origin("https://example.com") is True
    assert is_valid_origin("https://example.com:8443") is True
    assert is_valid_origin("http://127.0.0.1:8000") is True

    # Wildcards are strictly rejected to enforce origin isolation
    assert is_valid_origin("*") is False
    assert is_valid_origin("http://*") is False
    assert is_valid_origin("https://*") is False
    assert is_valid_origin("http://*.example.com") is False

    # Invalid cases
    assert is_valid_origin("localhost:3000") is False  # Missing scheme
    assert is_valid_origin("ftp://example.com") is False  # Non-HTTP(S) scheme
    assert is_valid_origin("http://example.com/api") is False  # Path not allowed
    assert is_valid_origin("http://example.com?query=1") is False  # Query not allowed
    assert is_valid_origin("javascript:alert(1)") is False
    assert is_valid_origin("") is False


def test_get_allowed_origins_rejects_wildcard():
    """Verify wildcard '*' cannot be used to enable unrestricted CORS."""
    # Naked wildcard string
    assert get_allowed_origins("*") == DEFAULT_ALLOWED_ORIGINS
    assert "*" not in get_allowed_origins("*")

    # JSON array with wildcard
    assert get_allowed_origins('["*"]') == DEFAULT_ALLOWED_ORIGINS
    assert "*" not in get_allowed_origins('["*"]')

    # Mixed wildcard and valid origin
    mixed = get_allowed_origins("*,http://localhost:3000")
    assert mixed == ["http://localhost:3000"]
    assert "*" not in mixed

    mixed_json = get_allowed_origins('["*", "http://127.0.0.1:3000"]')
    assert mixed_json == ["http://127.0.0.1:3000"]
    assert "*" not in mixed_json


# ==============================================================================
# 5. Non-Browser Clients (No Origin Header)
# ==============================================================================


def test_non_browser_clients_operate_normally_without_cors():
    """Direct API clients (cURL, Python scripts) without Origin header receive normal responses."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "recoverix-api"}
    assert "access-control-allow-origin" not in response.headers


# ==============================================================================
# 6. Interaction with Early 413 Upload Limit Rejections
# ==============================================================================


def test_cors_headers_preserved_on_413_upload_limit_rejection_for_allowed_origin():
    """When an upload is rejected with 413, allowed frontend origin still gets CORS header."""
    origin = "http://localhost:3000"
    oversized = b"X" * (MAX_EVIDENCE_SIZE + 1024)

    response = client.post(
        "/api/recover-file",
        files={"file": ("oversized.bin", oversized, "application/octet-stream")},
        headers={"Origin": origin},
    )
    assert response.status_code == 413
    assert response.headers.get("access-control-allow-origin") == origin


def test_cors_headers_omitted_on_413_for_unapproved_origin():
    """When an unapproved origin triggers 413, no CORS header is returned."""
    attacker_origin = "https://malicious.org"
    oversized = b"X" * (MAX_EVIDENCE_SIZE + 1024)

    response = client.post(
        "/api/recover-file",
        files={"file": ("oversized.bin", oversized, "application/octet-stream")},
        headers={"Origin": attacker_origin},
    )
    assert response.status_code == 413
    assert response.headers.get("access-control-allow-origin") is None


# ==============================================================================
# 7. Security Model Demonstration: CORS Does Not Equal Authentication
# ==============================================================================


def test_security_model_demonstration_unauthenticated_api_access():
    """Demonstrates that CORS protects against cross-origin browser requests, NOT direct API access.

    An unauthenticated attacker on the local network (or using a non-browser tool like curl)
    can still reach the API directly because no authentication tokens or sessions exist.
    This test formally documents why network-level binding (127.0.0.1) and reverse-proxy
    authentication are necessary when deploying outside a local workstation.
    """
    # Request with NO Origin header (simulating curl or non-browser script)
    res = client.post("/api/cases", json={"name": "Direct Access Case"})
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    # Data is created and readable because no auth layer exists on the backend
    get_res = client.get(f"/api/cases/{case_id}")
    assert get_res.status_code == 200
    assert get_res.json()["name"] == "Direct Access Case"


# ==============================================================================
# 8. Docker Loopback Port Bindings
# ==============================================================================


def test_docker_compose_loopback_bindings():
    """Verify docker-compose.yml strictly publishes ports to loopback (127.0.0.1)."""
    from pathlib import Path

    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist"
    content = compose_path.read_text(encoding="utf-8")

    # Check that published ports are explicitly bound to 127.0.0.1
    assert "127.0.0.1:8000:8000" in content
    assert "127.0.0.1:3000:3000" in content

    # Check port mappings under 'ports:' blocks
    in_ports_block = False
    port_mappings = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "ports:":
            in_ports_block = True
            continue
        if in_ports_block:
            if stripped.startswith("- "):
                port_mappings.append(stripped.strip('- "').strip("'"))
            else:
                in_ports_block = False

    assert port_mappings == ["127.0.0.1:8000:8000", "127.0.0.1:3000:3000"]
    for mapping in port_mappings:
        assert mapping.startswith("127.0.0.1:"), f"Port mapping not bound to loopback: {mapping}"
