"""
test_validation_download_hardening.py — Regression tests for recovery validation,
recovery status, download eligibility, and download endpoint consistency.

Covers Phase 13 requirements:
1. Mid-token truncated JSON (unclosed structure, failed validation) must NOT be downloadable.
2. Closable truncated JSON (repaired structure, passed validation) MUST be downloadable.
3. Intact JSON (fully recovered) MUST be downloadable.
4. Unrecoverable JSON must NOT be downloadable.
5. Valid partially recovered artifacts MUST be downloadable.
6. Download endpoints (/api/recover-file/{id}/download and /api/artifacts/{id}/download)
   strictly reject unrecoverable, corrupted, or validation-failed artifacts.
7. Verification across multiple formats (JSON, TXT, CSV, XML, PNG, JPEG, PDF, ZIP).
8. V/R/M accounting invariants and status guards.
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app, reset_rate_limits
from backend.app.store import store
from backend.app.models.artifact import (
    ArtifactRecord,
    ArtifactResponse,
    ConfidenceBreakdownSchema,
    ArtifactProvenanceSchema,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_store():
    """Ensure clean store and rate limits before each test."""
    store.clear()
    reset_rate_limits()
    yield
    store.clear()
    reset_rate_limits()


# ── Test 1: Mid-token Truncated JSON (Unclosed Structure) ───────────────────

def test_1_mid_token_truncated_json_fails_validation_and_cannot_be_downloaded():
    """F-02 Regression: Mid-token truncated JSON must report validation_status='FAILED',

    is_downloadable=False, and the download endpoint must return HTTP 404.
    """
    evidence = b'{"case":"IR-100","details":{"severi'

    response = client.post(
        "/api/recover-file",
        files={"file": ("incident.json", evidence, "application/json")},
    )
    assert response.status_code == 200
    data = response.json()

    # Recovery status reports partial evidence because verified prefix is retained
    assert data["status"] == "PARTIALLY_RECOVERED"

    # Validation must truthfully report failure
    assert data["validation_details"]["valid"] is False
    assert data["validation_status"] == "FAILED"

    # Download must be strictly disabled
    assert data["is_downloadable"] is False

    # Forensic V/R/M accounting: prefix retained without guessing syntax
    assert data["verified_bytes"] == 16  # b'{"case":"IR-100"'
    assert data["reconstructed_bytes"] == 0
    assert data["missing_bytes"] == 19
    assert data["verified_bytes"] + data["missing_bytes"] == len(evidence)

    # Persisted metadata inspection
    file_id = data["file_id"]
    meta = store.get_recovered_file_metadata(file_id)
    assert meta is not None
    assert meta["validation_status"] == "FAILED"
    assert meta["is_downloadable"] is False

    # Download endpoint must refuse to serve invalid JSON
    dl_resp = client.get(data["download_url"])
    assert dl_resp.status_code == 404
    assert "not found or unrecoverable" in dl_resp.json()["detail"]

    # Alias endpoint must also refuse
    alias_url = f"/api/recover/file/{file_id}/download"
    alias_resp = client.get(alias_url)
    assert alias_resp.status_code == 404


# ── Test 2: Valid JSON Reconstructed from Truncated Input ────────────────────

def test_2_closable_truncated_json_passes_validation_and_is_downloadable():
    """Closable truncated JSON deterministically reconstructed with closing markers

    passes structural validation and must be downloadable as valid JSON.
    """
    evidence = b'{"case":"IR-100","tags":["alpha","beta"'

    response = client.post(
        "/api/recover-file",
        files={"file": ("incident.json", evidence, "application/json")},
    )
    assert response.status_code == 200
    data = response.json()

    # Reconstructed syntax means partial recovery
    assert data["status"] == "PARTIALLY_RECOVERED"

    # Must pass structural validation
    assert data["validation_details"]["valid"] is True
    assert data["validation_status"] == "PASSED"

    # Download must be permitted
    assert data["is_downloadable"] is True
    assert data["reconstructed_bytes"] == 2  # b']}'
    assert data["missing_bytes"] == 0

    # Download endpoint must serve valid, parseable JSON
    dl_resp = client.get(data["download_url"])
    assert dl_resp.status_code == 200
    assert dl_resp.headers["content-type"] == "application/json"
    downloaded_data = json.loads(dl_resp.content.decode("utf-8"))
    assert downloaded_data == {"case": "IR-100", "tags": ["alpha", "beta"]}


# ── Test 3: Fully Recovered Intact JSON ───────────────────────────────────────

def test_3_intact_json_is_fully_recovered_and_downloadable():
    """Intact valid JSON must report FULLY_RECOVERED, PASSED, and be downloadable."""
    evidence = b'{"status":"ok","items":[1,2,3],"active":true}'

    response = client.post(
        "/api/recover-file",
        files={"file": ("status.json", evidence, "application/json")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "FULLY_RECOVERED"
    assert data["validation_details"]["valid"] is True
    assert data["validation_status"] == "PASSED"
    assert data["is_downloadable"] is True
    assert data["verified_bytes"] == len(evidence)
    assert data["reconstructed_bytes"] == 0
    assert data["missing_bytes"] == 0

    dl_resp = client.get(data["download_url"])
    assert dl_resp.status_code == 200
    assert dl_resp.content == evidence
    assert json.loads(dl_resp.content.decode("utf-8")) == {"status": "ok", "items": [1, 2, 3], "active": True}


# ── Test 4: Unrecoverable JSON ───────────────────────────────────────────────

def test_4_unrecoverable_json_reports_failed_and_not_downloadable():
    """Completely malformed JSON must report UNRECOVERABLE, FAILED, and 404 on download."""
    evidence = b"non-json garbage 12345"

    response = client.post(
        "/api/recover-file",
        files={"file": ("broken.json", evidence, "application/json")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "UNRECOVERABLE"
    assert data["validation_status"] == "FAILED"
    assert data["is_downloadable"] is False
    assert data["verified_bytes"] == 0
    assert data["missing_bytes"] == len(evidence)

    dl_resp = client.get(data["download_url"])
    assert dl_resp.status_code == 404


# ── Test 5: Valid Partially Recovered Artifact ───────────────────────────────

def test_5_valid_partially_recovered_artifact_is_downloadable():
    """Partially recovered artifact that passes validation is honestly downloadable."""
    # Text file with trailing null padding that was truncated/cleaned
    evidence = b"Report Header\nSection 1: Findings\nSection 2: Details\x00\x00\x00\x00"

    response = client.post(
        "/api/recover-file",
        files={"file": ("report.txt", evidence, "text/plain")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "PARTIALLY_RECOVERED"
    assert data["validation_status"] == "PASSED"
    assert data["validation_details"]["valid"] is True
    assert data["is_downloadable"] is True
    assert data["verified_bytes"] > 0

    dl_resp = client.get(data["download_url"])
    assert dl_resp.status_code == 200
    assert b"Report Header" in dl_resp.content


# ── Test 6: Conflicting Metadata Cannot Bypass Download Guard ────────────────

def test_6_conflicting_metadata_cannot_bypass_download_guards():
    """Even if persisted metadata maliciously sets is_downloadable=True,

    a validation_status='FAILED' or status='UNRECOVERABLE'/'CORRUPTED' must
    be forced to is_downloadable=False and rejected by the download endpoint.
    """
    file_id = "test-conflict-hardening-01"
    meta = {
        "file_id": file_id,
        "original_filename": "bad.json",
        "recovered_filename": "recovered_bad.json",
        "format": "json",
        "status": "PARTIALLY_RECOVERED",
        "confidence_score": 25.0,
        "verified_bytes": 10,
        "reconstructed_bytes": 0,
        "missing_bytes": 15,
        "reconstruction_method": "JSON_UNRESOLVED_CONTENT",
        "validation_status": "FAILED",  # Validation failed!
        "is_downloadable": True,         # Conflicting claim!
        "download_url": f"/api/recover-file/{file_id}/download",
        "score_breakdown": {},
        "validation_details": {"valid": False},
    }

    # Store file with conflicting metadata
    store.store_recovered_file(file_id, meta, b"unvalidated fragment")

    # In-store record must have forced is_downloadable=False
    retrieved_meta = store.get_recovered_file_metadata(file_id)
    assert retrieved_meta["is_downloadable"] is False

    # Download endpoint must reject with 404
    dl_resp = client.get(f"/api/recover-file/{file_id}/download")
    assert dl_resp.status_code == 404


# ── Test 7: Case Artifact Download Endpoint Rejects Validation Failures ──────

def test_7_case_artifact_download_rejects_validation_failures():
    """Case artifact download endpoint (/api/artifacts/{id}/download) must reject

    any artifact whose validation_status is 'FAILED' or status is CORRUPTED/UNRECOVERABLE.
    """
    case = store.create_case("Hardening Case")
    art_id = "art-hardening-fail-01"

    rec = ArtifactRecord(
        artifact_id=art_id,
        case_id=case.case_id,
        format="json",
        status="PARTIALLY_RECOVERED",
        confidence_score=30.0,
        verified_bytes=10,
        reconstructed_bytes=0,
        missing_bytes=20,
        total_input_bytes=30,
        reconstruction_method="JSON_UNRESOLVED_CONTENT",
        validation_status="FAILED",
        is_downloadable=False,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes(art_id, b"invalid json fragment")

    # Attempting to download via case artifact endpoint
    dl_resp = client.get(f"/api/artifacts/{art_id}/download")
    assert dl_resp.status_code == 404
    assert "cannot be downloaded" in dl_resp.json()["detail"]


# ── Test 8: Download Eligibility Invariants Across 8 Formats ─────────────────

@pytest.mark.parametrize(
    "fmt,filename,content,expected_downloadable",
    [
        ("json", "test.json", b'{"valid":true,"number":42}', True),
        ("json", "test_mid.json", b'{"valid":true,"incomplete_key":{"unclosed_tok', False),
        ("json", "test_garbage.json", b"not a json format at all", False),
        ("txt", "test.txt", b"Standard text evidence payload", True),
        ("txt", "test_nulls.txt", b"\x00\x00\x00\x00\x00\x00", False),
        ("csv", "test.csv", b"id,name,value\n1,alice,100\n2,bob,200\n", True),
        ("csv", "test_garbage.csv", b"\xff\xfe\x00\x00\xffbinary", False),
        ("xml", "test.xml", b"<catalog><item id='1'>Widget</item></catalog>", True),
        ("xml", "test_garbage.xml", b"not valid xml at all <<>>", False),
        ("png", "test_garbage.png", b"\x89PNG\r\n\x1a\ncorrupt header content", False),
        ("jpeg", "test_garbage.jpg", b"\xff\xd8\xff\xe0corrupt jpeg content", False),
        ("pdf", "test_garbage.pdf", b"%PDF-1.4\ncorrupted without structure\n", False),
        ("zip", "test_garbage.zip", b"PK\x03\x04\x00\x00corrupted zip content", False),
    ],
)
def test_8_download_eligibility_invariants_across_formats(fmt, filename, content, expected_downloadable):
    """Verify that is_downloadable strictly equals whether the recovered file

    is structurally valid across all supported formats.
    """
    resp = client.post("/api/recover-file", files={"file": (filename, content, "application/octet-stream")})
    assert resp.status_code == 200
    data = resp.json()

    assert data["is_downloadable"] is expected_downloadable, (
        f"Format {fmt} ({filename}) expected is_downloadable={expected_downloadable}, "
        f"got {data['is_downloadable']} with validation_status={data['validation_status']}"
    )

    dl_resp = client.get(data["download_url"])
    if expected_downloadable:
        assert dl_resp.status_code == 200
        assert data["validation_status"] == "PASSED"
        assert data["validation_details"].get("valid") is True
        assert len(dl_resp.content) > 0
    else:
        assert dl_resp.status_code == 404
        assert (
            data["validation_status"] == "FAILED"
            or data["status"] in ("UNRECOVERABLE", "CORRUPTED")
        )


# ── Test 9: Forensic Byte Accounting Conservation Invariants ────────────────

def test_9_forensic_byte_conservation_invariants():
    """Verify that source input bytes = verified bytes + missing bytes (V + M == Input)
    and recovered output bytes = verified bytes + reconstructed bytes (V + R == Output).
    Reconstructed syntax tokens must never inflate the recorded total_input_bytes.
    """
    # 1. Clean format (V = len, R = 0, M = 0)
    clean_txt = b"Recoverix forensic evidence payload without damage"
    resp1 = client.post("/api/recover-file", files={"file": ("clean.txt", clean_txt, "text/plain")})
    assert resp1.status_code == 200
    d1 = resp1.json()
    assert d1["total_input_bytes"] == len(clean_txt)
    assert d1["verified_bytes"] == len(clean_txt)
    assert d1["reconstructed_bytes"] == 0
    assert d1["missing_bytes"] == 0
    assert d1["verified_bytes"] + d1["missing_bytes"] == d1["total_input_bytes"]
    dl1 = client.get(d1["download_url"])
    assert len(dl1.content) == d1["verified_bytes"] + d1["reconstructed_bytes"]

    # 2. Truncated JSON with reconstruction (V = 39, R = 2, M = 0 -> Input = 39, Output = 41)
    trunc_json = b'{"name": "Recoverix", "items": [1, 2, 3'
    resp2 = client.post("/api/recover-file", files={"file": ("trunc.json", trunc_json, "application/json")})
    assert resp2.status_code == 200
    d2 = resp2.json()
    assert d2["status"] == "PARTIALLY_RECOVERED"
    assert d2["total_input_bytes"] == len(trunc_json)
    assert d2["verified_bytes"] == len(trunc_json)
    assert d2["reconstructed_bytes"] == 2
    assert d2["missing_bytes"] == 0
    # Crucial invariant: total_input_bytes is 39, NOT 41!
    assert d2["total_input_bytes"] == d2["verified_bytes"] + d2["missing_bytes"]
    assert d2["total_input_bytes"] != d2["verified_bytes"] + d2["reconstructed_bytes"] + d2["missing_bytes"]
    dl2 = client.get(d2["download_url"])
    assert len(dl2.content) == d2["verified_bytes"] + d2["reconstructed_bytes"]

    # 3. Unrecoverable garbage (V = 0, R = 0, M = len -> Input = len, Output = 0)
    garbage = b"\x00\xff\x1a\x2b\x3c\x4d\x5e\x6f" * 32
    resp3 = client.post("/api/recover-file", files={"file": ("garbage.bin", garbage, "application/octet-stream")})
    assert resp3.status_code == 200
    d3 = resp3.json()
    assert d3["status"] == "UNRECOVERABLE"
    assert d3["total_input_bytes"] == len(garbage)
    assert d3["verified_bytes"] == 0
    assert d3["reconstructed_bytes"] == 0
    assert d3["missing_bytes"] == len(garbage)
    assert d3["verified_bytes"] + d3["missing_bytes"] == d3["total_input_bytes"]


# ── Test 10: Pending / Unknown Validation Status Strictly Rejects Download ───

@pytest.mark.parametrize("val_status", ["PENDING", "UNKNOWN", "FAILED", "INVALID", ""])
def test_10_non_passed_validation_status_strictly_rejects_download(val_status):
    """Artifacts with validation_status not equal to 'PASSED' must be forced to
    is_downloadable=False and rejected with HTTP 404 on both download endpoints.
    """
    case = store.create_case("Validation State Test Case")
    art_id = f"art-val-status-{val_status or 'empty'}"
    rec = ArtifactRecord(
        artifact_id=art_id,
        case_id=case.case_id,
        format="json",
        status="FULLY_RECOVERED",
        confidence_score=95.0,
        verified_bytes=50,
        reconstructed_bytes=0,
        missing_bytes=0,
        total_input_bytes=50,
        reconstruction_method="NONE",
        validation_status=val_status,
        is_downloadable=True,  # Attempting to declare downloadable despite validation status
    )
    assert rec.is_downloadable is False, f"ArtifactRecord must force is_downloadable=False for {val_status}"
    store.save_artifact_record(rec)
    store.store_artifact_bytes(art_id, b'{"status": "test"}')

    # Case artifact download endpoint must refuse
    dl_resp = client.get(f"/api/artifacts/{art_id}/download")
    assert dl_resp.status_code == 404

    # Standalone file recovery endpoint must also refuse
    file_id = f"file-val-status-{val_status or 'empty'}"
    file_meta = rec.to_file_recovery_dict()
    file_meta["file_id"] = file_id
    store.store_recovered_file(file_id, file_meta, b'{"status": "test"}')
    file_dl_resp = client.get(f"/api/recover-file/{file_id}/download")
    assert file_dl_resp.status_code == 404


# ── Test 11: Non-Permitted Recovery Status Strictly Rejects Download ─────────

@pytest.mark.parametrize("rec_status", ["UNRECOVERABLE", "CORRUPTED", "FAILED", "PENDING", "UNKNOWN", "ABORTED"])
def test_11_non_permitted_status_strictly_rejects_download(rec_status):
    """Only FULLY_RECOVERED and PARTIALLY_RECOVERED are permitted to be downloaded.
    Any other status must force is_downloadable=False and return HTTP 404.
    """
    case = store.create_case("Status Permitted Test Case")
    art_id = f"art-rec-status-{rec_status}"
    rec = ArtifactRecord(
        artifact_id=art_id,
        case_id=case.case_id,
        format="txt",
        status=rec_status,
        confidence_score=50.0,
        verified_bytes=20,
        reconstructed_bytes=0,
        missing_bytes=10,
        total_input_bytes=30,
        reconstruction_method="NONE",
        validation_status="PASSED",
        is_downloadable=True,  # Attempting to declare downloadable
    )
    assert rec.is_downloadable is False, f"ArtifactRecord must force is_downloadable=False for status {rec_status}"
    store.save_artifact_record(rec)
    store.store_artifact_bytes(art_id, b"plain text payload")

    dl_resp = client.get(f"/api/artifacts/{art_id}/download")
    assert dl_resp.status_code == 404

    file_id = f"file-rec-status-{rec_status}"
    file_meta = rec.to_file_recovery_dict()
    file_meta["file_id"] = file_id
    store.store_recovered_file(file_id, file_meta, b"plain text payload")
    file_dl_resp = client.get(f"/api/recover-file/{file_id}/download")
    assert file_dl_resp.status_code == 404


# ── Test 12: Missing Explicit Download Permission Rejects Download ───────────

def test_12_explicit_download_permission_required():
    """An artifact with is_downloadable=False must be rejected even when status='FULLY_RECOVERED'
    and validation_status='PASSED'.
    """
    case = store.create_case("Explicit Permission Case")
    art_id = "art-explicit-perm-01"
    rec = ArtifactRecord(
        artifact_id=art_id,
        case_id=case.case_id,
        format="json",
        status="FULLY_RECOVERED",
        confidence_score=100.0,
        verified_bytes=40,
        reconstructed_bytes=0,
        missing_bytes=0,
        total_input_bytes=40,
        reconstruction_method="NONE",
        validation_status="PASSED",
        is_downloadable=False,  # Explicitly restricted by backend
    )
    assert rec.is_downloadable is False
    store.save_artifact_record(rec)
    store.store_artifact_bytes(art_id, b'{"authorized": false}')

    dl_resp = client.get(f"/api/artifacts/{art_id}/download")
    assert dl_resp.status_code == 404

    file_id = "file-explicit-perm-01"
    file_meta = rec.to_file_recovery_dict()
    file_meta["file_id"] = file_id
    store.store_recovered_file(file_id, file_meta, b'{"authorized": false}')
    file_dl_resp = client.get(f"/api/recover-file/{file_id}/download")
    assert file_dl_resp.status_code == 404


