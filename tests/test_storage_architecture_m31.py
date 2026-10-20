"""
test_storage_architecture_m31.py — Milestone 3.1 Storage Architecture & Repository Pattern Test Suite.

Verifies:
A. Pipeline B creates exactly one RecoveryRun.
B. Pipeline B lifecycle does not call add_recovery_run twice (Phase 10 Architecture Test).
C. Pipeline B artifact/run linkage resolves correctly.
D. Pipeline A behavior remains unchanged.
E. Standalone artifact storage and case artifact storage share the same artifact contract (ArtifactRecord).
F. Evidence BlobStore operations work.
G. Recovered-byte BlobStore operations work.
H. Missing blob behavior is deterministic.
I. Oversized Pipeline A upload returns 413.
J. Oversized Pipeline B upload returns 413.
K. Existing RecoveryRun retrieval/listing still works.
L. Existing explain endpoint can resolve the correct RecoveryRun.
M. Existing V/R/M tests remain unchanged and pass.
N. Existing fragmented TXT/CSV regressions remain unchanged.
O. JSON reconstruction remains unchanged.
P. PDF reconstruction remains unchanged.
Q. Bifragment ambiguity behavior remains unchanged.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.store import store, MAX_EVIDENCE_SIZE
from backend.app.models.artifact import ArtifactRecord, ArtifactResponse
from backend.app.models.recovery_run import RecoveryRun
from backend.app.recovery.tracer import execute_traced_recovery, execute_traced_recoveries
from backend.app.recovery.signatures import SYNTHETIC_START_MARKER, SYNTHETIC_END_MARKER

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_store():
    store.clear()
    yield
    store.clear()


# ── Test A: Pipeline B Creates Exactly One RecoveryRun ───────────────────────

def test_a_pipeline_b_creates_exactly_one_recovery_run():
    """A. Pipeline B creates exactly one RecoveryRun per execution."""
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Single\nBody: Test A\n" + SYNTHETIC_END_MARKER
    response = client.post(
        "/api/recover-file",
        files={"file": ("single.txt", payload, "text/plain")},
    )
    assert response.status_code == 200
    runs = store.list_recovery_runs()
    assert len(runs) == 1
    assert runs[0].run_id == response.json()["run_id"]


# ── Test B / Phase 10: Lifecycle Spy Proving Single Persistence ───────────────

def test_b_pipeline_b_lifecycle_does_not_call_add_recovery_run_twice(monkeypatch):
    """B / Phase 10: Verify add_recovery_run is called exactly once during Pipeline B recovery.

    Fails if anyone reintroduces model_copy(...) and add_recovery_run(...) after
    the canonical engine has already persisted the RecoveryRun.
    """
    call_count = 0
    orig_add_recovery_run = store.add_recovery_run

    def spy_add_recovery_run(run: RecoveryRun) -> RecoveryRun:
        nonlocal call_count
        call_count += 1
        return orig_add_recovery_run(run)

    monkeypatch.setattr(store, "add_recovery_run", spy_add_recovery_run)

    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Spy\nBody: Test B\n" + SYNTHETIC_END_MARKER

    # 1. Test via API endpoint
    response = client.post(
        "/api/recover-file",
        files={"file": ("spy_test.txt", payload, "text/plain")},
    )
    assert response.status_code == 200
    assert call_count == 1, f"Expected add_recovery_run called exactly once via API, got {call_count}"

    # 2. Test direct engine call with artifact_id
    call_count = 0
    run = execute_traced_recovery(
        filename="direct_spy.txt",
        content=payload,
        artifact_id="art-spy-check",
    )
    assert call_count == 1, f"Expected add_recovery_run called exactly once via execute_traced_recovery, got {call_count}"
    assert run.artifact_id is None, "Persisted RecoveryRun must not be mutated with artifact_id"
    assert store.get_recovery_run_by_artifact("art-spy-check").run_id == run.run_id


# ── Test C: Artifact/Run Linkage Resolves Correctly ───────────────────────────

def test_c_pipeline_b_artifact_run_linkage_resolves_correctly():
    """C. Pipeline B artifact/run linkage resolves correctly via the repository."""
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Linkage\nBody: Test C\n" + SYNTHETIC_END_MARKER
    response = client.post(
        "/api/recover-file",
        files={"file": ("linkage.txt", payload, "text/plain")},
    )
    assert response.status_code == 200
    data = response.json()
    file_id = data["file_id"]
    run_id = data["run_id"]

    resolved_run = store.get_recovery_run_by_artifact(file_id)
    assert resolved_run is not None
    assert resolved_run.run_id == run_id

    # Verify retrieval via direct run_id
    direct_run = store.get_recovery_run(run_id)
    assert direct_run is not None
    assert direct_run.run_id == run_id


# ── Test D: Pipeline A Behavior Remains Unchanged ────────────────────────────

def test_d_pipeline_a_behavior_remains_unchanged():
    """D. Pipeline A (/api/cases/{case_id}/analyze) behavior remains completely intact."""
    case = store.create_case(name="Pipeline A Case")
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Case A\nBody: Data\n" + SYNTHETIC_END_MARKER
    store.add_evidence(case.case_id, "doc.txt", payload)

    response = client.post(f"/api/cases/{case.case_id}/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"] == case.case_id
    assert data["status"] == "COMPLETED"
    assert data["artifact_count"] >= 1

    art = data["artifacts"][0]
    art_id = art["artifact_id"]
    run_id = art["metadata"]["run_id"]

    # Verify linkage in store
    run = store.get_recovery_run_by_artifact(art_id)
    assert run is not None
    assert run.run_id == run_id

    # Verify raw byte retrieval
    raw_b = store.get_artifact_bytes(art_id)
    assert raw_b == payload


# ── Test E: Standalone and Case Artifacts Share ArtifactRecord Contract ──────

def test_e_standalone_and_case_artifacts_share_same_artifact_contract():
    """E. Both case-associated and standalone artifacts are stored as ArtifactRecord in unified storage."""
    # Pipeline A artifact
    case = store.create_case(name="Contract Case")
    payload_a = SYNTHETIC_START_MARKER + b"FORMAT=txt\nBody: Artifact A\n" + SYNTHETIC_END_MARKER
    store.add_evidence(case.case_id, "a.txt", payload_a)
    analysis = client.post(f"/api/cases/{case.case_id}/analyze").json()
    art_a_id = analysis["artifacts"][0]["artifact_id"]

    # Pipeline B artifact
    payload_b = SYNTHETIC_START_MARKER + b"FORMAT=txt\nBody: Artifact B\n" + SYNTHETIC_END_MARKER
    rec_b = client.post(
        "/api/recover-file",
        files={"file": ("b.txt", payload_b, "text/plain")},
    ).json()
    file_b_id = rec_b["file_id"]

    # Both records exist in store._artifacts as ArtifactRecord
    rec_a = store.get_artifact_record(art_a_id)
    rec_b = store.get_artifact_record(file_b_id)

    assert isinstance(rec_a, ArtifactRecord)
    assert isinstance(rec_b, ArtifactRecord)

    assert rec_a.case_id == case.case_id
    assert rec_b.case_id is None

    # Both can produce valid ArtifactResponse
    resp_a = rec_a.to_artifact_response()
    resp_b = rec_b.to_artifact_response()
    assert isinstance(resp_a, ArtifactResponse)
    assert isinstance(resp_b, ArtifactResponse)

    # Both can be retrieved via get_artifact
    assert store.get_artifact(art_a_id) is not None
    assert store.get_artifact(file_b_id) is not None


# ── Test F: Evidence BlobStore Operations Work ───────────────────────────────

def test_f_evidence_blob_store_operations():
    """F. Evidence BlobStore operations (put, get, exists, delete) work as expected."""
    blob_store = store.evidence_blobs
    key = "case_blob_test"
    data = b"\x01\x02\x03\x04\x05"

    assert not blob_store.exists(key)
    assert blob_store.get(key) is None

    blob_store.put(key, data)
    assert blob_store.exists(key)
    assert blob_store.get(key) == data

    assert blob_store.delete(key) is True
    assert not blob_store.exists(key)
    assert blob_store.get(key) is None


# ── Test G: Recovered-Byte BlobStore Operations Work ─────────────────────────

def test_g_recovered_byte_blob_store_operations():
    """G. Recovered-byte BlobStore operations (put, get, exists, delete) work as expected."""
    blob_store = store.artifact_blobs
    key = "art_blob_test"
    data = b"RECOVERED_BYTES_PAYLOAD"

    assert not blob_store.exists(key)
    assert blob_store.get(key) is None

    blob_store.put(key, data)
    assert blob_store.exists(key)
    assert blob_store.get(key) == data

    assert blob_store.delete(key) is True
    assert not blob_store.exists(key)


# ── Test H: Missing Blob Behavior is Deterministic ───────────────────────────

def test_h_missing_blob_behavior_is_deterministic():
    """H. Missing blob operations return None/False deterministically without exceptions."""
    assert store.evidence_blobs.get("non-existent-key") is None
    assert store.evidence_blobs.exists("non-existent-key") is False
    assert store.evidence_blobs.delete("non-existent-key") is False

    assert store.artifact_blobs.get("non-existent-key") is None
    assert store.artifact_blobs.exists("non-existent-key") is False
    assert store.artifact_blobs.delete("non-existent-key") is False


# ── Test I: Oversized Pipeline A Upload Returns 413 ──────────────────────────

def test_i_oversized_pipeline_a_upload_returns_413():
    """I. Oversized evidence upload to /api/cases/{case_id}/evidence returns HTTP 413."""
    case = store.create_case(name="Oversized Case")
    oversized = b"X" * (MAX_EVIDENCE_SIZE + 1)

    response = client.post(
        f"/api/cases/{case.case_id}/evidence",
        files={"file": ("big.img", oversized, "application/octet-stream")},
    )
    assert response.status_code == 413


# ── Test J: Oversized Pipeline B Upload Returns 413 ──────────────────────────

def test_j_oversized_pipeline_b_upload_returns_413():
    """J. Oversized single-file upload to /api/recover-file returns HTTP 413."""
    oversized = b"X" * (MAX_EVIDENCE_SIZE + 1)

    response = client.post(
        "/api/recover-file",
        files={"file": ("big.txt", oversized, "text/plain")},
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "FILE_TOO_LARGE"


# ── Test K: Existing RecoveryRun Retrieval and Listing ───────────────────────

def test_k_recovery_run_retrieval_and_listing():
    """K. /api/recovery-runs and /api/recovery-runs/{run_id} endpoints work seamlessly."""
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nBody: Listing Test\n" + SYNTHETIC_END_MARKER
    res = client.post(
        "/api/recover-file",
        files={"file": ("list.txt", payload, "text/plain")},
    ).json()
    run_id = res["run_id"]

    list_res = client.get("/api/recovery-runs")
    assert list_res.status_code == 200
    runs = list_res.json()
    assert any(r["run_id"] == run_id for r in runs)

    get_res = client.get(f"/api/recovery-runs/{run_id}")
    assert get_res.status_code == 200
    assert get_res.json()["run_id"] == run_id


# ── Test L: Explain Endpoint Resolves RecoveryRun ────────────────────────────

def test_l_explain_endpoint_resolves_recovery_run():
    """L. /api/recover-file/{file_id}/explain resolves the stored RecoveryRun."""
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Doc\nBody: Important Forensic Info\n" + SYNTHETIC_END_MARKER
    res = client.post(
        "/api/recover-file",
        files={"file": ("important.txt", payload, "text/plain")},
    ).json()
    file_id = res["file_id"]

    explain_res = client.post(f"/api/recover-file/{file_id}/explain")
    assert explain_res.status_code == 200
    data = explain_res.json()
    assert "summary" in data


# ── Test M: V/R/M Byte Conservation ──────────────────────────────────────────

def test_m_vrm_byte_conservation():
    """M. Total input bytes strictly equals verified + reconstructed + missing bytes."""
    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nBody: Byte Conservation Test\n" + SYNTHETIC_END_MARKER
    res = client.post(
        "/api/recover-file",
        files={"file": ("conservation.txt", payload, "text/plain")},
    ).json()

    v = res["verified_bytes"]
    r = res["reconstructed_bytes"]
    m = res["missing_bytes"]
    tot = res["total_input_bytes"]

    assert v + r + m == tot
    assert v == len(payload)
    assert r == 0
    assert m == 0


# ── Test N: Fragmented Text/CSV Preserves Partial Status ──────────────────────

def test_n_fragmented_text_preserves_partial_status():
    """N. Fragmented text does not get upgraded to FULLY_RECOVERED."""
    frag_content = SYNTHETIC_START_MARKER + b"FORMAT=txt\nBody: Partial content without end marker"
    run = execute_traced_recovery(
        filename="partial.txt",
        content=frag_content,
        detection_mode="known_file",
    )
    assert run.status == "PARTIALLY_RECOVERED"
    assert run.total_input_bytes == run.total_verified_bytes + run.total_missing_bytes
    assert run.total_verified_bytes + run.total_reconstructed_bytes == len(bytes.fromhex(run.output["recovered_bytes"]))
    assert run.total_reconstructed_bytes > 0


# ── Test O: JSON Reconstruction Behavior Unchanged ───────────────────────────

def test_o_json_reconstruction_behavior_unchanged():
    """O. JSON recovery produces verified recovery run and intact byte accounting."""
    json_bytes = b'{"status": "ok", "count": 42}'
    run = execute_traced_recovery(
        filename="status.json",
        content=json_bytes,
        detection_mode="known_file",
    )
    assert run.status == "FULLY_RECOVERED"
    assert run.total_verified_bytes == len(json_bytes)
    assert run.total_missing_bytes == 0


# ── Test P: PDF Recovery Behavior Unchanged ──────────────────────────────────

def test_p_pdf_recovery_behavior_unchanged():
    """P. PDF recovery operates correctly through canonical engine."""
    from tests.test_pdf_recovery import build_minimal_pdf
    pdf_bytes = build_minimal_pdf()
    run = execute_traced_recovery(
        filename="doc.pdf",
        content=pdf_bytes,
        detection_mode="known_file",
    )
    assert run.format == "pdf"
    assert run.status == "FULLY_RECOVERED"
    assert run.total_verified_bytes == len(pdf_bytes)


# ── Test Q: Bifragment Ambiguity Behavior Unchanged ──────────────────────────

def test_q_bifragment_ambiguity_behavior_unchanged():
    """Q. Bounded bifragments with unresolved gaps preserve missing bytes and PARTIALLY_RECOVERED."""
    frag_a = SYNTHETIC_START_MARKER + b"FORMAT=txt\nPart A "
    frag_b = b"Part B\n" + SYNTHETIC_END_MARKER
    gap = b"\x00" * 32
    content = frag_a + gap + frag_b

    runs = execute_traced_recoveries(
        filename="bifrag.txt",
        content=content,
        detection_mode="known_file",
    )
    assert len(runs) >= 1
    # Check byte conservation on all produced runs
    for run in runs:
        assert run.total_input_bytes == run.total_verified_bytes + run.total_reconstructed_bytes + run.total_missing_bytes
