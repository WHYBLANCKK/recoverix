"""
test_idempotent_case_analysis_m314.py — Regression tests for M3.14.0 Idempotent Case Analysis.

Covers:
- TEST 1: First analysis produces expected artifacts.
- TEST 2: Repeated analysis of unchanged evidence creates no duplicates (stable identity).
- TEST 3: Legitimate distinct artifacts from multi-candidate evidence are preserved.
- TEST 4: Multiple evidence files in a case do not collide, replace, or collapse artifacts.
- TEST 5: Reanalysis after evidence changes updates without leaving stale or duplicate artifacts.
- TEST 6: Failure handling preserves prior valid state.
- TEST 7: Concurrent analysis requests do not produce duplicate logical artifacts.
- Repository unit tests for delete_artifact on both SqliteStore and InMemoryStore.
"""

from __future__ import annotations

import concurrent.futures
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.store import store
from backend.app.storage.sqlite_store import SqliteStore
from backend.app.storage.memory_store import InMemoryStore
from backend.app.models.artifact import (
    ArtifactResponse,
    ConfidenceBreakdownSchema,
    ArtifactProvenanceSchema,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# Minimal valid payloads for multi-format evidence
VALID_PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
VALID_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\x00IEND\xaeB`\x82"
)


# ==============================================================================
# TEST 1 — FIRST ANALYSIS
# ==============================================================================

def test_01_first_analysis_success(client: TestClient):
    """TEST 1: A valid case can be analyzed and produces expected artifacts."""
    create_res = client.post("/api/cases", json={"name": "M314 Test 1 Case"})
    assert create_res.status_code == 201
    case_id = create_res.json()["case_id"]

    ev_payload = b"Sample forensic text evidence for initial analysis."
    up_res = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("evidence.txt", ev_payload, "application/octet-stream")},
    )
    assert up_res.status_code == 200

    analyze_res = client.post(f"/api/cases/{case_id}/analyze")
    assert analyze_res.status_code == 200
    data = analyze_res.json()

    assert data["case_id"] == case_id
    assert data["status"] == "COMPLETED"
    assert data["artifact_count"] >= 1
    assert len(data["artifacts"]) == data["artifact_count"]

    art = data["artifacts"][0]
    assert art["artifact_id"].startswith("art_")
    assert art["case_id"] == case_id
    assert art["status"] in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")

    # Verify download of recovered bytes
    dl_res = client.get(f"/api/artifacts/{art['artifact_id']}/download")
    assert dl_res.status_code == 200
    assert len(dl_res.content) > 0


# ==============================================================================
# TEST 2 — REPEATED ANALYSIS
# ==============================================================================

def test_02_repeated_analysis_no_duplicates(client: TestClient):
    """TEST 2: Analyzing unchanged evidence twice (and thrice) creates no duplicates and preserves stable IDs."""
    create_res = client.post("/api/cases", json={"name": "M314 Test 2 Case"})
    case_id = create_res.json()["case_id"]

    ev_payload = b"Deterministic payload for idempotency verification."
    client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("evidence.txt", ev_payload, "application/octet-stream")},
    )

    # First analysis
    res1 = client.post(f"/api/cases/{case_id}/analyze")
    assert res1.status_code == 200
    data1 = res1.json()
    count1 = data1["artifact_count"]
    ids1 = [a["artifact_id"] for a in data1["artifacts"]]

    # Verify case state after first analysis
    case_get1 = client.get(f"/api/cases/{case_id}").json()
    assert case_get1["artifact_count"] == count1

    # Second analysis of unchanged evidence
    res2 = client.post(f"/api/cases/{case_id}/analyze")
    assert res2.status_code == 200
    data2 = res2.json()
    count2 = data2["artifact_count"]
    ids2 = [a["artifact_id"] for a in data2["artifacts"]]

    assert count2 == count1
    assert ids2 == ids1

    # Third analysis of unchanged evidence
    res3 = client.post(f"/api/cases/{case_id}/analyze")
    assert res3.status_code == 200
    data3 = res3.json()
    assert data3["artifact_count"] == count1
    assert [a["artifact_id"] for a in data3["artifacts"]] == ids1

    # Verify GET /api/cases/{case_id}/artifacts returns exact count without duplicate items
    arts_res = client.get(f"/api/cases/{case_id}/artifacts")
    assert arts_res.status_code == 200
    arts = arts_res.json()
    assert len(arts) == count1
    assert [a["artifact_id"] for a in arts] == ids1

    # Verify case summary artifact_count matches
    case_get_final = client.get(f"/api/cases/{case_id}").json()
    assert case_get_final["artifact_count"] == count1


# ==============================================================================
# TEST 3 — LEGITIMATE DISTINCT ARTIFACTS
# ==============================================================================

def test_03_multi_candidate_artifacts_preserved(client: TestClient):
    """TEST 3: Multiple legitimate distinct artifacts from same evidence are preserved and not collapsed."""
    create_res = client.post("/api/cases", json={"name": "M314 Test 3 Multi-Candidate"})
    case_id = create_res.json()["case_id"]

    # Evidence buffer containing both a PDF and a PNG
    multi_evidence = VALID_PDF + b"\x00" * 32 + VALID_PNG
    client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("disk.img", multi_evidence, "application/octet-stream")},
    )

    # First analysis
    res1 = client.post(f"/api/cases/{case_id}/analyze")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["artifact_count"] == 2

    formats = {a["format"] for a in data1["artifacts"]}
    assert "pdf" in formats
    assert "png" in formats

    art_ids_1 = {a["artifact_id"] for a in data1["artifacts"]}
    assert len(art_ids_1) == 2

    # Second analysis
    res2 = client.post(f"/api/cases/{case_id}/analyze")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["artifact_count"] == 2
    art_ids_2 = {a["artifact_id"] for a in data2["artifacts"]}
    assert art_ids_2 == art_ids_1

    # Verify store artifact listing
    arts_res = client.get(f"/api/cases/{case_id}/artifacts")
    assert arts_res.status_code == 200
    assert len(arts_res.json()) == 2


# ==============================================================================
# TEST 4 — MULTIPLE EVIDENCE FILES
# ==============================================================================

def test_04_multiple_evidence_files_preservation(client: TestClient):
    """TEST 4: Analyzing a case containing multiple evidence files does not replace or collapse artifacts from other evidence."""
    create_res = client.post("/api/cases", json={"name": "M314 Test 4 Multi-Evidence Case"})
    case_id = create_res.json()["case_id"]

    # Step 1: Pre-register an artifact belonging to another evidence file ("evidence_alpha.raw")
    alpha_art = ArtifactResponse(
        artifact_id="art_alpha_foreign",
        case_id=case_id,
        format="csv",
        size_bytes=100,
        confidence_score=95,
        score_breakdown=ConfidenceBreakdownSchema(
            header_validity=20, footer_validity=20, structural_validation=25, size_plausibility=15, reconstruction_integrity=15, total=95
        ),
        status="FULLY_RECOVERED",
        provenance=ArtifactProvenanceSchema(
            verified_bytes=100, reconstructed_bytes=0, missing_bytes=0, reconstruction_method="NONE", validation_status="PASSED"
        ),
        metadata={
            "original_filename": "evidence_alpha.raw",
            "evidence_filename": "evidence_alpha.raw",
            "evidence_file_id": "evidence_alpha.raw",
        },
    )
    store.add_artifact(alpha_art)
    store.store_artifact_bytes("art_alpha_foreign", b"col1,col2\nval1,val2\n")

    # Verify case has 1 artifact from alpha
    case_check = client.get(f"/api/cases/{case_id}").json()
    assert case_check["artifact_count"] == 1

    # Step 2: Upload and analyze a second evidence file ("evidence_beta.raw")
    beta_payload = VALID_PDF
    up_res = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("evidence_beta.raw", beta_payload, "application/octet-stream")},
    )
    assert up_res.status_code == 200

    analyze_res = client.post(f"/api/cases/{case_id}/analyze")
    assert analyze_res.status_code == 200
    beta_data = analyze_res.json()
    assert beta_data["artifact_count"] >= 1

    # Step 3: Verify that alpha artifact is STILL in the case!
    all_arts_res = client.get(f"/api/cases/{case_id}/artifacts")
    assert all_arts_res.status_code == 200
    all_arts = all_arts_res.json()

    art_ids = [a["artifact_id"] for a in all_arts]
    assert "art_alpha_foreign" in art_ids, "Artifact from evidence_alpha.raw was accidentally deleted!"
    assert any(a["artifact_id"] != "art_alpha_foreign" for a in all_arts), "New artifact from evidence_beta.raw was not added!"

    # Re-analyze beta evidence: alpha artifact must still be preserved!
    analyze_res_2 = client.post(f"/api/cases/{case_id}/analyze")
    assert analyze_res_2.status_code == 200

    all_arts_2 = client.get(f"/api/cases/{case_id}/artifacts").json()
    assert any(a["artifact_id"] == "art_alpha_foreign" for a in all_arts_2)
    assert len(all_arts_2) == len(all_arts)


# ==============================================================================
# TEST 5 — REANALYSIS AFTER EVIDENCE CHANGES
# ==============================================================================

def test_05_reanalysis_after_evidence_change(client: TestClient):
    """TEST 5: New or changed evidence is handled without leaving stale or duplicate results."""
    create_res = client.post("/api/cases", json={"name": "M314 Test 5 Evidence Change Case"})
    case_id = create_res.json()["case_id"]

    # Initial evidence has 2 artifacts (PDF + PNG)
    multi_evidence = VALID_PDF + b"\x00" * 32 + VALID_PNG
    client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("target.img", multi_evidence, "application/octet-stream")},
    )

    res1 = client.post(f"/api/cases/{case_id}/analyze")
    assert res1.status_code == 200
    assert res1.json()["artifact_count"] == 2

    # Case now has 2 artifacts
    assert client.get(f"/api/cases/{case_id}").json()["artifact_count"] == 2

    # Upload replacement evidence containing ONLY a single text candidate
    single_evidence = b"Replacement single candidate content."
    client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("target.img", single_evidence, "application/octet-stream")},
    )

    # Re-analyze with the new evidence
    res2 = client.post(f"/api/cases/{case_id}/analyze")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["artifact_count"] == 1

    # Verify no stale artifacts from old evidence remain in case
    arts_res = client.get(f"/api/cases/{case_id}/artifacts")
    assert arts_res.status_code == 200
    arts = arts_res.json()
    assert len(arts) == 1
    assert arts[0]["format"] == "txt"

    # Case artifact count in store must also reflect 1
    assert client.get(f"/api/cases/{case_id}").json()["artifact_count"] == 1


# ==============================================================================
# TEST 6 — FAILURE HANDLING
# ==============================================================================

def test_06_failure_handling_preserves_prior_state(client: TestClient, monkeypatch):
    """TEST 6: A failed analysis does not leave the case in a misleading state or destroy prior valid results."""
    create_res = client.post("/api/cases", json={"name": "M314 Test 6 Failure Handling Case"})
    case_id = create_res.json()["case_id"]

    ev_payload = b"Valid evidence for failure testing."
    client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("test.txt", ev_payload, "application/octet-stream")},
    )

    # Initial successful analysis
    res1 = client.post(f"/api/cases/{case_id}/analyze")
    assert res1.status_code == 200
    prior_arts = res1.json()["artifacts"]
    assert len(prior_arts) >= 1
    prior_id = prior_arts[0]["artifact_id"]

    # Simulate unexpected failure during recovery engine execution
    from backend.app.api import analysis

    def mock_fail(*args, **kwargs):
        raise RuntimeError("Simulated recovery engine crash")

    monkeypatch.setattr(analysis, "execute_traced_recoveries", mock_fail)

    with pytest.raises(RuntimeError, match="Simulated recovery engine crash"):
        client.post(f"/api/cases/{case_id}/analyze")

    # Verify prior valid state remains completely intact in store!
    case_get = client.get(f"/api/cases/{case_id}").json()
    assert case_get["artifact_count"] == len(prior_arts)

    arts_get = client.get(f"/api/cases/{case_id}/artifacts").json()
    assert len(arts_get) == len(prior_arts)
    assert arts_get[0]["artifact_id"] == prior_id


# ==============================================================================
# TEST 7 — CONCURRENT REQUESTS
# ==============================================================================

def test_07_concurrent_analysis_requests(client: TestClient):
    """TEST 7: Concurrent analysis requests do not produce duplicate logical artifacts."""
    create_res = client.post("/api/cases", json={"name": "M314 Test 7 Concurrent Analysis"})
    case_id = create_res.json()["case_id"]

    ev_payload = b"Concurrent analysis test payload."
    client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("evidence.txt", ev_payload, "application/octet-stream")},
    )

    # Fire 5 concurrent analyze requests
    def call_analyze():
        return client.post(f"/api/cases/{case_id}/analyze")

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(call_analyze) for _ in range(5)]
        results = [f.result() for f in futures]

    for res in results:
        assert res.status_code == 200
        assert res.json()["artifact_count"] == 1

    # Verify final persisted state has exactly 1 artifact, not 5
    case_get = client.get(f"/api/cases/{case_id}").json()
    assert case_get["artifact_count"] == 1

    arts_get = client.get(f"/api/cases/{case_id}/artifacts").json()
    assert len(arts_get) == 1


# ==============================================================================
# UNIT TESTS: delete_artifact ON SqliteStore AND InMemoryStore
# ==============================================================================

def test_delete_artifact_sqlite_store():
    """Verify delete_artifact cleans up artifacts, artifact_runs, and blobs in SqliteStore."""
    test_store = SqliteStore(":memory:")
    case = test_store.create_case("Delete Test Case")

    art = ArtifactResponse(
        artifact_id="art_del_sq",
        case_id=case.case_id,
        format="txt",
        size_bytes=10,
        confidence_score=100,
        score_breakdown=ConfidenceBreakdownSchema(
            header_validity=20, footer_validity=20, structural_validation=30, size_plausibility=15, reconstruction_integrity=15, total=100
        ),
        status="FULLY_RECOVERED",
        provenance=ArtifactProvenanceSchema(
            verified_bytes=10, reconstructed_bytes=0, missing_bytes=0, reconstruction_method="NONE", validation_status="PASSED"
        ),
    )
    test_store.add_artifact(art)
    test_store.store_artifact_bytes("art_del_sq", b"data123456")

    assert test_store.get_artifact("art_del_sq") is not None
    assert test_store.get_artifact_bytes("art_del_sq") == b"data123456"
    assert test_store.get_case(case.case_id).artifact_count == 1

    # Delete artifact
    deleted = test_store.delete_artifact("art_del_sq")
    assert deleted is True

    # Verify absence
    assert test_store.get_artifact("art_del_sq") is None
    assert test_store.get_artifact_bytes("art_del_sq") is None
    assert test_store.get_case(case.case_id).artifact_count == 0

    # Deleting non-existent artifact returns False
    assert test_store.delete_artifact("non_existent_id") is False


def test_delete_artifact_memory_store():
    """Verify delete_artifact cleans up artifacts, case_artifacts, and blobs in InMemoryStore."""
    mem_store = InMemoryStore()
    case = mem_store.create_case("Memory Delete Case")

    art = ArtifactResponse(
        artifact_id="art_del_mem",
        case_id=case.case_id,
        format="txt",
        size_bytes=10,
        confidence_score=100,
        score_breakdown=ConfidenceBreakdownSchema(
            header_validity=20, footer_validity=20, structural_validation=30, size_plausibility=15, reconstruction_integrity=15, total=100
        ),
        status="FULLY_RECOVERED",
        provenance=ArtifactProvenanceSchema(
            verified_bytes=10, reconstructed_bytes=0, missing_bytes=0, reconstruction_method="NONE", validation_status="PASSED"
        ),
    )
    mem_store.add_artifact(art)
    mem_store.store_artifact_bytes("art_del_mem", b"data123456")

    assert mem_store.get_artifact("art_del_mem") is not None
    assert mem_store.get_artifact_bytes("art_del_mem") == b"data123456"
    assert mem_store.get_case(case.case_id).artifact_count == 1

    # Delete artifact
    deleted = mem_store.delete_artifact("art_del_mem")
    assert deleted is True

    # Verify absence
    assert mem_store.get_artifact("art_del_mem") is None
    assert mem_store.get_artifact_bytes("art_del_mem") is None
    assert mem_store.get_case(case.case_id).artifact_count == 0

    # Deleting non-existent artifact returns False
    assert mem_store.delete_artifact("non_existent_id") is False
