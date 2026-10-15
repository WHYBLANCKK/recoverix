"""
test_blob_integrity_and_artifact_identity_m321.py — Milestone M3.21.0 Regression Test Suite.

Audits artifact payload storage, association, retrieval, and download integrity:
1. Two artifacts with different payloads.
2. Multiple artifacts within the same case.
3. Artifacts in separate cases.
4. Identical payloads stored under different artifact identifiers.
5. The same artifact identifier updated with new payload bytes.
6. Repeated analysis of unchanged evidence.
7. Reanalysis after evidence changes (including stale blob deletion).
8. Artifact deletion and related blob cleanup.
9. Missing blob records handling.
10. Missing artifact records handling.
11. Evidence vs Artifact namespace collision isolation.
12. Exact byte integrity across diverse binary fixtures.
13. Transactional partial-failure behavior.
14. SqliteStore and InMemoryStore parity matrix.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.artifact import (
    ArtifactProvenanceSchema,
    ArtifactRecord,
    ArtifactResponse,
    ConfidenceBreakdownSchema,
)
from backend.app.models.recovery_run import RecoveryRun
from backend.app.storage.blob_store import InMemoryBlobStore
from backend.app.storage.memory_store import InMemoryStore
from backend.app.storage.sqlite_blob_store import SqliteBlobStore
from backend.app.storage.sqlite_engine import SqliteEngine
from backend.app.storage.sqlite_store import SqliteStore
from backend.app.store import store

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_store():
    store.clear()
    yield
    store.clear()


# ── Scenario 1: Two Artifacts with Different Payloads ─────────────────────────


def test_01_two_artifacts_different_payloads():
    """Verify two artifacts with different payloads maintain strict association and no cross-talk."""
    case = store.create_case("Case 1 Distinct Payloads")
    payload_a = b"PAYLOAD_ALPHA_EXACT_BYTES_12345"
    payload_b = b"PAYLOAD_BETA_EXACT_BYTES_67890"

    rec_a = ArtifactRecord(
        artifact_id="art-distinct-a",
        case_id=case.case_id,
        recovered_filename="alpha.txt",
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=95.0,
        verified_bytes=len(payload_a),
        is_downloadable=True,
    )
    rec_b = ArtifactRecord(
        artifact_id="art-distinct-b",
        case_id=case.case_id,
        recovered_filename="beta.txt",
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=95.0,
        verified_bytes=len(payload_b),
        is_downloadable=True,
    )

    store.save_artifact_record(rec_a)
    store.store_artifact_bytes("art-distinct-a", payload_a)

    store.save_artifact_record(rec_b)
    store.store_artifact_bytes("art-distinct-b", payload_b)

    # Repository retrieval
    assert store.get_artifact_bytes("art-distinct-a") == payload_a
    assert store.get_artifact_bytes("art-distinct-b") == payload_b

    # API download retrieval
    resp_a = client.get("/api/artifacts/art-distinct-a/download")
    assert resp_a.status_code == 200
    assert resp_a.content == payload_a
    assert hashlib.sha256(resp_a.content).hexdigest() == hashlib.sha256(payload_a).hexdigest()

    resp_b = client.get("/api/artifacts/art-distinct-b/download")
    assert resp_b.status_code == 200
    assert resp_b.content == payload_b
    assert hashlib.sha256(resp_b.content).hexdigest() == hashlib.sha256(payload_b).hexdigest()


# ── Scenario 2: Multiple Artifacts Within the Same Case ───────────────────────


def test_02_multiple_artifacts_same_case():
    """Verify multiple artifacts of different formats within one case retrieve correct payloads."""
    case = store.create_case("Case 2 Multi-Format")
    payloads = {
        "art-txt-01": b"Plain text evidence body",
        "art-png-01": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01",
        "art-json-01": b'{"case": "test", "valid": true}',
    }

    for art_id, content in payloads.items():
        fmt = art_id.split("-")[1]
        rec = ArtifactRecord(
            artifact_id=art_id,
            case_id=case.case_id,
            recovered_filename=f"file.{fmt}",
            format=fmt,
            status="FULLY_RECOVERED",
            confidence_score=90.0,
            verified_bytes=len(content),
            is_downloadable=True,
        )
        store.save_artifact_record(rec)
        store.store_artifact_bytes(art_id, content)

    for art_id, expected_bytes in payloads.items():
        retrieved = store.get_artifact_bytes(art_id)
        assert retrieved == expected_bytes
        resp = client.get(f"/api/artifacts/{art_id}/download")
        assert resp.status_code == 200
        assert resp.content == expected_bytes


# ── Scenario 3: Artifacts in Separate Cases ───────────────────────────────────


def test_03_artifacts_in_separate_cases():
    """Verify artifacts belonging to different cases are fully isolated and download their own bytes."""
    case1 = store.create_case("Case 3 Alpha")
    case2 = store.create_case("Case 3 Beta")

    payload1 = b"CASE_ALPHA_SECRET_DATA"
    payload2 = b"CASE_BETA_SECRET_DATA"

    rec1 = ArtifactRecord(
        artifact_id="art-case1",
        case_id=case1.case_id,
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=90.0,
        verified_bytes=len(payload1),
        is_downloadable=True,
    )
    rec2 = ArtifactRecord(
        artifact_id="art-case2",
        case_id=case2.case_id,
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=90.0,
        verified_bytes=len(payload2),
        is_downloadable=True,
    )

    store.save_artifact_record(rec1)
    store.store_artifact_bytes("art-case1", payload1)

    store.save_artifact_record(rec2)
    store.store_artifact_bytes("art-case2", payload2)

    assert store.get_artifact_bytes("art-case1") == payload1
    assert store.get_artifact_bytes("art-case2") == payload2

    resp1 = client.get("/api/artifacts/art-case1/download")
    assert resp1.content == payload1

    resp2 = client.get("/api/artifacts/art-case2/download")
    assert resp2.content == payload2


# ── Scenario 4: Identical Payloads Stored Under Different Identifiers ─────────


def test_04_identical_payloads_different_identifiers():
    """Verify identical payloads stored under separate IDs do not mutate or delete each other."""
    case = store.create_case("Case 4 Shared Content")
    shared_payload = b"IDENTICAL_EVIDENCE_RECOVERED_STREAM"

    rec_a = ArtifactRecord(
        artifact_id="art-shared-a",
        case_id=case.case_id,
        format="bin",
        status="FULLY_RECOVERED",
        confidence_score=90.0,
        verified_bytes=len(shared_payload),
        is_downloadable=True,
    )
    rec_b = ArtifactRecord(
        artifact_id="art-shared-b",
        case_id=case.case_id,
        format="bin",
        status="FULLY_RECOVERED",
        confidence_score=90.0,
        verified_bytes=len(shared_payload),
        is_downloadable=True,
    )

    store.save_artifact_record(rec_a)
    store.store_artifact_bytes("art-shared-a", shared_payload)

    store.save_artifact_record(rec_b)
    store.store_artifact_bytes("art-shared-b", shared_payload)

    assert store.get_artifact_bytes("art-shared-a") == shared_payload
    assert store.get_artifact_bytes("art-shared-b") == shared_payload

    # Update artifact A with different bytes
    new_payload_a = b"MODIFIED_A_ONLY"
    store.store_artifact_bytes("art-shared-a", new_payload_a)
    assert store.get_artifact_bytes("art-shared-a") == new_payload_a
    # Artifact B MUST remain unchanged
    assert store.get_artifact_bytes("art-shared-b") == shared_payload

    # Delete artifact A
    assert store.delete_artifact("art-shared-a") is True
    assert store.get_artifact_bytes("art-shared-a") is None
    # Artifact B MUST still have its payload
    assert store.get_artifact_bytes("art-shared-b") == shared_payload
    resp_b = client.get("/api/artifacts/art-shared-b/download")
    assert resp_b.status_code == 200
    assert resp_b.content == shared_payload


# ── Scenario 5: Artifact Payload Update Replaces Cleanly ───────────────────────


def test_05_artifact_payload_update_replaces_cleanly():
    """Verify updating an artifact's payload serves only new bytes without stale retention."""
    case = store.create_case("Case 5 Update")
    payload_v1 = b"VERSION_1_ORIGINAL_BYTES"
    payload_v2 = b"VERSION_2_RECOVERED_AND_RECONSTRUCTED_BYTES_EXTENDED"

    rec = ArtifactRecord(
        artifact_id="art-update-05",
        case_id=case.case_id,
        format="txt",
        status="PARTIALLY_RECOVERED",
        confidence_score=70.0,
        verified_bytes=len(payload_v1),
        is_downloadable=True,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes("art-update-05", payload_v1)

    assert store.get_artifact_bytes("art-update-05") == payload_v1
    resp_v1 = client.get("/api/artifacts/art-update-05/download")
    assert resp_v1.content == payload_v1

    # Overwrite payload
    store.store_artifact_bytes("art-update-05", payload_v2)
    assert store.get_artifact_bytes("art-update-05") == payload_v2
    resp_v2 = client.get("/api/artifacts/art-update-05/download")
    assert resp_v2.content == payload_v2
    assert resp_v2.content != payload_v1
    assert len(resp_v2.content) == len(payload_v2)


# ── Scenario 6: Repeated Analysis of Unchanged Evidence ───────────────────────


def test_06_repeated_analysis_unchanged_evidence():
    """Verify re-running analysis on unchanged evidence preserves deterministic IDs and payload bytes."""
    case = store.create_case("Case 6 Repeated Analysis")
    evidence = (
        b"<<<RECOVERIX_START_OFFSET_0000000000>>>\n"
        b"Content: Consistent Forensic Image\n"
        b"<<<RECOVERIX_END_OFFSET_0000000000>>>\n"
    )
    store.add_evidence(case.case_id, "disk.raw", evidence)

    # First analysis
    resp1 = client.post(f"/api/cases/{case.case_id}/analyze")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["artifact_count"] >= 1
    art_ids_1 = [a["artifact_id"] for a in data1["artifacts"]]

    downloads_1 = {}
    for aid in art_ids_1:
        d = client.get(f"/api/artifacts/{aid}/download")
        downloads_1[aid] = d.content

    # Second analysis on same unchanged evidence
    resp2 = client.post(f"/api/cases/{case.case_id}/analyze")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["artifact_count"] == data1["artifact_count"]
    art_ids_2 = [a["artifact_id"] for a in data2["artifacts"]]

    # Stable deterministic artifact IDs
    assert art_ids_1 == art_ids_2

    # Byte-equal payload downloads across repeated runs
    for aid in art_ids_2:
        d = client.get(f"/api/artifacts/{aid}/download")
        assert d.content == downloads_1[aid]


# ── Scenario 7: Reanalysis After Evidence Change & Blob Cleanup ───────────────


def test_07_reanalysis_after_evidence_change_and_blob_cleanup():
    """Verify evidence change replaces artifacts and cleanly removes stale blobs."""
    case = store.create_case("Case 7 Evidence Change")
    ev1 = (
        b"<<<RECOVERIX_START_OFFSET_0000000000>>>\n"
        b"Candidate One: Initial State\n"
        b"<<<RECOVERIX_END_OFFSET_0000000000>>>\n"
    )
    store.add_evidence(case.case_id, "evidence.raw", ev1)

    res1 = client.post(f"/api/cases/{case.case_id}/analyze")
    assert res1.status_code == 200
    arts1 = res1.json()["artifacts"]
    assert len(arts1) >= 1
    old_art_id = arts1[0]["artifact_id"]

    dl1 = client.get(f"/api/artifacts/{old_art_id}/download")
    assert dl1.status_code == 200
    assert b"Candidate One" in dl1.content

    # New evidence with different candidate
    ev2 = (
        b"<<<RECOVERIX_START_OFFSET_0000000500>>>\n"
        b"Candidate Two: Completely Different Content\n"
        b"<<<RECOVERIX_END_OFFSET_0000000500>>>\n"
    )
    store.add_evidence(case.case_id, "evidence.raw", ev2)

    res2 = client.post(f"/api/cases/{case.case_id}/analyze")
    assert res2.status_code == 200
    arts2 = res2.json()["artifacts"]
    new_art_ids = [a["artifact_id"] for a in arts2]

    # Verify stale artifact was deleted and its blob is gone
    if old_art_id not in new_art_ids:
        stale_dl = client.get(f"/api/artifacts/{old_art_id}/download")
        assert stale_dl.status_code == 404
        assert store.get_artifact_bytes(old_art_id) is None


# ── Scenario 8: Artifact Deletion and Related Blob Cleanup ────────────────────


def test_08_artifact_deletion_and_blob_cleanup(tmp_path):
    """Verify delete_artifact cleans up record, linkages, and blob in both SqliteStore and InMemoryStore."""
    db_file = str(tmp_path / "del_test.db")
    sql_store = SqliteStore(db_file)
    mem_store = InMemoryStore()

    for st in (sql_store, mem_store):
        c = st.create_case("Del Case")
        rec = ArtifactRecord(
            artifact_id="art-del-08",
            case_id=c.case_id,
            format="bin",
            status="FULLY_RECOVERED",
            confidence_score=90.0,
            verified_bytes=20,
            is_downloadable=True,
        )
        st.save_artifact_record(rec)
        st.store_artifact_bytes("art-del-08", b"RECOVERED_BYTES_DEL")

        assert st.get_artifact_record("art-del-08") is not None
        assert st.get_artifact_bytes("art-del-08") == b"RECOVERED_BYTES_DEL"

        # Delete artifact
        deleted = st.delete_artifact("art-del-08")
        assert deleted is True

        # Both record and blob must be deleted
        assert st.get_artifact_record("art-del-08") is None
        assert st.get_artifact_bytes("art-del-08") is None

        # Repeat delete returns False
        assert st.delete_artifact("art-del-08") is False

    sql_store.close()


# ── Scenario 9: Missing Blob Records Handling ─────────────────────────────────


def test_09_missing_blob_records_handling():
    """Verify artifact with missing blob returns 404 on download and never fabricates bytes."""
    case = store.create_case("Case 9 Missing Blob")
    rec = ArtifactRecord(
        artifact_id="art-missing-blob",
        case_id=case.case_id,
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=90.0,
        verified_bytes=100,
        is_downloadable=True,
        content_preview="Preview that must not be used as payload",
    )
    store.save_artifact_record(rec)
    # Deliberately do NOT store bytes

    assert store.get_artifact_bytes("art-missing-blob") is None
    resp = client.get("/api/artifacts/art-missing-blob/download")
    assert resp.status_code == 404
    assert resp.content != b"Preview that must not be used as payload"


# ── Scenario 10: Missing Artifact Record Handling ─────────────────────────────


def test_10_missing_artifact_record_handling():
    """Verify downloading an unrecorded key returns 404 even if an orphaned blob exists."""
    # Put orphaned blob in artifact_blobs
    store.artifact_blobs.put("orphaned-key-10", b"ORPHANED_DATA")

    # Download must check artifact record first and return 404
    resp = client.get("/api/artifacts/orphaned-key-10/download")
    assert resp.status_code == 404


# ── Scenario 11: Evidence vs Artifact Namespace Collision Isolation ───────────


def test_11_evidence_vs_artifact_namespace_collision_isolation(tmp_path):
    """Verify complete domain isolation between evidence blobs and artifact blobs when IDs collide."""
    db_file = str(tmp_path / "collision_iso.db")
    sql_store = SqliteStore(db_file)
    mem_store = InMemoryStore()

    for st in (sql_store, mem_store):
        shared_id = "shared-id-xyz"
        ev_data = b"RAW_DISK_EVIDENCE_SECTORS_001"
        art_data = b"RECOVERED_OUTPUT_FILE_BYTES_999"

        case = st.create_case("Collision Case")
        # Ingest evidence under case_id
        st.evidence_blobs.put(shared_id, ev_data)
        # Store artifact payload under the same ID
        st.store_artifact_bytes(shared_id, art_data)

        # 1. Independent retrieval: artifact must not overwrite evidence
        assert st.evidence_blobs.get(shared_id) == ev_data
        assert st.get_artifact_bytes(shared_id) == art_data

        # 2. Deleting artifact must not touch evidence blob
        st.artifact_blobs.delete(shared_id)
        assert st.get_artifact_bytes(shared_id) is None
        assert st.evidence_blobs.get(shared_id) == ev_data

        # 3. Clear evidence blobs must not clear artifact blobs
        st.store_artifact_bytes(shared_id, art_data)
        st.evidence_blobs.clear()
        assert st.evidence_blobs.get(shared_id) is None
        assert st.get_artifact_bytes(shared_id) == art_data

        # 4. Clear artifact blobs must not clear evidence blobs
        st.evidence_blobs.put(shared_id, ev_data)
        st.artifact_blobs.clear()
        assert st.get_artifact_bytes(shared_id) is None
        assert st.evidence_blobs.get(shared_id) == ev_data

    sql_store.close()


# ── Scenario 12: Exact Byte Integrity Across Diverse Binary Fixtures ──────────


@pytest.mark.parametrize(
    "fixture_name,payload",
    [
        ("plain_text", b"Hello Recoverix forensic integrity test."),
        ("non_ascii_utf8", "Привет мир! こんにちは世界 🌟 Forensic Audit".encode("utf-8")),
        ("embedded_nulls", b"HEADER\x00\x00\x00\x01\x00\x02\x00TRAILER\x00"),
        ("arbitrary_binary", bytes(range(256))),
        ("png_header", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\xf3\xffa"),
        ("jpeg_header", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C"),
        ("large_payload", b"X" * (128 * 1024)),  # 128 KiB
    ],
)
def test_12_exact_byte_integrity_across_fixtures(fixture_name, payload):
    """Verify exact byte-for-byte SHA-256 integrity across diverse binary fixtures in Pipeline A and B."""
    sha = hashlib.sha256(payload).hexdigest()

    # Pipeline A: Case artifact
    case = store.create_case(f"Case 12 {fixture_name}")
    art_id = f"art-{fixture_name}"
    rec = ArtifactRecord(
        artifact_id=art_id,
        case_id=case.case_id,
        recovered_filename=f"{fixture_name}.bin",
        format="bin",
        status="FULLY_RECOVERED",
        confidence_score=95.0,
        verified_bytes=len(payload),
        is_downloadable=True,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes(art_id, payload)

    retrieved_a = store.get_artifact_bytes(art_id)
    assert retrieved_a == payload
    assert hashlib.sha256(retrieved_a).hexdigest() == sha

    resp_a = client.get(f"/api/artifacts/{art_id}/download")
    assert resp_a.status_code == 200
    assert resp_a.content == payload
    assert hashlib.sha256(resp_a.content).hexdigest() == sha

    # Pipeline B: Standalone file recovery
    file_id = f"file-{fixture_name}"
    meta_b = {
        "file_id": file_id,
        "original_filename": f"{fixture_name}.bin",
        "recovered_filename": f"recovered_{fixture_name}.bin",
        "format": "bin",
        "status": "FULLY_RECOVERED",
        "confidence_score": 95.0,
        "verified_bytes": len(payload),
        "reconstructed_bytes": 0,
        "missing_bytes": 0,
        "reconstruction_method": "NONE",
        "validation_status": "PASSED",
        "is_downloadable": True,
        "download_url": f"/api/recover-file/{file_id}/download",
        "score_breakdown": {},
        "validation_details": {},
    }
    store.store_recovered_file(file_id, meta_b, payload)

    retrieved_b = store.get_recovered_file_bytes(file_id)
    assert retrieved_b == payload
    assert hashlib.sha256(retrieved_b).hexdigest() == sha

    resp_b = client.get(f"/api/recover-file/{file_id}/download")
    assert resp_b.status_code == 200
    assert resp_b.content == payload
    assert hashlib.sha256(resp_b.content).hexdigest() == sha


# ── Scenario 13: Transactional Partial Failure Behavior ───────────────────────


def test_13_transactional_partial_failure_behavior(tmp_path):
    """Verify failure during compound storage rolls back atomically without partial residue."""
    db_file = str(tmp_path / "rollback_test.db")
    sql_store = SqliteStore(db_file)
    case = sql_store.create_case("Rollback Case")

    # Attempt a compound transaction that fails midway
    try:
        with sql_store._engine.transaction() as cur:
            rec = ArtifactRecord(
                artifact_id="art-rollback-13",
                case_id=case.case_id,
                format="txt",
                status="FULLY_RECOVERED",
                confidence_score=90.0,
                verified_bytes=50,
                is_downloadable=True,
            )
            sql_store.save_artifact_record(rec, cursor=cur)
            sql_store.store_artifact_bytes("art-rollback-13", b"PARTIAL_BLOB", cursor=cur)
            # Simulate unexpected failure before commit
            raise RuntimeError("Midway transaction failure")
    except RuntimeError:
        pass

    # Verify both record and blob were rolled back
    assert sql_store.get_artifact_record("art-rollback-13") is None
    assert sql_store.get_artifact_bytes("art-rollback-13") is None

    sql_store.close()


# ── Scenario 14: SqliteStore and InMemoryStore Parity Matrix ──────────────────


def test_14_sqlite_and_in_memory_parity_matrix(tmp_path):
    """Verify strict behavioral parity between SqliteStore and InMemoryStore across all operations."""
    db_file = str(tmp_path / "parity_test.db")
    sql_store = SqliteStore(db_file)
    mem_store = InMemoryStore()

    for st in (sql_store, mem_store):
        c = st.create_case("Parity Case")

        # 1. Non-existent artifact returns None
        assert st.get_artifact("non-existent") is None
        assert st.get_artifact_record("non-existent") is None
        assert st.get_artifact_bytes("non-existent") is None
        assert st.delete_artifact("non-existent") is False

        # 2. Store and retrieve artifact record and bytes
        rec = ArtifactRecord(
            artifact_id="art-parity-01",
            case_id=c.case_id,
            format="txt",
            status="FULLY_RECOVERED",
            confidence_score=90.0,
            verified_bytes=30,
            is_downloadable=True,
        )
        st.save_artifact_record(rec)
        st.store_artifact_bytes("art-parity-01", b"PARITY_TEST_PAYLOAD")

        ret_rec = st.get_artifact_record("art-parity-01")
        assert ret_rec is not None
        assert ret_rec.artifact_id == "art-parity-01"
        assert st.get_artifact_bytes("art-parity-01") == b"PARITY_TEST_PAYLOAD"

        # 3. Store and retrieve evidence
        st.add_evidence(c.case_id, "ev.raw", b"PARITY_EVIDENCE_RAW")
        assert st.get_evidence_bytes(c.case_id) == b"PARITY_EVIDENCE_RAW"

        # 4. Delete artifact leaves evidence intact
        assert st.delete_artifact("art-parity-01") is True
        assert st.get_artifact_bytes("art-parity-01") is None
        assert st.get_evidence_bytes(c.case_id) == b"PARITY_EVIDENCE_RAW"

    sql_store.close()
