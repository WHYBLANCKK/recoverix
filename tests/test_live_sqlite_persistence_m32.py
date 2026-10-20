"""
test_live_sqlite_persistence_m32.py — Milestone 3.2.3 Live SQLite Persistence Test Suite.

Proves real file-backed SQLite persistence, durability across engine close/reopen,
process restart simulation, authoritative linkage, and single-write invariants.
Uses pytest `tmp_path` to guarantee 100% isolation from the production database.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.artifact import ArtifactRecord, ArtifactResponse, ConfidenceBreakdownSchema, ArtifactProvenanceSchema
from backend.app.models.case import CaseResponse, EvidenceMetadata
from backend.app.models.recovery_run import (
    DamageRegion,
    Fragment,
    FragmentRelationship,
    PipelineEvent,
    ReconstructionStep,
    RecoveryRun,
)
from backend.app.recovery.signatures import SYNTHETIC_START_MARKER, SYNTHETIC_END_MARKER
from backend.app.recovery.tracer import execute_traced_recovery
import backend.app.store as app_store
from backend.app.storage.sqlite_engine import SqliteEngine
from backend.app.storage.sqlite_store import SqliteStore


# ── Test A: Case Persistence Across Restart ───────────────────────────────────

def test_a_case_persistence_across_restart(tmp_path):
    """Case identity, attributes, and dynamic counts survive complete store restart."""
    db_file = str(tmp_path / "case_test.db")

    # Session 1: Create case and close
    store1 = SqliteStore(db_file)
    case = store1.create_case("Homicide 2026-001", "Forensic analysis of suspect SSD")
    case_id = case.case_id
    store1.close()

    # Session 2: Fresh instance against same DB file
    store2 = SqliteStore(db_file)
    retrieved = store2.get_case(case_id)

    assert retrieved is not None
    assert retrieved.case_id == case_id
    assert retrieved.name == "Homicide 2026-001"
    assert retrieved.description == "Forensic analysis of suspect SSD"
    assert retrieved.artifact_count == 0
    assert retrieved.evidence is None

    # Listing cases survives restart
    all_cases = store2.list_cases()
    assert len(all_cases) == 1
    assert all_cases[0].case_id == case_id

    store2.close()


# ── Test B: Evidence Persistence Across Restart ───────────────────────────────

def test_b_evidence_persistence_across_restart(tmp_path):
    """Evidence metadata, binary blobs, and chunks survive complete store restart."""
    db_file = str(tmp_path / "evidence_test.db")
    payload = b"FORENSIC_RAW_EVIDENCE_PAYLOAD_ABC1234567890_XYZ"

    # Session 1: Create case and ingest evidence
    store1 = SqliteStore(db_file)
    case = store1.create_case("Evidence Persistence Case")
    meta = store1.add_evidence(case.case_id, "disk.raw", payload)
    store1.close()

    # Session 2: Fresh store instance
    store2 = SqliteStore(db_file)
    rec_case = store2.get_case(case.case_id)

    assert rec_case is not None
    assert rec_case.evidence is not None
    assert rec_case.evidence.filename == "disk.raw"
    assert rec_case.evidence.file_size == len(payload)
    assert rec_case.evidence.sha256 == meta.sha256

    # Verify exact binary payload from blob store
    retrieved_bytes = store2.get_evidence_bytes(case.case_id)
    assert retrieved_bytes == payload

    # Verify sequential chunks
    chunks = store2.get_evidence_chunks(case.case_id)
    assert chunks is not None
    assert len(chunks) >= 1
    assert chunks[0].index == 0
    assert chunks[0].data == payload

    store2.close()


# ── Test C: Artifact & Blob Persistence Across Restart ────────────────────────

def test_c_artifact_persistence_across_restart(tmp_path):
    """Case artifacts and standalone files survive complete store restart."""
    db_file = str(tmp_path / "artifact_test.db")
    art_payload = b"%PDF-1.4 Recovered Document Stream Payload\n%%EOF"
    standalone_payload = b"FORMAT=txt\nHeader: Standalone\nBody: Restored Content\n"

    # Session 1: Store case artifact and standalone file
    store1 = SqliteStore(db_file)
    case = store1.create_case("Artifact Case")

    art_response = ArtifactResponse(
        artifact_id="art_test_restart",
        case_id=case.case_id,
        format="pdf",
        size_bytes=len(art_payload),
        confidence_score=94,
        score_breakdown=ConfidenceBreakdownSchema(
            header_validity=100, footer_validity=100, structural_validation=90,
            size_plausibility=90, reconstruction_integrity=90, total=94,
        ),
        status="FULLY_RECOVERED",
        provenance=ArtifactProvenanceSchema(
            verified_bytes=len(art_payload), reconstructed_bytes=0, missing_bytes=0,
            reconstruction_method="NONE", validation_status="PASSED",
        ),
        category="DOCUMENTS",
        priority="HIGH",
        content_preview="PDF Header Stream",
        metadata={"scanner": "pdf_v2"},
    )
    store1.add_artifact(art_response)
    store1.store_artifact_bytes("art_test_restart", art_payload)

    # Standalone recovered file (Pipeline B)
    store1.store_recovered_file(
        "rec_standalone_001",
        {
            "file_id": "rec_standalone_001",
            "format": "txt",
            "status": "FULLY_RECOVERED",
            "confidence_score": 91.0,
            "original_filename": "notes.txt",
        },
        standalone_payload,
    )
    store1.close()

    # Session 2: Fresh store instance
    store2 = SqliteStore(db_file)

    # Verify Case Artifact
    retrieved_art = store2.get_artifact("art_test_restart")
    assert retrieved_art is not None
    assert retrieved_art.artifact_id == "art_test_restart"
    assert retrieved_art.case_id == case.case_id
    assert retrieved_art.format == "pdf"
    assert retrieved_art.confidence_score == 94
    assert retrieved_art.category == "DOCUMENTS"
    assert retrieved_art.priority == "HIGH"
    assert store2.get_artifact_bytes("art_test_restart") == art_payload

    # Verify dynamic artifact count updated on case
    updated_case = store2.get_case(case.case_id)
    assert updated_case.artifact_count == 1

    # Verify Standalone Recovered File
    standalone_meta = store2.get_recovered_file_metadata("rec_standalone_001")
    assert standalone_meta is not None
    assert standalone_meta["file_id"] == "rec_standalone_001"
    assert standalone_meta["format"] == "txt"
    assert standalone_meta["status"] == "FULLY_RECOVERED"
    assert store2.get_recovered_file_bytes("rec_standalone_001") == standalone_payload

    store2.close()


# ── Test D: RecoveryRun Complex Model Persistence Across Restart ───────────────

def test_d_recovery_run_persistence_across_restart(tmp_path):
    """Deeply nested RecoveryRun models (fragments, relationships, steps, events) persist."""
    db_file = str(tmp_path / "recovery_run_test.db")
    now = datetime.now(timezone.utc)
    run_id = "run_deep_persistence"

    # Session 1: Create RecoveryRun with nested structures
    store1 = SqliteStore(db_file)
    run = RecoveryRun(
        run_id=run_id,
        artifact_id="art_linked_001",
        candidate_id="cand_001",
        filename="suspicious.csv",
        format="csv",
        status="PARTIALLY_RECOVERED",
        detection_mode="known_file",
        started_at=now,
        completed_at=now,
        total_input_bytes=1000,
        total_verified_bytes=800,
        total_reconstructed_bytes=100,
        total_missing_bytes=100,
        fragments=[
            Fragment(
                fragment_id="frag_1",
                offset=0,
                length=500,
                end_offset=500,
                status="VERIFIED",
                source="synthetic_boundary",
                format="csv",
                verified_bytes=500,
                reconstructed_bytes=0,
                missing_bytes=0,
                validation_status="PASSED",
                relationships=[
                    FragmentRelationship(
                        source_fragment_id="frag_1",
                        target_fragment_id="frag_2",
                        relationship_type="PRECEDES",
                        details={"gap": 100},
                    )
                ],
            )
        ],
        damage_regions=[
            DamageRegion(
                region_id="dmg_1",
                start_offset=500,
                end_offset=600,
                length=100,
                type="MISSING",
                status="RECONSTRUCTED",
                affected_fragment_ids=["frag_1"],
            )
        ],
        reconstruction_steps=[
            ReconstructionStep(
                step_id="step_1",
                method="BIFRAGMENT_GAP",
                input_fragment_ids=["frag_1"],
                gap_start=500,
                gap_end=600,
                gap_size=100,
                result="SUCCESS",
                verified_bytes=500,
                reconstructed_bytes=100,
                missing_bytes=0,
                validation_status="PASSED",
                confidence=88.5,
            )
        ],
        events=[
            PipelineEvent(
                event_id="evt_1",
                run_id=run_id,
                sequence=1,
                event_type="RECONSTRUCTION_COMPLETED",
                timestamp=now,
                message="Bifragment gap resolved successfully",
                relevant_fragment_ids=["frag_1"],
            )
        ],
        validation={"csv_dialect": "excel", "delimiter": ","},
        confidence={"total": 88.5},
        provenance={"analyzer": "csv_v2"},
        output={"recovered_bytes": "61,62,63\n"},
    )
    store1.add_recovery_run(run)
    store1.close()

    # Session 2: Fresh instance
    store2 = SqliteStore(db_file)
    retrieved = store2.get_recovery_run(run_id)

    assert retrieved is not None
    assert retrieved.run_id == run_id
    assert retrieved.filename == "suspicious.csv"
    assert retrieved.format == "csv"
    assert retrieved.status == "PARTIALLY_RECOVERED"
    assert len(retrieved.fragments) == 1
    assert len(retrieved.fragments[0].relationships) == 1
    assert retrieved.fragments[0].relationships[0].relationship_type == "PRECEDES"
    assert retrieved.fragments[0].relationships[0].details == {"gap": 100}
    assert len(retrieved.damage_regions) == 1
    assert len(retrieved.reconstruction_steps) == 1
    assert len(retrieved.events) == 1
    assert retrieved.events[0].message == "Bifragment gap resolved successfully"
    assert retrieved.validation == {"csv_dialect": "excel", "delimiter": ","}
    assert retrieved.output == {"recovered_bytes": "61,62,63\n"}

    store2.close()


# ── Test E: Authoritative Linkage Across Restart ──────────────────────────────

def test_e_authoritative_linkage_across_restart(tmp_path):
    """Authoritative artifact_runs linkage survives store restart."""
    db_file = str(tmp_path / "linkage_test.db")
    now = datetime.now(timezone.utc)
    run_id = "run_authoritative_001"
    art_id = "art_authoritative_001"

    # Session 1: Create run, record, and link authoritatively
    store1 = SqliteStore(db_file)
    run = RecoveryRun(
        run_id=run_id, filename="data.txt", format="txt", status="FULLY_RECOVERED",
        started_at=now, total_input_bytes=100, total_verified_bytes=100,
        total_reconstructed_bytes=0, total_missing_bytes=0,
    )
    store1.add_recovery_run(run)
    store1.link_artifact_to_run(art_id, run_id)
    store1.close()

    # Session 2: Fresh store instance
    store2 = SqliteStore(db_file)

    # Authoritative resolution
    linked_run = store2.get_recovery_run_by_artifact(art_id)
    assert linked_run is not None
    assert linked_run.run_id == run_id

    # Verify table directly
    with store2._engine.transaction() as cursor:
        cursor.execute("SELECT run_id FROM artifact_runs WHERE artifact_id = ?;", (art_id,))
        row = cursor.fetchone()
        assert row is not None
        assert row["run_id"] == run_id

    store2.close()


# ── Test F: Full Application-Style Recovery Persistence ───────────────────────

def test_f_full_application_recovery_persistence(tmp_path):
    """Full recovery pipeline writes to file-backed SQLite, surviving complete app restart."""
    db_file = str(tmp_path / "app_recovery_durability.db")

    # 1. Wire file-backed store as application store
    app_store.store.reconfigure(db_file)

    client = TestClient(app)

    # 2. Pipeline B Recovery via API
    txt_content = b"FORMAT=txt\nHeader: Application Persistence Test\nBody: Restored Content 12345\n"
    payload = SYNTHETIC_START_MARKER + txt_content + SYNTHETIC_END_MARKER

    res = client.post(
        "/api/recover-file",
        files={"file": ("persist_test.txt", payload, "text/plain")},
    )
    assert res.status_code == 200
    file_data = res.json()
    file_id = file_data["file_id"]
    run_id = file_data["run_id"]

    # 3. Pipeline A Case Creation + Ingestion + Analysis
    case_res = client.post("/api/cases", json={"name": "Live Analysis Persistence Case"})
    assert case_res.status_code == 201
    case_id = case_res.json()["case_id"]

    ev_res = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("evidence.img", payload, "application/octet-stream")},
    )
    assert ev_res.status_code == 200

    analyze_res = client.post(f"/api/cases/{case_id}/analyze")
    assert analyze_res.status_code == 200
    analysis_data = analyze_res.json()
    assert analysis_data["status"] == "COMPLETED"
    assert analysis_data["artifact_count"] >= 1
    case_art_id = analysis_data["artifacts"][0]["artifact_id"]

    # Close first application store session
    app_store.store.close()

    # ── 4. Process Restart Simulation ──────────────────────────────────────
    # Reopen same DB file on the application store
    app_store.store.reconfigure(db_file)
    client_reopened = TestClient(app)
    client_reopened.cookies.update(client.cookies)

    # A. Verify Pipeline B recovered file survived restart
    get_file_res = client_reopened.get(f"/api/recover-file/{file_id}")
    assert get_file_res.status_code == 200
    assert get_file_res.json()["file_id"] == file_id
    assert get_file_res.json()["run_id"] == run_id

    # Download raw bytes
    dl_file_res = client_reopened.get(f"/api/recover-file/{file_id}/download")
    assert dl_file_res.status_code == 200
    assert len(dl_file_res.content) > 0

    # B. Verify Pipeline A case & artifacts survived restart
    get_case_res = client_reopened.get(f"/api/cases/{case_id}")
    assert get_case_res.status_code == 200
    assert get_case_res.json()["artifact_count"] >= 1

    list_arts_res = client_reopened.get(f"/api/cases/{case_id}/artifacts")
    assert list_arts_res.status_code == 200
    arts = list_arts_res.json()
    assert len(arts) >= 1
    assert any(a["artifact_id"] == case_art_id for a in arts)

    dl_art_res = client_reopened.get(f"/api/artifacts/{case_art_id}/download")
    assert dl_art_res.status_code == 200
    assert len(dl_art_res.content) > 0

    # C. Verify RecoveryRuns list endpoint survived restart
    runs_res = client_reopened.get("/api/recovery-runs")
    assert runs_res.status_code == 200
    runs = runs_res.json()
    assert len(runs) >= 2  # 1 from Pipeline B, 1+ from Pipeline A

    # Reset store to clean in-memory for subsequent tests
    app_store.store.reconfigure(":memory:")


# ── Test G: Single-Write Invariant on SQLite ──────────────────────────────────

def test_g_single_write_invariant(tmp_path):
    """Canonical recovery writes exactly one RecoveryRun to SQLite."""
    db_file = str(tmp_path / "single_write_test.db")
    app_store.store.reconfigure(db_file)

    payload = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Invariant Test\nBody: Single Write Verification\n" + SYNTHETIC_END_MARKER

    # Execute single traced recovery directly through canonical engine
    run = execute_traced_recovery(
        filename="invariant.txt",
        content=payload,
    )

    # 1. Store API reports exactly 1 run
    runs = app_store.store.list_recovery_runs()
    assert len(runs) == 1
    assert runs[0].run_id == run.run_id

    # 2. Database level inspection verifies exactly 1 row in recovery_runs
    with app_store.store._engine.transaction() as cursor:
        cursor.execute("SELECT COUNT(*) FROM recovery_runs;")
        row = cursor.fetchone()
        assert row[0] == 1

        cursor.execute("SELECT run_id FROM recovery_runs;")
        row = cursor.fetchone()
        assert row["run_id"] == run.run_id

    # Reset store to clean in-memory for subsequent tests
    app_store.store.reconfigure(":memory:")


# ── Test H: Multi-Session Restart Durability & PRAGMA FK Validation ───────────

def test_h_restart_simulation_comprehensive(tmp_path):
    """Multiple sequential restart cycles maintain absolute zero foreign key violations."""
    db_file = str(tmp_path / "multi_restart_durability.db")

    # Session 1: Create case and evidence
    s1 = SqliteStore(db_file)
    c1 = s1.create_case("Case Session 1")
    s1.add_evidence(c1.case_id, "ev1.raw", b"SESSION_1_BYTES")
    s1.close()

    # Session 2: Reopen, add artifacts
    s2 = SqliteStore(db_file)
    assert s2.get_case(c1.case_id) is not None
    s2.store_recovered_file("file_session_2", {
        "file_id": "file_session_2",
        "format": "bin",
        "status": "FULLY_RECOVERED",
        "confidence_score": 98.0,
    }, b"SESSION_2_RECOVERED")
    s2.close()

    # Session 3: Reopen, verify everything and run PRAGMA foreign_key_check
    s3 = SqliteStore(db_file)
    assert s3.get_case(c1.case_id) is not None
    assert s3.get_evidence_bytes(c1.case_id) == b"SESSION_1_BYTES"
    assert s3.get_recovered_file_bytes("file_session_2") == b"SESSION_2_RECOVERED"

    with s3._engine.transaction() as cursor:
        cursor.execute("PRAGMA foreign_key_check;")
        violations = cursor.fetchall()
        assert len(violations) == 0

    s3.close()
