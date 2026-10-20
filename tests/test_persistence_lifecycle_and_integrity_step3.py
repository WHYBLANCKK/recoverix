"""
tests/test_persistence_lifecycle_and_integrity_step3.py — Comprehensive tests
for Step 3: Persistence, Recovery Run Tracking, and State Integrity Audit.

Validates the 10 mandatory persistence and lifecycle invariants:
  1. RecoveryRun survives a true process restart (connection close & re-open).
  2. ArtifactRecord and raw payload blob survive restart.
  3. Forensic byte accounting (V, R, M) and provenance round-trip serialization.
  4. Case / RecoveryRun / Artifact authoritative relationships survive restart.
  5. Idempotent duplicate requests and terminal state protection against stale retries.
  6. Atomic rollback on partial failure prevents orphan records or incomplete state.
  7. Malformed JSON column corruption isolation without unhandled exceptions.
  8. Standalone file 24h TTL purge cleans up artifacts, linkages, and blobs while preserving case evidence.
  9. Repeated idempotent schema initialization on an existing populated database.
  10. Multi-threaded concurrent writes with WAL mode and busy-timeout protection.
"""

from __future__ import annotations

import os
import tempfile
import threading
from datetime import datetime, timezone, timedelta
import pytest

from backend.app.models.artifact import ArtifactRecord
from backend.app.models.recovery_run import (
    DamageRegion,
    Fragment,
    PipelineEvent,
    ReconstructionStep,
    RecoveryRun,
)
from backend.app.storage.sqlite_engine import SqliteEngine
from backend.app.storage.sqlite_store import SqliteStore


@pytest.fixture
def temp_db_path():
    """Create a temporary database file on disk and clean up on teardown."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="recoverix_test_")
    os.close(fd)
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass
    # Clean WAL and SHM files if present
    for ext in ("-wal", "-shm"):
        f = path + ext
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass


# ── 1. True Process Restart for RecoveryRun ───────────────────────────────────


def test_01_recovery_run_survives_real_process_restart(temp_db_path: str):
    """A RecoveryRun written to SQLite must survive a full engine close and re-open."""
    engine1 = SqliteEngine(db_path=temp_db_path)
    store1 = SqliteStore(engine1)

    now = datetime.now(timezone.utc)
    run_id = "run-restart-001"
    run = RecoveryRun(
        run_id=run_id,
        filename="corrupted_report.pdf",
        format="pdf",
        status="PARTIALLY_RECOVERED",
        detection_mode="known_file",
        case_name="Operation North Star",
        investigator="Agent Fox",
        notes="Damaged PDF recovered with reconstructed xref table",
        started_at=now,
        completed_at=now + timedelta(seconds=2),
        total_input_bytes=1000,
        total_verified_bytes=950,
        total_reconstructed_bytes=70,
        total_missing_bytes=50,
        fragments=[
            Fragment(
                fragment_id="frag_01",
                offset=0,
                length=950,
                end_offset=950,
                status="VERIFIED",
                source="magic_bytes",
                format="pdf",
                verified_bytes=950,
                reconstructed_bytes=0,
                missing_bytes=0,
                validation_status="PASSED",
            )
        ],
        damage_regions=[
            DamageRegion(
                region_id="dmg_01",
                start_offset=950,
                end_offset=1000,
                length=50,
                type="MISSING",
                status="RECONSTRUCTED",
            )
        ],
        reconstruction_steps=[
            ReconstructionStep(
                step_id="step_01",
                method="XREF_RECONSTRUCTION",
                result="SUCCESS",
                verified_bytes=950,
                reconstructed_bytes=70,
                missing_bytes=50,
                validation_status="PASSED",
                confidence=88.5,
            )
        ],
        events=[
            PipelineEvent(
                event_id="evt_01",
                run_id=run_id,
                sequence=1,
                event_type="EVIDENCE_SCANNED",
                timestamp=now,
                message="PDF header detected at offset 0",
            )
        ],
        validation={"valid": True, "xref_rebuilt": True},
        confidence={"total": 88.5, "header_validity": 100},
        provenance={"sha256_input": "abc123input", "sha256_output": "def456output"},
        output={"recovered_bytes": b"%PDF-1.4...".hex()},
    )
    store1.add_recovery_run(run)

    # Completely close first store and release all connection locks
    store1.close()

    # Re-open with a brand new engine pointing to the exact same file
    engine2 = SqliteEngine(db_path=temp_db_path)
    store2 = SqliteStore(engine2)

    retrieved = store2.get_recovery_run(run_id)
    assert retrieved is not None
    assert retrieved.run_id == run_id
    assert retrieved.filename == "corrupted_report.pdf"
    assert retrieved.status == "PARTIALLY_RECOVERED"
    assert retrieved.case_name == "Operation North Star"
    assert retrieved.investigator == "Agent Fox"
    assert retrieved.notes == "Damaged PDF recovered with reconstructed xref table"
    assert retrieved.total_input_bytes == 1000
    assert retrieved.total_verified_bytes == 950
    assert retrieved.total_reconstructed_bytes == 70
    assert retrieved.total_missing_bytes == 50
    assert len(retrieved.fragments) == 1
    assert retrieved.fragments[0].fragment_id == "frag_01"
    assert len(retrieved.damage_regions) == 1
    assert retrieved.damage_regions[0].region_id == "dmg_01"
    assert len(retrieved.reconstruction_steps) == 1
    assert retrieved.reconstruction_steps[0].method == "XREF_RECONSTRUCTION"
    assert len(retrieved.events) == 1
    assert retrieved.events[0].event_type == "EVIDENCE_SCANNED"
    assert retrieved.validation["xref_rebuilt"] is True
    assert retrieved.provenance["sha256_input"] == "abc123input"

    store2.close()


# ── 2. True Process Restart for Artifact and Raw Blob Payload ─────────────────


def test_02_artifact_and_payload_blob_survive_real_process_restart(temp_db_path: str):
    """An ArtifactRecord and raw byte blob must survive a full process restart."""
    engine1 = SqliteEngine(db_path=temp_db_path)
    store1 = SqliteStore(engine1)

    art_id = "art-restart-002"
    payload = b"Exact byte payload of recovered forensic artifact 2026."
    record = ArtifactRecord(
        artifact_id=art_id,
        case_id=None,
        original_filename="evidence.bin",
        recovered_filename="recovered_evidence.bin",
        format="bin",
        status="FULLY_RECOVERED",
        confidence_score=99.0,
        verified_bytes=len(payload),
        reconstructed_bytes=0,
        missing_bytes=0,
        total_input_bytes=len(payload),
        reconstruction_method="NONE",
        validation_status="PASSED",
        is_downloadable=True,
        download_url=f"/api/recover-file/{art_id}/download",
        content_preview="Exact byte payload...",
    )
    store1.save_artifact_record(record)
    store1.store_artifact_bytes(art_id, payload)
    store1.close()

    # Re-open with fresh engine
    engine2 = SqliteEngine(db_path=temp_db_path)
    store2 = SqliteStore(engine2)

    retrieved_rec = store2.get_artifact_record(art_id)
    assert retrieved_rec is not None
    assert retrieved_rec.artifact_id == art_id
    assert retrieved_rec.status == "FULLY_RECOVERED"
    assert retrieved_rec.is_downloadable is True
    assert retrieved_rec.verified_bytes == len(payload)
    assert retrieved_rec.reconstructed_bytes == 0
    assert retrieved_rec.missing_bytes == 0

    retrieved_bytes = store2.get_artifact_bytes(art_id)
    assert retrieved_bytes == payload

    store2.close()


# ── 3. Forensic Byte Accounting Roundtrip Serialization ───────────────────────


def test_03_vrm_byte_accounting_and_provenance_roundtrip(temp_db_path: str):
    """Verify that V + M == total_input_bytes, V + R == output_bytes, and
    reconstructed syntax is never added to input evidence size during roundtrip.
    """
    engine = SqliteEngine(db_path=temp_db_path)
    store = SqliteStore(engine)

    art_id = "art-vrm-roundtrip"
    input_size = 120
    v_bytes = 100
    r_bytes = 15  # 15 bytes of closing braces synthesized
    m_bytes = 20  # 20 bytes severed/unobserved
    assert v_bytes + m_bytes == input_size

    record = ArtifactRecord(
        artifact_id=art_id,
        format="json",
        status="PARTIALLY_RECOVERED",
        confidence_score=75.0,
        verified_bytes=v_bytes,
        reconstructed_bytes=r_bytes,
        missing_bytes=m_bytes,
        total_input_bytes=input_size,
        reconstruction_method="JSON_STRUCTURAL_CLOSURE",
        validation_status="PASSED",
        is_downloadable=True,
    )
    store.save_artifact_record(record)

    # Retrieve and check internal model
    loaded_record = store.get_artifact_record(art_id)
    assert loaded_record is not None
    assert loaded_record.verified_bytes == v_bytes
    assert loaded_record.reconstructed_bytes == r_bytes
    assert loaded_record.missing_bytes == m_bytes
    assert loaded_record.total_input_bytes == input_size
    assert loaded_record.verified_bytes + loaded_record.missing_bytes == loaded_record.total_input_bytes

    # Convert to API response
    api_resp = loaded_record.to_artifact_response()
    assert api_resp.provenance.verified_bytes == v_bytes
    assert api_resp.provenance.reconstructed_bytes == r_bytes
    assert api_resp.provenance.missing_bytes == m_bytes
    assert api_resp.metadata["total_input_bytes"] == input_size
    assert api_resp.size_bytes == v_bytes + r_bytes  # Output bytes

    # Adversarial check: Deserializing from ArtifactResponse without metadata["total_input_bytes"]
    # must calculate total_input_bytes = V + M (120), NEVER V + R + M (135)
    api_resp_no_meta = api_resp.model_copy(deep=True)
    api_resp_no_meta.metadata.pop("total_input_bytes", None)
    roundtrip_from_resp = ArtifactRecord.from_artifact_response(api_resp_no_meta)
    assert roundtrip_from_resp.total_input_bytes == input_size, (
        f"Expected {input_size} (V={v_bytes} + M={m_bytes}), got {roundtrip_from_resp.total_input_bytes}. "
        "Reconstructed bytes must never be counted as observed input!"
    )

    store.close()


# ── 4. Case / RecoveryRun / Artifact Relationship Durability ─────────────────


def test_04_case_run_artifact_linkage_survives_restart(temp_db_path: str):
    """Case, RecoveryRun, Artifact, and artifact_runs linkages must survive restart."""
    engine1 = SqliteEngine(db_path=temp_db_path)
    store1 = SqliteStore(engine1)

    case = store1.create_case("Homicide Case 2026", "Digital evidence from seized disk")
    case_id = case.case_id
    run_id = "run-linkage-004"
    art_id = "art-linkage-004"
    now = datetime.now(timezone.utc)

    # 1. Store recovery run under case
    run = RecoveryRun(
        run_id=run_id,
        case_id=case_id,
        artifact_id=art_id,
        filename="chat_log.json",
        format="json",
        status="FULLY_RECOVERED",
        started_at=now,
        completed_at=now,
        total_input_bytes=50,
        total_verified_bytes=50,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
    )
    store1.add_recovery_run(run)

    # 2. Store artifact under case and run
    art = ArtifactRecord(
        artifact_id=art_id,
        case_id=case_id,
        run_id=run_id,
        format="json",
        status="FULLY_RECOVERED",
        confidence_score=100.0,
        verified_bytes=50,
        reconstructed_bytes=0,
        missing_bytes=0,
        total_input_bytes=50,
    )
    store1.save_artifact_record(art)
    store1.link_artifact_to_run(art_id, run_id)
    store1.close()

    # Reopen
    engine2 = SqliteEngine(db_path=temp_db_path)
    store2 = SqliteStore(engine2)

    # Check case lookup
    c = store2.get_case(case_id)
    assert c is not None
    assert c.name == "Homicide Case 2026"

    # Check case recovery runs
    runs = store2.get_case_recovery_runs(case_id)
    assert runs is not None and len(runs) == 1
    assert runs[0].run_id == run_id

    # Check case artifacts
    arts = store2.get_case_artifacts(case_id)
    assert arts is not None and len(arts) == 1
    assert arts[0].artifact_id == art_id

    # Check bidirectional authoritative linkage
    linked_run = store2.get_recovery_run_by_artifact(art_id)
    assert linked_run is not None
    assert linked_run.run_id == run_id

    rec = store2.get_artifact_record(art_id)
    assert rec is not None
    assert rec.run_id == run_id

    store2.close()


# ── 5. Idempotent Duplicate Requests and Terminal State Protection ────────────


def test_05_idempotent_duplicate_recovery_runs_and_terminal_protection(temp_db_path: str):
    """Duplicate submissions of the same run_id must update cleanly without duplication,
    and a terminal status (e.g. FULLY_RECOVERED) must NOT be regressed by a stale RUNNING payload.
    """
    engine = SqliteEngine(db_path=temp_db_path)
    store = SqliteStore(engine)

    run_id = "run-idemp-005"
    now = datetime.now(timezone.utc)

    # 1. First submission: terminal status
    run1 = RecoveryRun(
        run_id=run_id,
        filename="data.csv",
        format="csv",
        status="FULLY_RECOVERED",
        started_at=now,
        completed_at=now,
        total_input_bytes=200,
        total_verified_bytes=200,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
    )
    store.add_recovery_run(run1)

    # Verify 1 record
    all_runs = store.list_recovery_runs()
    assert len(all_runs) == 1
    assert all_runs[0].status == "FULLY_RECOVERED"

    # 2. Resubmission with stale RUNNING status (simulating late arrival of in-flight message)
    run_stale = RecoveryRun(
        run_id=run_id,
        filename="data.csv",
        format="csv",
        status="RUNNING",  # Stale!
        started_at=now,
        completed_at=None,
        total_input_bytes=200,
        total_verified_bytes=0,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
    )
    store.add_recovery_run(run_stale)

    # Must still be only 1 record, and status must remain FULLY_RECOVERED
    all_runs2 = store.list_recovery_runs()
    assert len(all_runs2) == 1
    assert all_runs2[0].status == "FULLY_RECOVERED"

    store.close()


# ── 6. Atomic Transaction Rollback on Partial Failure ─────────────────────────


def test_06_atomic_transaction_rollback_prevents_partial_commit_and_orphans(temp_db_path: str):
    """A multi-record write that raises an exception midway must roll back completely."""
    engine = SqliteEngine(db_path=temp_db_path)
    store = SqliteStore(engine)

    art_id = "art-rollback-006"
    record = ArtifactRecord(
        artifact_id=art_id,
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=90.0,
        verified_bytes=10,
        reconstructed_bytes=0,
        missing_bytes=0,
        total_input_bytes=10,
    )

    with pytest.raises(RuntimeError, match="Simulated crash during transaction"):
        with engine.transaction() as cursor:
            # Step A: write artifact
            store._save_artifact_record_on_cursor(cursor, record)
            # Step B: write blob
            store._store_artifact_bytes_on_cursor(cursor, art_id, b"test content")
            # Step C: simulate crash before commit
            raise RuntimeError("Simulated crash during transaction")

    # Verify neither artifact nor blob was committed
    assert store.get_artifact_record(art_id) is None
    assert store.get_artifact_bytes(art_id) is None

    store.close()


# ── 7. Malformed JSON Column Corruption Isolation ─────────────────────────────


def test_07_malformed_json_column_isolation(temp_db_path: str):
    """Direct storage of corrupt JSON in SQLite columns must be safely isolated
    without crashing the deserializer or hiding corruption.
    """
    engine = SqliteEngine(db_path=temp_db_path)
    store = SqliteStore(engine)

    art_id = "art-corrupt-json-007"
    # Insert row directly with corrupted JSON in score_breakdown_json
    with engine.transaction() as cur:
        cur.execute(
            """
            INSERT INTO artifacts (
                artifact_id, format, status, confidence_score, verified_bytes,
                reconstructed_bytes, missing_bytes, total_input_bytes,
                score_breakdown_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (art_id, "json", "PARTIALLY_RECOVERED", 50.0, 10, 0, 5, 15, "NOT VALID JSON {{{{"),
        )

    # Retrieval must not raise JSONDecodeError; it must track corrupted_fields
    rec = store.get_artifact_record(art_id)
    assert rec is not None
    assert rec.artifact_id == art_id
    assert rec.corrupted_fields is not None
    assert "score_breakdown_json" in rec.corrupted_fields

    store.close()


# ── 8. 24h TTL Purge Cleans Standalone Files and Protects Case Evidence ───────


def test_08_purge_expired_files_preserves_case_evidence_and_download_guards(temp_db_path: str):
    """purge_expired_recovered_files must delete expired standalone files and their blobs,
    while strictly preserving case-associated evidence files.
    """
    engine = SqliteEngine(db_path=temp_db_path)
    store = SqliteStore(engine)

    old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()

    # 1. Standalone expired artifact
    standalone_id = "rec_file_standalone_expired"
    standalone_meta = {
        "file_id": standalone_id,
        "format": "txt",
        "status": "FULLY_RECOVERED",
        "confidence_score": 100.0,
        "verified_bytes": 12,
        "reconstructed_bytes": 0,
        "missing_bytes": 0,
        "total_input_bytes": 12,
        "validation_status": "PASSED",
        "is_downloadable": True,
        "created_at": old_time,
    }
    store.store_recovered_file(standalone_id, standalone_meta, b"expired text")

    # 2. Case-associated artifact (also old, but part of a legal case)
    case = store.create_case("Court Case 101")
    store.add_evidence(case.case_id, "evidence.raw", b"important case evidence bytes")
    case_art_id = "art_case_old_008"
    case_art = ArtifactRecord(
        artifact_id=case_art_id,
        case_id=case.case_id,
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=100.0,
        verified_bytes=20,
        total_input_bytes=20,
        metadata={"created_at": old_time},
    )
    store.save_artifact_record(case_art)
    # Explicitly store case artifact blob with created_at=old_time to verify TTL purge never touches case blobs
    store.store_artifact_bytes(case_art_id, b"case artifact bytes", created_at=old_time)

    # Run 24h purge
    purged_count = store.purge_expired_recovered_files(ttl_hours=24)
    assert purged_count == 1

    # Standalone artifact must be gone
    assert store.get_recovered_file_metadata(standalone_id) is None
    assert store.get_recovered_file_bytes(standalone_id) is None

    # Case artifact and evidence MUST be completely preserved
    assert store.get_artifact_record(case_art_id) is not None
    assert store.get_artifact_bytes(case_art_id) == b"case artifact bytes"
    assert store.get_evidence_bytes(case.case_id) == b"important case evidence bytes"

    store.close()


# ── 9. Repeated Schema Initialization on Existing Populated Database ─────────


def test_09_repeated_schema_initialization_on_existing_database(temp_db_path: str):
    """Calling SqliteEngine.initialize() repeatedly on a populated database must be idempotent
    and must never drop tables, wipe data, or fail with duplicate column errors.
    """
    engine = SqliteEngine(db_path=temp_db_path)
    store = SqliteStore(engine)

    # Populate data
    case = store.create_case("Persistence Safety Check")
    store.add_evidence(case.case_id, "data.bin", b"0123456789" * 10)

    # Re-initialize 10 times consecutively
    for _ in range(10):
        engine.initialize()

    # Verify data remains intact
    retrieved_case = store.get_case(case.case_id)
    assert retrieved_case is not None
    assert retrieved_case.name == "Persistence Safety Check"
    ev_bytes = store.get_evidence_bytes(case.case_id)
    assert ev_bytes == b"0123456789" * 10

    store.close()


# ── 10. Multi-Threaded Concurrent Writes and Busy-Timeout Safety ─────────────


def test_10_concurrent_writes_and_busy_timeout_thread_safety(temp_db_path: str):
    """Concurrent worker threads writing RecoveryRuns and ArtifactRecords to SQLite
    must complete without database deadlocks or lost updates under WAL mode.
    """
    engine = SqliteEngine(db_path=temp_db_path)
    store = SqliteStore(engine)

    num_threads = 8
    num_writes_per_thread = 5
    barrier = threading.Barrier(num_threads)
    errors: list[Exception] = []

    def worker(worker_id: int):
        barrier.wait()
        for i in range(num_writes_per_thread):
            run_id = f"run-thread-{worker_id}-{i}"
            art_id = f"art-thread-{worker_id}-{i}"
            now = datetime.now(timezone.utc)
            try:
                run = RecoveryRun(
                    run_id=run_id,
                    filename=f"worker_{worker_id}.json",
                    format="json",
                    status="FULLY_RECOVERED",
                    started_at=now,
                    completed_at=now,
                    total_input_bytes=100,
                    total_verified_bytes=100,
                    total_reconstructed_bytes=0,
                    total_missing_bytes=0,
                )
                store.add_recovery_run(run)

                rec = ArtifactRecord(
                    artifact_id=art_id,
                    run_id=run_id,
                    format="json",
                    status="FULLY_RECOVERED",
                    confidence_score=100.0,
                    verified_bytes=100,
                    reconstructed_bytes=0,
                    missing_bytes=0,
                    total_input_bytes=100,
                )
                store.save_artifact_record(rec)
            except Exception as exc:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Concurrent worker threads encountered errors: {errors}"

    # Verify exact number of committed records
    all_runs = store.list_recovery_runs()
    expected_total = num_threads * num_writes_per_thread
    assert len(all_runs) == expected_total

    store.close()
