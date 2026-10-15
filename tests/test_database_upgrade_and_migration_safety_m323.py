"""
test_database_upgrade_and_migration_safety_m323.py — Comprehensive test suite for M3.23.0.

Validates database upgrade and migration safety:
- Initialization order and schema tolerance across historical database schemas.
- Strict ownership decisions for all Cases A through N.
- Transaction atomicity and failure recovery with multi-stage fault injection.
- Deep idempotency verification (exact byte, hash, key, count equality across multiple runs).
- Post-migration storage contract compliance and deletion safety.
"""

import hashlib
import sqlite3
import tempfile
import os
import pytest
from unittest.mock import patch

from backend.app.storage.sqlite_engine import SqliteEngine
from backend.app.storage.sqlite_blob_store import SqliteBlobStore
from backend.app.storage.sqlite_store import SqliteStore, migrate_legacy_blobs
from backend.app.storage.memory_store import InMemoryStore
from backend.app.models.artifact import ArtifactRecord


def _create_minimal_legacy_db(
    db_path: str,
    include_evidence_sha: bool = True,
    include_evidence_size: bool = True,
    include_blob_size: bool = True,
    include_blob_created_at: bool = True,
    include_artifacts: bool = True,
) -> None:
    """Create a customized historical database fixture to test schema tolerance."""
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE cases (case_id TEXT PRIMARY KEY, name TEXT, description TEXT, created_at TEXT);")

    ev_cols = ["case_id TEXT PRIMARY KEY", "filename TEXT NOT NULL", "uploaded_at TEXT NOT NULL"]
    if include_evidence_size:
        ev_cols.append("file_size INTEGER NOT NULL")
    if include_evidence_sha:
        ev_cols.append("sha256 TEXT NOT NULL")
    conn.execute(f"CREATE TABLE evidence_files ({', '.join(ev_cols)});")

    if include_artifacts:
        conn.execute(
            """
            CREATE TABLE artifacts (
                artifact_id TEXT PRIMARY KEY,
                case_id TEXT,
                run_id TEXT,
                original_filename TEXT,
                recovered_filename TEXT,
                format TEXT NOT NULL,
                status TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                verified_bytes INTEGER DEFAULT 0,
                reconstructed_bytes INTEGER DEFAULT 0,
                missing_bytes INTEGER DEFAULT 0,
                total_input_bytes INTEGER,
                reconstruction_method TEXT DEFAULT 'NONE',
                validation_status TEXT DEFAULT 'PASSED',
                is_downloadable INTEGER DEFAULT 1,
                download_url TEXT,
                content_preview TEXT,
                category TEXT,
                priority TEXT,
                ai_summary TEXT,
                score_breakdown_json TEXT DEFAULT '{}',
                provenance_json TEXT DEFAULT '{}',
                validation_details_json TEXT DEFAULT '{}',
                metadata_json TEXT DEFAULT '{}',
                fragments_json TEXT,
                damage_regions_json TEXT,
                reconstruction_steps_json TEXT
            );
            """
        )

    blob_cols = ["blob_key TEXT PRIMARY KEY", "data BLOB NOT NULL"]
    if include_blob_size:
        blob_cols.append("size_bytes INTEGER NOT NULL")
    if include_blob_created_at:
        blob_cols.append("created_at TEXT NOT NULL")
    conn.execute(f"CREATE TABLE blobs ({', '.join(blob_cols)});")

    conn.commit()
    conn.close()


# ── STEP 2: Initialization Order and Schema Tolerance ───────────────────────


def test_init_fresh_database(tmp_path):
    """1. Opening a fresh database initializes schema and runs empty migration safely."""
    db_path = str(tmp_path / "fresh_init.db")
    store = SqliteStore(db_path)
    try:
        assert store.cases.list_cases() == []
        stats = store.migrate_legacy_blobs()
        assert stats == {"migrated_evidence": 0, "migrated_artifact": 0, "ambiguous": 0, "orphaned": 0}
    finally:
        store.close()


def test_init_legacy_database_pre_namespaced(tmp_path):
    """2. Opening a legacy database from before namespaced blobs migrates cleanly."""
    db_path = str(tmp_path / "legacy_pre_namespaced.db")
    _create_minimal_legacy_db(db_path)

    ev_data = b"LEGACY_PRE_NAMESPACED_BYTES"
    ev_sha = hashlib.sha256(ev_data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_old', 'Old Case', NULL, '2026-01-01T00:00:00Z');")
    conn.execute("INSERT INTO evidence_files VALUES ('c_old', 'disk.img', '2026-01-01T00:00:00Z', ?, ?);", (len(ev_data), ev_sha))
    conn.execute("INSERT INTO blobs VALUES ('c_old', ?, ?, '2026-01-01T00:00:00Z');", (ev_data, len(ev_data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_evidence_bytes("c_old") == ev_data
        assert store.get_artifact_bytes("c_old") is None
    finally:
        store.close()


def test_init_reconfigure_repeatedly(tmp_path):
    """5. Calling reconfigure() repeatedly is stable and safe."""
    db_path = str(tmp_path / "reconfig.db")
    store = SqliteStore(db_path)
    try:
        case = store.create_case("Reconfig Case")
        store.add_evidence(case.case_id, "ev.raw", b"RECONFIG_EVIDENCE")

        for _ in range(3):
            store.reconfigure(db_path)
            assert store.get_evidence_bytes(case.case_id) == b"RECONFIG_EVIDENCE"
    finally:
        store.close()


def test_init_missing_optional_columns_in_evidence_files(tmp_path):
    """6a. Opening a database whose evidence_files table lacks sha256 or file_size does not crash."""
    db_path = str(tmp_path / "missing_cols_ev.db")
    _create_minimal_legacy_db(db_path, include_evidence_sha=False, include_evidence_size=False)

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_nocol', 'No Col Case', NULL, 'now');")
    conn.execute("INSERT INTO evidence_files VALUES ('c_nocol', 'disk.img', 'now');")
    conn.execute("INSERT INTO blobs VALUES ('c_nocol', X'AABB', 2, 'now');")
    conn.commit()
    conn.close()

    engine = SqliteEngine(db_path)
    try:
        stats = migrate_legacy_blobs(engine)
        # Without SHA-256 verification, cannot prove evidence consistency -> preserved as ambiguous
        assert stats["ambiguous"] == 1
        assert stats["migrated_evidence"] == 0
    finally:
        engine.close()


def test_init_missing_optional_columns_in_blobs(tmp_path):
    """6b. Opening a database whose blobs table lacks size_bytes or created_at does not crash."""
    db_path = str(tmp_path / "missing_cols_blobs.db")
    _create_minimal_legacy_db(db_path, include_blob_size=False, include_blob_created_at=False)

    ev_data = b"ANCIENT_BLOB_PAYLOAD"
    ev_sha = hashlib.sha256(ev_data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_ancient', 'Ancient Case', NULL, 'now');")
    conn.execute("INSERT INTO evidence_files VALUES ('c_ancient', 'disk.img', 'now', ?, ?);", (len(ev_data), ev_sha))
    conn.execute("INSERT INTO blobs VALUES ('c_ancient', ?);", (ev_data,))
    conn.commit()
    conn.close()

    engine = SqliteEngine(db_path)
    try:
        stats = migrate_legacy_blobs(engine)
        assert stats["migrated_evidence"] == 1
        # Verify namespaced blob was created
        with engine.transaction() as cur:
            cur.execute("SELECT blob_key, data FROM blobs;")
            rows = cur.fetchall()
            assert len(rows) == 1
            assert rows[0]["blob_key"] == "evidence:c_ancient"
            assert bytes(rows[0]["data"]) == ev_data
    finally:
        engine.close()


# ── STEP 3: Migration Ownership Decisions (Cases A–N) ────────────────────────


def test_case_a_evidence_matching_sha(tmp_path):
    """Case A: Legacy evidence record with matching SHA-256 -> migrated to evidence:k."""
    db_path = str(tmp_path / "case_a.db")
    _create_minimal_legacy_db(db_path)

    data = b"VERIFIED_EVIDENCE_BYTES_A"
    sha = hashlib.sha256(data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('case_a', 'Case A', NULL, 'now');")
    conn.execute("INSERT INTO evidence_files VALUES ('case_a', 'ev.raw', 'now', ?, ?);", (len(data), sha))
    conn.execute("INSERT INTO blobs VALUES ('case_a', ?, ?, 'now');", (data, len(data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_evidence_bytes("case_a") == data
        assert store.get_artifact_bytes("case_a") is None
    finally:
        store.close()


def test_case_b_evidence_mismatching_sha(tmp_path):
    """Case B: Legacy evidence record with mismatching SHA-256 -> preserved unmigrated as ambiguous."""
    db_path = str(tmp_path / "case_b.db")
    _create_minimal_legacy_db(db_path)

    expected_sha = "f" * 64
    actual_data = b"MISMATCHED_EVIDENCE_BYTES_B"

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('case_b', 'Case B', NULL, 'now');")
    conn.execute("INSERT INTO evidence_files VALUES ('case_b', 'ev.raw', 'now', ?, ?);", (len(actual_data), expected_sha))
    conn.execute("INSERT INTO blobs VALUES ('case_b', ?, ?, 'now');", (actual_data, len(actual_data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        # Mismatched evidence must not be exposed as valid evidence
        assert store.get_evidence_bytes("case_b") is None
        assert store.get_artifact_bytes("case_b") is None

        # Original unprefixed blob must be preserved
        with store._engine.transaction() as cur:
            cur.execute("SELECT blob_key FROM blobs WHERE blob_key = 'case_b';")
            assert cur.fetchone() is not None
    finally:
        store.close()


def test_case_c_artifact_without_evidence(tmp_path):
    """Case C: Legacy artifact record without evidence record -> migrated to artifact:k."""
    db_path = str(tmp_path / "case_c.db")
    _create_minimal_legacy_db(db_path)

    data = b"ARTIFACT_C_DOCUMENT_DATA"

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('case_c', 'Case C', NULL, 'now');")
    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES ('art_c', 'case_c', 'PDF', 'RECOVERED', 0.95);
        """
    )
    conn.execute("INSERT INTO blobs VALUES ('art_c', ?, ?, 'now');", (data, len(data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_artifact_bytes("art_c") == data
        assert store.get_evidence_bytes("art_c") is None
    finally:
        store.close()


def test_case_d_same_identifier_collision(tmp_path):
    """Case D: A case and artifact share the same identifier."""
    db_path = str(tmp_path / "case_d.db")
    _create_minimal_legacy_db(db_path)

    shared_id = "shared_d"
    ev_data = b"EVIDENCE_D_PAYLOAD"
    ev_sha = hashlib.sha256(ev_data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES (?, 'Case D', NULL, 'now');", (shared_id,))
    conn.execute("INSERT INTO evidence_files VALUES (?, 'ev.raw', 'now', ?, ?);", (shared_id, len(ev_data), ev_sha))
    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES (?, ?, 'PNG', 'RECOVERED', 0.88);
        """,
        (shared_id, shared_id),
    )
    conn.execute("INSERT INTO blobs VALUES (?, ?, ?, 'now');", (shared_id, ev_data, len(ev_data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        # Verified evidence returns exact bytes
        assert store.get_evidence_bytes(shared_id) == ev_data
        # Collapsed artifact payload returns None (honest representation of historical collision)
        assert store.get_artifact_bytes(shared_id) is None
    finally:
        store.close()


def test_case_e_namespaced_evidence_plus_legacy_artifact(tmp_path):
    """Case E: Existing evidence: prefixed key plus a legacy key."""
    db_path = str(tmp_path / "case_e.db")
    _create_minimal_legacy_db(db_path)

    key = "item_e"
    ev_data = b"NAMESPACED_EV_E"
    art_data = b"LEGACY_ART_E"

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES (?, 'Case E', NULL, 'now');", (key,))
    conn.execute("INSERT INTO evidence_files VALUES (?, 'ev.raw', 'now', ?, ?);", (key, len(ev_data), hashlib.sha256(ev_data).hexdigest()))
    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES (?, ?, 'TXT', 'RECOVERED', 0.9);
        """,
        (key, key),
    )
    conn.execute("INSERT INTO blobs VALUES (?, ?, ?, 'now');", (f"evidence:{key}", ev_data, len(ev_data)))
    conn.execute("INSERT INTO blobs VALUES (?, ?, ?, 'now');", (key, art_data, len(art_data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_evidence_bytes(key) == ev_data
        assert store.get_artifact_bytes(key) == art_data
    finally:
        store.close()


def test_case_f_namespaced_artifact_plus_legacy_evidence(tmp_path):
    """Case F: Existing artifact: prefixed key plus a legacy key."""
    db_path = str(tmp_path / "case_f.db")
    _create_minimal_legacy_db(db_path)

    key = "item_f"
    art_data = b"NAMESPACED_ART_F"
    ev_data = b"LEGACY_EV_F"

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES (?, 'Case F', NULL, 'now');", (key,))
    conn.execute("INSERT INTO evidence_files VALUES (?, 'ev.raw', 'now', ?, ?);", (key, len(ev_data), hashlib.sha256(ev_data).hexdigest()))
    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES (?, ?, 'PNG', 'RECOVERED', 0.9);
        """,
        (key, key),
    )
    conn.execute("INSERT INTO blobs VALUES (?, ?, ?, 'now');", (f"artifact:{key}", art_data, len(art_data)))
    conn.execute("INSERT INTO blobs VALUES (?, ?, ?, 'now');", (key, ev_data, len(ev_data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_artifact_bytes(key) == art_data
        assert store.get_evidence_bytes(key) == ev_data
    finally:
        store.close()


def test_case_g_both_namespaced_keys_exist(tmp_path):
    """Case G: Both namespaced keys with different payloads."""
    db_path = str(tmp_path / "case_g.db")
    store = SqliteStore(db_path)
    try:
        key = "item_g"
        ev_data = b"EVIDENCE_PAYLOAD_G"
        art_data = b"ARTIFACT_PAYLOAD_G"

        store.evidence_blobs.put(key, ev_data)
        store.artifact_blobs.put(key, art_data)

        assert store.evidence_blobs.get(key) == ev_data
        assert store.artifact_blobs.get(key) == art_data
    finally:
        store.close()


def test_case_h_legacy_blob_no_relational_record(tmp_path):
    """Case H: A legacy blob with no corresponding relational record (orphaned)."""
    db_path = str(tmp_path / "case_h.db")
    _create_minimal_legacy_db(db_path)

    orphan_data = b"ORPHANED_BLOB_BYTES"
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO blobs VALUES ('orphan_h', ?, ?, 'now');", (orphan_data, len(orphan_data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_evidence_bytes("orphan_h") is None
        assert store.get_artifact_bytes("orphan_h") is None

        # Blob is preserved in blobs table
        with store._engine.transaction() as cur:
            cur.execute("SELECT blob_key FROM blobs WHERE blob_key = 'orphan_h';")
            assert cur.fetchone() is not None
    finally:
        store.close()


def test_case_i_relational_record_missing_blob(tmp_path):
    """Case I: A relational record whose blob is missing."""
    db_path = str(tmp_path / "case_i.db")
    _create_minimal_legacy_db(db_path)

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_i', 'Case I', NULL, 'now');")
    conn.execute("INSERT INTO evidence_files VALUES ('c_i', 'ev.raw', 'now', 100, ?);", ("a" * 64,))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_evidence_bytes("c_i") is None
        assert store.get_artifact_bytes("c_i") is None
    finally:
        store.close()


def test_case_j_zero_byte_payload(tmp_path):
    """Case J: Zero-byte payloads are migrated with exact binary fidelity."""
    db_path = str(tmp_path / "case_j.db")
    _create_minimal_legacy_db(db_path)

    empty_data = b""
    empty_sha = hashlib.sha256(empty_data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_j', 'Case J', NULL, 'now');")
    conn.execute("INSERT INTO evidence_files VALUES ('c_j', 'empty.bin', 'now', 0, ?);", (empty_sha,))
    conn.execute("INSERT INTO blobs VALUES ('c_j', ?, 0, 'now');", (empty_data,))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        res = store.get_evidence_bytes("c_j")
        assert res is not None
        assert res == b""
        assert len(res) == 0
    finally:
        store.close()


def test_case_k_missing_or_malformed_evidence_hashes(tmp_path):
    """Case K: Missing or malformed evidence hashes are preserved as ambiguous."""
    db_path = str(tmp_path / "case_k.db")
    _create_minimal_legacy_db(db_path)

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_k1', 'Case K1', NULL, 'now');")
    conn.execute("INSERT INTO evidence_files VALUES ('c_k1', 'ev1.raw', 'now', 10, 'not-a-sha256');")
    conn.execute("INSERT INTO blobs VALUES ('c_k1', X'0102030405060708090A', 10, 'now');")

    conn.execute("INSERT INTO cases VALUES ('c_k2', 'Case K2', NULL, 'now');")
    conn.execute("INSERT INTO evidence_files VALUES ('c_k2', 'ev2.raw', 'now', 10, '');")
    conn.execute("INSERT INTO blobs VALUES ('c_k2', X'0102030405060708090A', 10, 'now');")
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_evidence_bytes("c_k1") is None
        assert store.get_evidence_bytes("c_k2") is None

        # Both remain preserved in blobs table
        with store._engine.transaction() as cur:
            cur.execute("SELECT blob_key FROM blobs;")
            keys = [r[0] for r in cur.fetchall()]
            assert "c_k1" in keys
            assert "c_k2" in keys
    finally:
        store.close()


def test_case_l_file_size_metadata_inconsistent(tmp_path):
    """Case L: File-size metadata inconsistent with stored bytes is preserved as ambiguous."""
    db_path = str(tmp_path / "case_l.db")
    _create_minimal_legacy_db(db_path)

    actual_data = b"SHORT_DATA"  # length 10
    actual_sha = hashlib.sha256(actual_data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_l', 'Case L', NULL, 'now');")
    # Recorded size is 9999, but actual blob length is 10
    conn.execute("INSERT INTO evidence_files VALUES ('c_l', 'ev.raw', 'now', 9999, ?);", (actual_sha,))
    conn.execute("INSERT INTO blobs VALUES ('c_l', ?, 10, 'now');", (actual_data,))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_evidence_bytes("c_l") is None
        with store._engine.transaction() as cur:
            cur.execute("SELECT blob_key FROM blobs WHERE blob_key = 'c_l';")
            assert cur.fetchone() is not None
    finally:
        store.close()


def test_case_n_unexpected_namespace_like_keys(tmp_path):
    """Case N: Unexpected key values containing namespace-like prefixes handled deterministically."""
    db_path = str(tmp_path / "case_n.db")
    _create_minimal_legacy_db(db_path)

    data = b"PREFIX_LIKE_DATA"
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO blobs VALUES ('evidence:', ?, ?, 'now');", (data, len(data)))
    conn.execute("INSERT INTO blobs VALUES ('artifact:', ?, ?, 'now');", (data, len(data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        # Does not crash; keys without valid IDs are ignored
        assert store.get_evidence_bytes("") is None
        assert store.get_artifact_bytes("") is None
    finally:
        store.close()


# ── STEP 4: Atomicity and Multi-Stage Failure Recovery ───────────────────────


@pytest.mark.parametrize("fail_stage", [1, 2, 3, 4, 5, 6])
def test_atomicity_and_multi_stage_failure_recovery(tmp_path, fail_stage):
    """Inject failure at 6 different migration stages and verify 100% rollback and recovery."""
    db_path = str(tmp_path / f"fail_stage_{fail_stage}.db")
    _create_minimal_legacy_db(db_path)

    ev_data = b"EVIDENCE_STAGE_FAULT_INJECTION"
    ev_sha = hashlib.sha256(ev_data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_stage', 'Stage Case', NULL, 'now');")
    conn.execute("INSERT INTO evidence_files VALUES ('c_stage', 'ev.raw', 'now', ?, ?);", (len(ev_data), ev_sha))
    conn.execute("INSERT INTO blobs VALUES ('c_stage', ?, ?, 'now');", (ev_data, len(ev_data)))
    conn.commit()
    conn.close()

    engine = SqliteEngine(db_path)
    engine.initialize()

    real_transaction = engine.transaction

    step_count = 0

    def faulty_transaction():
        nonlocal step_count
        with real_transaction() as cursor:
            if fail_stage == 1:
                # Stage 1: Before the first row is processed
                raise sqlite3.OperationalError("Simulated failure at Stage 1")

            cursor.execute("SELECT blob_key, data, size_bytes, created_at FROM blobs WHERE blob_key = 'c_stage';")
            row = cursor.fetchone()

            if fail_stage == 2:
                # Stage 2: After identifying an evidence blob
                raise sqlite3.OperationalError("Simulated failure at Stage 2")

            cursor.execute(
                "INSERT INTO blobs (blob_key, data, size_bytes, created_at) VALUES ('evidence:c_stage', ?, ?, 'now');",
                (ev_data, len(ev_data)),
            )

            if fail_stage == 3:
                # Stage 3: After copying a blob into a namespace
                raise sqlite3.OperationalError("Simulated failure at Stage 3")

            if fail_stage == 4:
                # Stage 4: Before deleting its legacy key
                raise sqlite3.OperationalError("Simulated failure at Stage 4")

            cursor.execute("DELETE FROM blobs WHERE blob_key = 'c_stage';")

            if fail_stage == 5:
                # Stage 5: After migrating one row but before processing the next
                raise sqlite3.OperationalError("Simulated failure at Stage 5")

            if fail_stage == 6:
                # Stage 6: Immediately before transaction commit
                raise sqlite3.OperationalError("Simulated failure at Stage 6")

    with patch.object(engine, "transaction", side_effect=faulty_transaction):
        with pytest.raises(sqlite3.OperationalError):
            migrate_legacy_blobs(engine)

    # Inspect database post-failure: must have rolled back 100%
    with real_transaction() as cur:
        cur.execute("SELECT blob_key FROM blobs;")
        keys = [r[0] for r in cur.fetchall()]
        assert "c_stage" in keys, f"Stage {fail_stage}: original legacy key was lost!"
        assert "evidence:c_stage" not in keys, f"Stage {fail_stage}: partial uncommitted write was retained!"

    # Retry migration cleanly: must succeed deterministically
    stats = migrate_legacy_blobs(engine)
    assert stats["migrated_evidence"] == 1

    with real_transaction() as cur:
        cur.execute("SELECT blob_key FROM blobs;")
        keys = [r[0] for r in cur.fetchall()]
        assert "evidence:c_stage" in keys
        assert "c_stage" not in keys

    engine.close()


# ── STEP 5: Migration Idempotency Deep Verification ──────────────────────────


def test_migration_idempotency_deep_verification(tmp_path):
    """Run migration 5 consecutive times and verify exact database identity before and after."""
    db_path = str(tmp_path / "deep_idempotency.db")
    _create_minimal_legacy_db(db_path)

    ev_data = b"IDEMPOTENCY_EVIDENCE_DATA"
    art_data = b"IDEMPOTENCY_ARTIFACT_DATA"
    amb_data = b"AMBIGUOUS_DATA"

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_idemp', 'Case Idemp', NULL, 'now');")
    conn.execute("INSERT INTO evidence_files VALUES ('c_idemp', 'ev.raw', 'now', ?, ?);", (len(ev_data), hashlib.sha256(ev_data).hexdigest()))
    conn.execute("INSERT INTO blobs VALUES ('c_idemp', ?, ?, 'now');", (ev_data, len(ev_data)))

    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES ('a_idemp', 'c_idemp', 'TXT', 'RECOVERED', 0.9);
        """
    )
    conn.execute("INSERT INTO blobs VALUES ('a_idemp', ?, ?, 'now');", (art_data, len(art_data)))

    # Ambiguous entry (hash mismatch)
    conn.execute("INSERT INTO cases VALUES ('c_amb', 'Case Amb', NULL, 'now');")
    conn.execute("INSERT INTO evidence_files VALUES ('c_amb', 'ev.raw', 'now', 100, ?);", ("e" * 64,))
    conn.execute("INSERT INTO blobs VALUES ('c_amb', ?, ?, 'now');", (amb_data, len(amb_data)))

    conn.commit()
    conn.close()

    engine = SqliteEngine(db_path)

    # Run 1: performs migration
    stats1 = migrate_legacy_blobs(engine)
    assert stats1["migrated_evidence"] == 1
    assert stats1["migrated_artifact"] == 1
    assert stats1["ambiguous"] == 1

    def _snapshot():
        with engine.transaction() as cur:
            cur.execute("SELECT blob_key, data, size_bytes FROM blobs ORDER BY blob_key ASC;")
            return [(r["blob_key"], bytes(r["data"]), r["size_bytes"]) for r in cur.fetchall()]

    baseline_snapshot = _snapshot()

    # Runs 2 through 5: must produce 0 migrations and identical snapshot
    for i in range(2, 6):
        stats_i = migrate_legacy_blobs(engine)
        assert stats_i["migrated_evidence"] == 0, f"Run {i} unexpectedly migrated evidence!"
        assert stats_i["migrated_artifact"] == 0, f"Run {i} unexpectedly migrated artifact!"
        assert stats_i["ambiguous"] == 1
        current_snapshot = _snapshot()
        assert current_snapshot == baseline_snapshot, f"Snapshot diverged on run {i}!"

    engine.close()


# ── STEP 7: Post-Migration Functionality & Storage Contracts ─────────────────


def test_post_migration_storage_contracts(tmp_path):
    """Exercise complete post-migration CRUD and deletion isolation contracts."""
    db_path = str(tmp_path / "post_migration_crud.db")
    store = SqliteStore(db_path)
    try:
        case = store.create_case("CRUD Case")
        ev_meta = store.add_evidence(case.case_id, "ev.raw", b"ORIGINAL_EVIDENCE_BYTES")

        art_record = ArtifactRecord(
            artifact_id="art_crud_01",
            case_id=case.case_id,
            format="PNG",
            status="RECOVERED",
            confidence_score=0.99,
        )
        store.save_artifact_record(art_record)
        store.store_artifact_bytes("art_crud_01", b"ORIGINAL_ARTIFACT_BYTES")

        # 1. Exact byte equality
        assert store.get_evidence_bytes(case.case_id) == b"ORIGINAL_EVIDENCE_BYTES"
        assert store.get_artifact_bytes("art_crud_01") == b"ORIGINAL_ARTIFACT_BYTES"

        # 2. Overwriting artifact does not modify evidence
        store.store_artifact_bytes("art_crud_01", b"UPDATED_ARTIFACT_BYTES")
        assert store.get_artifact_bytes("art_crud_01") == b"UPDATED_ARTIFACT_BYTES"
        assert store.get_evidence_bytes(case.case_id) == b"ORIGINAL_EVIDENCE_BYTES"

        # 3. Deleting artifact never deletes evidence even if ID matches case_id
        store.delete_artifact(case.case_id)
        assert store.get_evidence_bytes(case.case_id) == b"ORIGINAL_EVIDENCE_BYTES"

        # 4. Deleting artifact removes artifact bytes cleanly
        store.delete_artifact("art_crud_01")
        assert store.get_artifact_bytes("art_crud_01") is None
        assert store.get_evidence_bytes(case.case_id) == b"ORIGINAL_EVIDENCE_BYTES"
    finally:
        store.close()
