"""
test_legacy_blob_migration_and_isolation_m322.py — Regression test suite for M3.22.0.

Validates legacy blob migration, namespace isolation, collision handling,
and exact parity between SqliteStore and InMemoryStore.
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


def _create_legacy_db(db_path: str) -> None:
    """Create a raw legacy database fixture mimicking pre-M3.21.0 schema."""
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE cases (case_id TEXT PRIMARY KEY, name TEXT, description TEXT, created_at TEXT);")
    conn.execute(
        """
        CREATE TABLE evidence_files (
            case_id TEXT PRIMARY KEY,
            filename TEXT,
            file_size INTEGER,
            uploaded_at TEXT,
            sha256 TEXT,
            chunk_size INTEGER DEFAULT 4096,
            total_chunks INTEGER DEFAULT 0
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE evidence_chunks (
            chunk_id TEXT PRIMARY KEY,
            case_id TEXT,
            chunk_index INTEGER,
            offset INTEGER,
            size INTEGER,
            sha256 TEXT
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE recovery_runs (
            run_id TEXT PRIMARY KEY,
            case_id TEXT,
            artifact_id TEXT,
            candidate_id TEXT,
            filename TEXT,
            format TEXT,
            status TEXT,
            detection_mode TEXT,
            started_at TEXT,
            completed_at TEXT,
            total_input_bytes INTEGER,
            total_verified_bytes INTEGER,
            total_reconstructed_bytes INTEGER,
            total_missing_bytes INTEGER,
            validation_json TEXT DEFAULT '{}',
            confidence_json TEXT DEFAULT '{}',
            provenance_json TEXT DEFAULT '{}',
            output_json TEXT,
            fragments_json TEXT DEFAULT '[]',
            damage_regions_json TEXT DEFAULT '[]',
            reconstruction_steps_json TEXT DEFAULT '[]',
            events_json TEXT DEFAULT '[]'
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE artifacts (
            artifact_id TEXT PRIMARY KEY,
            case_id TEXT,
            run_id TEXT,
            original_filename TEXT,
            recovered_filename TEXT,
            format TEXT,
            status TEXT,
            confidence_score REAL,
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
    conn.execute("CREATE TABLE artifact_runs (artifact_id TEXT PRIMARY KEY, run_id TEXT);")
    conn.execute(
        """
        CREATE TABLE blobs (
            blob_key TEXT PRIMARY KEY,
            data BLOB NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


# ── Step 3 Case A: Legacy Evidence Blob Only ────────────────────────────────


def test_case_a_legacy_evidence_only(tmp_path):
    """Case A: Legacy evidence blob exists; no artifact blob exists.

    Must return evidence bytes for evidence lookup, and None for artifact lookup.
    """
    db_path = str(tmp_path / "case_a.db")
    _create_legacy_db(db_path)

    ev_data = b"RAW_DISK_EVIDENCE_SECTORS_CASE_A"
    sha = hashlib.sha256(ev_data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('case_a', 'Case A', NULL, '2026-01-01T00:00:00Z');")
    conn.execute(
        "INSERT INTO evidence_files VALUES ('case_a', 'evidence.raw', ?, '2026-01-01T00:00:00Z', ?, 4096, 1);",
        (len(ev_data), sha),
    )
    conn.execute("INSERT INTO blobs VALUES ('case_a', ?, ?, '2026-01-01T00:00:00Z');", (ev_data, len(ev_data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_evidence_bytes("case_a") == ev_data
        assert store.get_artifact_bytes("case_a") is None
        assert store.evidence_blobs.exists("case_a") is True
        assert store.artifact_blobs.exists("case_a") is False

        # Verify deletion isolation
        assert store.artifact_blobs.delete("case_a") is False
        assert store.get_evidence_bytes("case_a") == ev_data
    finally:
        store.close()


# ── Step 3 Case B: Legacy Artifact Blob Only ────────────────────────────────


def test_case_b_legacy_artifact_only(tmp_path):
    """Case B: Legacy artifact blob exists; no evidence blob exists.

    Must return artifact bytes for artifact lookup, and None for evidence lookup.
    """
    db_path = str(tmp_path / "case_b.db")
    _create_legacy_db(db_path)

    art_data = b"RECOVERED_DOCUMENT_FILE_CASE_B"

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('case_b', 'Case B', NULL, '2026-01-01T00:00:00Z');")
    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES ('art_b', 'case_b', 'PDF', 'RECOVERED', 0.99);
        """
    )
    conn.execute("INSERT INTO blobs VALUES ('art_b', ?, ?, '2026-01-01T00:00:00Z');", (art_data, len(art_data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_artifact_bytes("art_b") == art_data
        assert store.get_evidence_bytes("art_b") is None
        assert store.artifact_blobs.exists("art_b") is True
        assert store.evidence_blobs.exists("art_b") is False

        # Verify deletion isolation
        assert store.evidence_blobs.delete("art_b") is False
        assert store.get_artifact_bytes("art_b") == art_data
    finally:
        store.close()


# ── Step 3 Case C: Legacy Collision Disambiguated by SHA-256 ─────────────────


def test_case_c_legacy_collision_evidence_verified(tmp_path):
    """Case C: Both legacy evidence and artifact identities use the same key, but only one unprefixed blob exists.

    If the blob matches evidence_files.sha256, it is verified evidence.
    Artifact lookup must return None (honest representation: artifact payload was lost in legacy collision).
    """
    db_path = str(tmp_path / "case_c.db")
    _create_legacy_db(db_path)

    shared_key = "colliding_id_c"
    ev_data = b"EVIDENCE_MATCHING_SHA256_DATA"
    ev_sha = hashlib.sha256(ev_data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES (?, 'Case C', NULL, '2026-01-01T00:00:00Z');", (shared_key,))
    conn.execute(
        "INSERT INTO evidence_files VALUES (?, 'evidence.raw', ?, '2026-01-01T00:00:00Z', ?, 4096, 1);",
        (shared_key, len(ev_data), ev_sha),
    )
    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES (?, ?, 'PNG', 'RECOVERED', 0.85);
        """,
        (shared_key, shared_key),
    )
    conn.execute("INSERT INTO blobs VALUES (?, ?, ?, '2026-01-01T00:00:00Z');", (shared_key, ev_data, len(ev_data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        # Evidence is verified
        assert store.get_evidence_bytes(shared_key) == ev_data
        assert store.evidence_blobs.exists(shared_key) is True

        # Artifact payload was overwritten in history: do not fabricate or return wrong bytes
        assert store.get_artifact_bytes(shared_key) is None
        assert store.artifact_blobs.exists(shared_key) is False
    finally:
        store.close()


# ── Step 3 Case D: Legacy Collision With Mismatched Hash (Ambiguous) ─────────


def test_case_d_legacy_collision_ambiguous_preserved(tmp_path):
    """Case D: Both legacy identities use the same key and original payloads were different,

    but database contains only one unprefixed entry whose hash does NOT match evidence_files.sha256.
    Must be preserved unmigrated and neither lookup may return unverified bytes.
    """
    db_path = str(tmp_path / "case_d.db")
    _create_legacy_db(db_path)

    shared_key = "colliding_id_d"
    expected_ev_sha = "0000000000000000000000000000000000000000000000000000000000000000"
    unknown_blob = b"CORRUPTED_OR_OVERWRITTEN_LEGACY_PAYLOAD"

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES (?, 'Case D', NULL, '2026-01-01T00:00:00Z');", (shared_key,))
    conn.execute(
        "INSERT INTO evidence_files VALUES (?, 'evidence.raw', ?, '2026-01-01T00:00:00Z', ?, 4096, 1);",
        (shared_key, 1024, expected_ev_sha),
    )
    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES (?, ?, 'ZIP', 'RECOVERED', 0.70);
        """,
        (shared_key, shared_key),
    )
    conn.execute(
        "INSERT INTO blobs VALUES (?, ?, ?, '2026-01-01T00:00:00Z');",
        (shared_key, unknown_blob, len(unknown_blob)),
    )
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        # Neither can safely claim this ambiguous blob
        assert store.get_evidence_bytes(shared_key) is None
        assert store.get_artifact_bytes(shared_key) is None

        # Verify unprefixed blob was NOT deleted
        with store._engine.transaction() as cur:
            cur.execute("SELECT data FROM blobs WHERE blob_key = ?;", (shared_key,))
            row = cur.fetchone()
            assert row is not None
            assert bytes(row["data"]) == unknown_blob
    finally:
        store.close()


# ── Step 3 Case E: Namespaced Evidence + Legacy Artifact Coexist ─────────────


def test_case_e_namespaced_evidence_coexists_with_legacy_artifact(tmp_path):
    """Case E: A namespaced evidence blob and legacy artifact key coexist."""
    db_path = str(tmp_path / "case_e.db")
    _create_legacy_db(db_path)

    key = "item_e"
    ev_data = b"NAMESPACED_EVIDENCE_PAYLOAD_E"
    art_data = b"LEGACY_ARTIFACT_PAYLOAD_E"
    ev_sha = hashlib.sha256(ev_data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES (?, 'Case E', NULL, '2026-01-01T00:00:00Z');", (key,))
    conn.execute(
        "INSERT INTO evidence_files VALUES (?, 'evidence.raw', ?, '2026-01-01T00:00:00Z', ?, 4096, 1);",
        (key, len(ev_data), ev_sha),
    )
    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES (?, ?, 'TXT', 'RECOVERED', 0.90);
        """,
        (key, key),
    )
    # Namespaced evidence blob already present
    conn.execute(
        "INSERT INTO blobs VALUES (?, ?, ?, '2026-01-01T00:00:00Z');",
        (f"evidence:{key}", ev_data, len(ev_data)),
    )
    # Legacy unprefixed artifact blob
    conn.execute("INSERT INTO blobs VALUES (?, ?, ?, '2026-01-01T00:00:00Z');", (key, art_data, len(art_data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_evidence_bytes(key) == ev_data
        assert store.get_artifact_bytes(key) == art_data
        assert store.evidence_blobs.exists(key) is True
        assert store.artifact_blobs.exists(key) is True
    finally:
        store.close()


# ── Step 3 Case F: Namespaced Artifact + Legacy Evidence Coexist ─────────────


def test_case_f_namespaced_artifact_coexists_with_legacy_evidence(tmp_path):
    """Case F: A namespaced artifact blob and legacy evidence key coexist."""
    db_path = str(tmp_path / "case_f.db")
    _create_legacy_db(db_path)

    key = "item_f"
    art_data = b"NAMESPACED_ARTIFACT_PAYLOAD_F"
    ev_data = b"LEGACY_EVIDENCE_PAYLOAD_F"
    ev_sha = hashlib.sha256(ev_data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES (?, 'Case F', NULL, '2026-01-01T00:00:00Z');", (key,))
    conn.execute(
        "INSERT INTO evidence_files VALUES (?, 'evidence.raw', ?, '2026-01-01T00:00:00Z', ?, 4096, 1);",
        (key, len(ev_data), ev_sha),
    )
    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES (?, ?, 'PNG', 'RECOVERED', 0.90);
        """,
        (key, key),
    )
    # Namespaced artifact blob already present
    conn.execute(
        "INSERT INTO blobs VALUES (?, ?, ?, '2026-01-01T00:00:00Z');",
        (f"artifact:{key}", art_data, len(art_data)),
    )
    # Legacy unprefixed evidence blob
    conn.execute("INSERT INTO blobs VALUES (?, ?, ?, '2026-01-01T00:00:00Z');", (key, ev_data, len(ev_data)))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_artifact_bytes(key) == art_data
        assert store.get_evidence_bytes(key) == ev_data
        assert store.artifact_blobs.exists(key) is True
        assert store.evidence_blobs.exists(key) is True
    finally:
        store.close()


# ── Step 3 Case G: Both Namespaced Blobs Exist ───────────────────────────────


def test_case_g_both_namespaced_blobs_exist(tmp_path):
    """Case G: Both namespaced blobs exist with different payloads."""
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

        # Deleting artifact must not touch evidence
        assert store.artifact_blobs.delete(key) is True
        assert store.artifact_blobs.get(key) is None
        assert store.evidence_blobs.get(key) == ev_data
    finally:
        store.close()


# ── Step 3 Case H: Migration Idempotency & Repeated Initialization ───────────


def test_case_h_migration_idempotency(tmp_path):
    """Case H: Migration is strictly idempotent and safe across multiple invocations and store restarts."""
    db_path = str(tmp_path / "case_h.db")
    _create_legacy_db(db_path)

    ev_data = b"EVIDENCE_H_BYTES"
    art_data = b"ARTIFACT_H_BYTES"

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_h', 'Case H', NULL, '2026-01-01T00:00:00Z');")
    conn.execute(
        "INSERT INTO evidence_files VALUES ('c_h', 'ev.raw', ?, '2026-01-01T00:00:00Z', ?, 4096, 1);",
        (len(ev_data), hashlib.sha256(ev_data).hexdigest()),
    )
    conn.execute("INSERT INTO blobs VALUES ('c_h', ?, ?, '2026-01-01T00:00:00Z');", (ev_data, len(ev_data)))
    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES ('a_h', 'c_h', 'TXT', 'RECOVERED', 0.9);
        """
    )
    conn.execute("INSERT INTO blobs VALUES ('a_h', ?, ?, '2026-01-01T00:00:00Z');", (art_data, len(art_data)))
    conn.commit()
    conn.close()

    # First open: executes migration
    store1 = SqliteStore(db_path)
    assert store1.get_evidence_bytes("c_h") == ev_data
    assert store1.get_artifact_bytes("a_h") == art_data

    # Re-run migration explicitly: should report 0 new migrations
    stats = store1.migrate_legacy_blobs()
    assert stats["migrated_evidence"] == 0
    assert stats["migrated_artifact"] == 0
    store1.close()

    # Second open: new store instance on same DB
    store2 = SqliteStore(db_path)
    assert store2.get_evidence_bytes("c_h") == ev_data
    assert store2.get_artifact_bytes("a_h") == art_data
    store2.close()


# ── Step 3 Case I: Missing Legacy Blob ───────────────────────────────────────


def test_case_i_missing_legacy_blob(tmp_path):
    """Case I: A legacy record exists in relational table but blob is missing from blobs table."""
    db_path = str(tmp_path / "case_i.db")
    _create_legacy_db(db_path)

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_i', 'Case I', NULL, '2026-01-01T00:00:00Z');")
    conn.execute(
        "INSERT INTO evidence_files VALUES ('c_i', 'ev.raw', 100, '2026-01-01T00:00:00Z', 'hash', 4096, 1);"
    )
    conn.execute(
        """
        INSERT INTO artifacts (artifact_id, case_id, format, status, confidence_score)
        VALUES ('a_i', 'c_i', 'TXT', 'RECOVERED', 0.9);
        """
    )
    # Intentionally do not insert any rows in blobs table
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        assert store.get_evidence_bytes("c_i") is None
        assert store.get_artifact_bytes("a_i") is None
        assert store.evidence_blobs.exists("c_i") is False
        assert store.artifact_blobs.exists("a_i") is False
    finally:
        store.close()


# ── Step 3 Case J: Empty Legacy Blob (0-byte payload) ────────────────────────


def test_case_j_empty_legacy_blob(tmp_path):
    """Case J: A legacy blob has an empty (0-byte) payload."""
    db_path = str(tmp_path / "case_j.db")
    _create_legacy_db(db_path)

    empty_data = b""
    empty_sha = hashlib.sha256(empty_data).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_j', 'Case J', NULL, '2026-01-01T00:00:00Z');")
    conn.execute(
        "INSERT INTO evidence_files VALUES ('c_j', 'empty.bin', 0, '2026-01-01T00:00:00Z', ?, 4096, 0);",
        (empty_sha,),
    )
    conn.execute("INSERT INTO blobs VALUES ('c_j', ?, 0, '2026-01-01T00:00:00Z');", (empty_data,))
    conn.commit()
    conn.close()

    store = SqliteStore(db_path)
    try:
        res = store.get_evidence_bytes("c_j")
        assert res is not None
        assert res == b""
        assert len(res) == 0
        assert store.get_artifact_bytes("c_j") is None
    finally:
        store.close()


# ── Deletion Safety ──────────────────────────────────────────────────────────


def test_delete_artifact_never_deletes_evidence(tmp_path):
    """Verify that calling delete_artifact never deletes evidence under any circumstances."""
    db_path = str(tmp_path / "del_safety.db")
    store = SqliteStore(db_path)
    try:
        case = store.create_case("Delete Test Case")
        ev_meta = store.add_evidence(case.case_id, "evidence.raw", b"CRITICAL_FORENSIC_EVIDENCE")

        # Try to delete using the case_id as artifact_id
        deleted = store.delete_artifact(case.case_id)
        assert deleted is False

        # Evidence must still exist with exact bytes
        assert store.get_evidence_bytes(case.case_id) == b"CRITICAL_FORENSIC_EVIDENCE"
    finally:
        store.close()


# ── Atomic Migration Rollback ────────────────────────────────────────────────


def test_migration_atomic_rollback_on_failure(tmp_path):
    """Verify that if an error occurs during migration, the transaction is completely rolled back."""
    db_path = str(tmp_path / "rollback.db")
    _create_legacy_db(db_path)

    ev_data = b"EVIDENCE_BEFORE_CRASH"
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO cases VALUES ('c_err', 'Case Err', NULL, '2026-01-01T00:00:00Z');")
    conn.execute(
        "INSERT INTO evidence_files VALUES ('c_err', 'ev.raw', ?, '2026-01-01T00:00:00Z', ?, 4096, 1);",
        (len(ev_data), hashlib.sha256(ev_data).hexdigest()),
    )
    conn.execute("INSERT INTO blobs VALUES ('c_err', ?, ?, '2026-01-01T00:00:00Z');", (ev_data, len(ev_data)))
    conn.commit()
    conn.close()

    engine = SqliteEngine(db_path)
    engine.initialize()

    # Simulate failure during migration by hooking into cursor.execute
    real_transaction = engine.transaction

    with patch.object(engine, "transaction") as mock_tx:
        # Let's test that if an exception is raised inside transaction, rollback occurs
        def failing_tx():
            with real_transaction() as cursor:
                cursor.execute(
                    "INSERT INTO blobs (blob_key, data, size_bytes, created_at) VALUES ('evidence:c_err', ?, ?, 'now');",
                    (ev_data, len(ev_data)),
                )
                raise sqlite3.OperationalError("Simulated disk error during migration")

        mock_tx.side_effect = failing_tx

        with pytest.raises(sqlite3.OperationalError):
            migrate_legacy_blobs(engine)

    # Reconnect and verify original state is completely intact
    with real_transaction() as cur:
        cur.execute("SELECT blob_key FROM blobs;")
        keys = [r[0] for r in cur.fetchall()]
        assert "c_err" in keys
        assert "evidence:c_err" not in keys

    engine.close()


# ── Fresh Store Cleanliness ──────────────────────────────────────────────────


def test_fresh_store_creates_only_namespaced_blobs(tmp_path):
    """Verify that fresh store operations never create unprefixed legacy blobs."""
    db_path = str(tmp_path / "fresh.db")
    store = SqliteStore(db_path)
    try:
        case = store.create_case("Fresh Case")
        store.add_evidence(case.case_id, "ev.raw", b"FRESH_EVIDENCE_BYTES")

        art_record = ArtifactRecord(
            artifact_id="art_fresh_001",
            case_id=case.case_id,
            format="PNG",
            status="RECOVERED",
            confidence_score=0.95,
        )
        store.save_artifact_record(art_record)
        store.store_artifact_bytes(art_record.artifact_id, b"FRESH_ARTIFACT_BYTES")

        with store._engine.transaction() as cur:
            cur.execute("SELECT blob_key FROM blobs;")
            keys = [r[0] for r in cur.fetchall()]
            assert len(keys) == 2
            for k in keys:
                assert k.startswith("evidence:") or k.startswith("artifact:")
    finally:
        store.close()


# ── Parity With InMemoryStore ────────────────────────────────────────────────


def test_sqlite_and_in_memory_parity(tmp_path):
    """Verify exact parity between SqliteStore and InMemoryStore for namespace isolation."""
    db_path = str(tmp_path / "parity.db")
    sql_store = SqliteStore(db_path)
    mem_store = InMemoryStore()

    for store in (sql_store, mem_store):
        shared_id = "shared_entity_999"
        ev_bytes = b"EVIDENCE_PARITY_BYTES"
        art_bytes = b"ARTIFACT_PARITY_BYTES"

        case = store.create_case("Parity Case")
        # Put evidence
        store.evidence_blobs.put(shared_id, ev_bytes)
        # Put artifact
        store.store_artifact_bytes(shared_id, art_bytes)

        # 1. Independent lookups
        assert store.get_evidence_bytes(shared_id) == ev_bytes
        assert store.get_artifact_bytes(shared_id) == art_bytes
        assert store.evidence_blobs.exists(shared_id) is True
        assert store.artifact_blobs.exists(shared_id) is True

        # 2. Delete artifact leaves evidence untouched
        assert store.artifact_blobs.delete(shared_id) is True
        assert store.get_artifact_bytes(shared_id) is None
        assert store.get_evidence_bytes(shared_id) == ev_bytes

        # 3. Empty payload handling
        store.evidence_blobs.put("empty_ev", b"")
        assert store.get_evidence_bytes("empty_ev") == b""
        assert store.get_artifact_bytes("empty_ev") is None

        # 4. Missing key handling
        assert store.get_evidence_bytes("nonexistent") is None
        assert store.get_artifact_bytes("nonexistent") is None

    sql_store.close()
