"""
test_artifact_sha256_integrity_step6b2.py — Regression tests for recovered-artifact SHA-256 integrity.

Covers Step 6B.2 requirements:
1. Persisted SHA-256 digest is calculated from the exact recovered bytes.
2. Distinct labeling and preservation of original upload evidence hash vs recovered artifact hash.
3. Cryptographic integrity check prior to serving download via constant-time comparison.
4. Fail-closed behavior on single-byte tampering in blob store.
5. Fail-closed behavior on corrupted/tampered persisted digest in SQLite.
6. Fail-closed behavior on missing or malformed digest.
7. Fail-closed behavior on ineligible recovery status (UNRECOVERABLE, FAILED validation, is_downloadable=False).
8. Persistence across SQLite engine close and reopen.
9. Database migration adding sha256 column and deterministic backfill of legacy records.
10. Downloads via both artifact ID and linked recovery-run ID.
11. Sanitize error messages: no leakage of internal paths, blob keys, or payload contents.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app, reset_rate_limits
from backend.app.store import store
from backend.app.storage.sqlite_engine import SqliteEngine
from backend.app.storage.sqlite_store import SqliteStore
from backend.app.models.artifact import (
    ArtifactRecord,
    ArtifactResponse,
    ConfidenceBreakdownSchema,
    ArtifactProvenanceSchema,
)
from backend.app.recovery.artifact_integrity import (
    verify_artifact_download_integrity,
    is_valid_sha256_hex,
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


# ── Test 1: Single-File Recovery Produces Matching SHA-256 Digest ───────────

def test_single_file_recovery_populates_sha256_and_serves_download():
    """Verify single-file recovery computes SHA-256 over exact recovered bytes,

    persists it on the record, and serves download with matching ETag and digest headers.
    """
    payload = b'{"case_id":"CASE-777","status":"RESOLVED","items":[1,2,3,4]}'
    response = client.post(
        "/api/recover-file",
        files={"file": ("incident.json", payload, "application/json")},
    )
    assert response.status_code == 200
    data = response.json()

    expected_sha = hashlib.sha256(payload).hexdigest().lower()
    assert data["sha256"] == expected_sha
    assert data["is_downloadable"] is True

    # Persisted record check
    file_id = data["file_id"]
    rec = store.get_artifact_record(file_id)
    assert rec is not None
    assert rec.sha256 == expected_sha

    # Download via primary route
    dl_resp = client.get(data["download_url"])
    assert dl_resp.status_code == 200
    assert dl_resp.content == payload
    assert dl_resp.headers["etag"] == f'"{expected_sha}"'
    assert dl_resp.headers["x-artifact-sha256"] == expected_sha

    # Download via alias route
    alias_resp = client.get(f"/api/recover/file/{file_id}/download")
    assert alias_resp.status_code == 200
    assert alias_resp.content == payload
    assert alias_resp.headers["etag"] == f'"{expected_sha}"'


# ── Test 2: Case Analysis Separates Evidence Hash from Artifact Hash ──────────

def test_case_analysis_distinct_evidence_and_artifact_sha256():
    """Verify Pipeline A distinctly labels original upload evidence sha256 vs

    recovered artifact sha256, and artifact download verifies the artifact sha256.
    """
    case_resp = client.post("/api/cases", json={"name": "Integrity Test Case"})
    assert case_resp.status_code == 201
    case_id = case_resp.json()["case_id"]

    # Evidence has some padding/wrapper around a JSON payload
    inner_json = b'{"forensic_evidence":"authenticated_record","count":99}'
    evidence_bytes = b"HEADER_JUNK_DATA\n" + inner_json + b"\nTRAILER_GARBAGE"

    evidence_sha = hashlib.sha256(evidence_bytes).hexdigest().lower()

    up_resp = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("evidence.raw", evidence_bytes, "application/octet-stream")},
    )
    assert up_resp.status_code == 200
    assert up_resp.json()["evidence"]["sha256"] == evidence_sha

    # Run analysis
    an_resp = client.post(f"/api/cases/{case_id}/analyze")
    assert an_resp.status_code == 200
    artifacts = an_resp.json()["artifacts"]
    assert len(artifacts) > 0

    art = artifacts[0]
    art_id = art["artifact_id"]

    # Verify distinct hashes
    assert art["metadata"]["evidence_sha256"] == evidence_sha
    assert art["sha256"] is not None
    assert art["sha256"] != evidence_sha  # Recovered artifact hash differs from raw evidence container hash

    # Download artifact and verify bytes match artifact sha256
    dl_resp = client.get(f"/api/artifacts/{art_id}/download")
    assert dl_resp.status_code == 200
    downloaded_bytes = dl_resp.content
    assert hashlib.sha256(downloaded_bytes).hexdigest().lower() == art["sha256"]
    assert dl_resp.headers["etag"] == f'"{art["sha256"]}"'
    assert dl_resp.headers["x-artifact-sha256"] == art["sha256"]


# ── Test 3: Single-Byte Payload Tampering Fails Closed with 404 ──────────────

def test_single_byte_tampering_in_blob_store_blocks_download():
    """Adversarial check: modifying a single byte in the binary payload store

    triggers cryptographic integrity failure, causing the download endpoint to
    fail closed (404) without leaking paths or content.
    """
    payload = b'{"important":"untampered_payload","data":[10,20,30]}'
    response = client.post(
        "/api/recover-file",
        files={"file": ("evidence.json", payload, "application/json")},
    )
    assert response.status_code == 200
    file_id = response.json()["file_id"]

    # Directly tamper one byte in the database blob table
    if isinstance(store, SqliteStore):
        engine = store._engine
        with engine.transaction() as cur:
            cur.execute(
                "SELECT data FROM blobs WHERE blob_key = ?;",
                (f"artifact:{file_id}",),
            )
            row = cur.fetchone()
            assert row is not None
            raw_blob = bytearray(row[0] if isinstance(row, (tuple, list)) else row["data"])
            # Flip a single bit in the first byte
            raw_blob[0] ^= 0x01
            cur.execute(
                "UPDATE blobs SET data = ? WHERE blob_key = ?;",
                (sqlite3.Binary(raw_blob), f"artifact:{file_id}"),
            )
    else:
        # In-memory store fallback
        raw_blob = bytearray(store.get_artifact_bytes(file_id))
        raw_blob[0] ^= 0x01
        store._artifact_blobs.put(file_id, bytes(raw_blob))

    # Attempt download -> must fail closed with 404
    dl_resp = client.get(f"/api/recover-file/{file_id}/download")
    assert dl_resp.status_code == 404
    detail = dl_resp.json()["detail"]
    assert "Integrity verification failed" in detail
    # Verify no leaked server paths or payloads
    assert "/Users/" not in detail
    assert "blobs" not in detail
    assert "untampered" not in detail

    # Also check case download endpoint behaves identically
    case_dl_resp = client.get(f"/api/artifacts/{file_id}/download")
    assert case_dl_resp.status_code == 404


# ── Test 4: Tampering Persisted Digest in Database Fails Closed ─────────────

def test_tampered_persisted_digest_in_database_blocks_download():
    """Adversarial check: altering the stored SHA-256 hash in the database to a

    different valid hash causes verification failure and blocks download.
    """
    payload = b"Sample text artifact for digest tampering test"
    rec_resp = client.post(
        "/api/recover-file",
        files={"file": ("sample.txt", payload, "text/plain")},
    )
    assert rec_resp.status_code == 200
    file_id = rec_resp.json()["file_id"]

    fake_sha = hashlib.sha256(b"completely_different_payload").hexdigest().lower()

    if isinstance(store, SqliteStore):
        with store._engine.transaction() as cur:
            cur.execute(
                "UPDATE artifacts SET sha256 = ? WHERE artifact_id = ?;",
                (fake_sha, file_id),
            )
    else:
        rec = store.get_artifact_record(file_id)
        rec.sha256 = fake_sha

    dl_resp = client.get(f"/api/recover-file/{file_id}/download")
    assert dl_resp.status_code == 404
    assert "Integrity verification failed" in dl_resp.json()["detail"]


# ── Test 5: Missing or Null Digest Blocks Download ──────────────────────────

def test_missing_or_null_sha256_digest_blocks_download():
    """Adversarial check: an artifact with NULL sha256 cannot be served for download."""
    payload = b"Unverified legacy artifact bytes without digest"
    file_id = "art_legacy_no_digest"

    rec = ArtifactRecord(
        artifact_id=file_id,
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=100.0,
        verified_bytes=len(payload),
        reconstructed_bytes=0,
        missing_bytes=0,
        total_input_bytes=len(payload),
        validation_status="PASSED",
        is_downloadable=True,
        sha256=None,
    )
    store.save_artifact_record(rec)
    # Manually store bytes without updating sha256
    if isinstance(store, SqliteStore):
        with store._engine.transaction() as cur:
            cur.execute(
                "INSERT INTO blobs (blob_key, data, size_bytes, created_at) VALUES (?, ?, ?, datetime('now'));",
                (f"artifact:{file_id}", sqlite3.Binary(payload), len(payload)),
            )
            cur.execute("UPDATE artifacts SET sha256 = NULL WHERE artifact_id = ?;", (file_id,))
    else:
        store._artifact_blobs.put(file_id, payload)
        rec.sha256 = None

    dl_resp = client.get(f"/api/artifacts/{file_id}/download")
    assert dl_resp.status_code == 404
    assert "Integrity verification failed" in dl_resp.json()["detail"]


# ── Test 6: Malformed Digest Strings Block Download ─────────────────────────

@pytest.mark.parametrize(
    "malformed_sha",
    [
        "not_a_sha256",
        "12345",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855extra",  # 69 chars
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",       # 63 chars
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",       # Non-hex
        "",
        "   ",
    ],
)
def test_malformed_sha256_format_blocks_download(malformed_sha: str):
    """Adversarial check: any non-standard or malformed SHA-256 string fails verification."""
    payload = b"Valid payload data"
    file_id = f"art_malformed_{hashlib.md5(malformed_sha.encode()).hexdigest()[:8]}"

    rec = ArtifactRecord(
        artifact_id=file_id,
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=100.0,
        verified_bytes=len(payload),
        reconstructed_bytes=0,
        missing_bytes=0,
        total_input_bytes=len(payload),
        validation_status="PASSED",
        is_downloadable=True,
        sha256=malformed_sha,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes(file_id, payload)

    # Force the malformed string into SQLite directly (bypassing any store update)
    if isinstance(store, SqliteStore):
        with store._engine.transaction() as cur:
            cur.execute("UPDATE artifacts SET sha256 = ? WHERE artifact_id = ?;", (malformed_sha, file_id))

    dl_resp = client.get(f"/api/artifacts/{file_id}/download")
    assert dl_resp.status_code == 404
    assert "Integrity verification failed" in dl_resp.json()["detail"]


# ── Test 7: Ineligible Recovery Status Never Served Even with Valid Digest ────

@pytest.mark.parametrize(
    "status,val_status,is_dl",
    [
        ("UNRECOVERABLE", "FAILED", False),
        ("CORRUPTED", "PASSED", True),
        ("PARTIALLY_RECOVERED", "FAILED", True),
        ("FULLY_RECOVERED", "PASSED", False),
    ],
)
def test_ineligible_status_blocks_download_even_if_digest_matches(status: str, val_status: str, is_dl: bool):
    """Guarantees that status/validation gates fail closed before cryptographic serving."""
    payload = b"Valid bytes that should not be served due to status eligibility"
    file_id = f"art_ineligible_{status}_{val_status}"
    payload_sha = hashlib.sha256(payload).hexdigest().lower()

    rec = ArtifactRecord(
        artifact_id=file_id,
        format="txt",
        status=status,
        confidence_score=50.0,
        verified_bytes=len(payload),
        reconstructed_bytes=0,
        missing_bytes=0,
        total_input_bytes=len(payload),
        validation_status=val_status,
        is_downloadable=is_dl,
        sha256=payload_sha,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes(file_id, payload)

    dl_resp = client.get(f"/api/artifacts/{file_id}/download")
    assert dl_resp.status_code == 404
    assert "cannot be downloaded" in dl_resp.json()["detail"]


# ── Test 8: Persistence and Verification Across SQLite Close and Reopen ───────

def test_sqlite_restart_preserves_sha256_and_allows_verified_download():
    """Verify that sha256 survives persistent database close and reopen,

    and continues to authorize verified downloads.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        # Initialize store 1
        engine1 = SqliteEngine(db_path=db_path)
        store1 = SqliteStore(engine=engine1)

        payload = b'{"system":"RECOVERIX_DETERMINISTIC","key":"integrity_test"}'
        file_id = "rec_persistent_integrity_001"
        payload_sha = hashlib.sha256(payload).hexdigest().lower()

        meta = {
            "file_id": file_id,
            "format": "json",
            "status": "FULLY_RECOVERED",
            "confidence_score": 100.0,
            "verified_bytes": len(payload),
            "reconstructed_bytes": 0,
            "missing_bytes": 0,
            "validation_status": "PASSED",
            "is_downloadable": True,
        }
        store1.store_recovered_file(file_id, meta, payload)

        # Confirm persisted on store 1
        rec1 = store1.get_artifact_record(file_id)
        assert rec1 is not None
        assert rec1.sha256 == payload_sha

        # Close store 1
        store1.close()

        # Open store 2 on the exact same database file
        engine2 = SqliteEngine(db_path=db_path)
        store2 = SqliteStore(engine=engine2)

        # Retrieve record from restarted store
        rec2 = store2.get_artifact_record(file_id)
        assert rec2 is not None
        assert rec2.sha256 == payload_sha

        # Retrieve bytes and run direct verification
        retrieved_bytes = store2.get_recovered_file_bytes(file_id)
        verified = verify_artifact_download_integrity(rec2, retrieved_bytes, file_id)
        assert verified == payload

        store2.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


# ── Test 9: Schema Migration and Legacy Backfill ─────────────────────────────

def test_migration_and_deterministic_backfill_of_legacy_records():
    """Adversarial check: simulate a legacy database that has artifacts without

    a sha256 column and legacy blobs. Upon initialize(), the migration must
    add the column and safely backfill the sha256 digest from existing blobs.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        conn = sqlite3.connect(db_path)
        # Create legacy artifacts table without sha256
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
                verified_bytes INTEGER NOT NULL DEFAULT 0,
                reconstructed_bytes INTEGER NOT NULL DEFAULT 0,
                missing_bytes INTEGER NOT NULL DEFAULT 0,
                total_input_bytes INTEGER,
                reconstruction_method TEXT NOT NULL DEFAULT 'NONE',
                validation_status TEXT NOT NULL DEFAULT 'PASSED',
                is_downloadable INTEGER NOT NULL DEFAULT 1,
                download_url TEXT,
                content_preview TEXT,
                category TEXT,
                priority TEXT,
                ai_summary TEXT,
                score_breakdown_json TEXT NOT NULL DEFAULT '{}',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                validation_details_json TEXT NOT NULL DEFAULT '{}',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                fragments_json TEXT,
                damage_regions_json TEXT,
                reconstruction_steps_json TEXT,
                created_at TEXT
            );
            """
        )
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

        legacy_data1 = b"Legacy recovered artifact payload 1"
        legacy_sha1 = hashlib.sha256(legacy_data1).hexdigest().lower()
        art_id1 = "art_legacy_001"

        # Insert legacy artifact record
        conn.execute(
            """
            INSERT INTO artifacts (
                artifact_id, format, status, confidence_score, verified_bytes,
                reconstructed_bytes, missing_bytes, validation_status, is_downloadable
            ) VALUES (?, 'txt', 'FULLY_RECOVERED', 100.0, ?, 0, 0, 'PASSED', 1);
            """,
            (art_id1, len(legacy_data1)),
        )
        # Insert legacy namespaced blob
        conn.execute(
            "INSERT INTO blobs (blob_key, data, size_bytes, created_at) VALUES (?, ?, ?, datetime('now'));",
            (f"artifact:{art_id1}", sqlite3.Binary(legacy_data1), len(legacy_data1)),
        )

        # Also insert a legacy artifact without a blob (orphan/missing)
        art_id2 = "art_legacy_orphan"
        conn.execute(
            """
            INSERT INTO artifacts (
                artifact_id, format, status, confidence_score, verified_bytes,
                reconstructed_bytes, missing_bytes, validation_status, is_downloadable
            ) VALUES (?, 'txt', 'FULLY_RECOVERED', 100.0, 10, 0, 0, 'PASSED', 1);
            """,
            (art_id2,),
        )
        conn.commit()
        conn.close()

        # Open with modern SqliteEngine which executes initialize() migrations
        engine = SqliteEngine(db_path=db_path)
        engine.initialize()

        # Check table columns
        conn_check = engine.connect()
        cur = conn_check.cursor()
        cur.execute("PRAGMA table_info(artifacts);")
        cols = {row[1] for row in cur.fetchall()}
        assert "sha256" in cols

        # Check legacy backfill
        cur.execute("SELECT artifact_id, sha256 FROM artifacts WHERE artifact_id = ?;", (art_id1,))
        row1 = cur.fetchone()
        assert row1[1] == legacy_sha1  # Successfully backfilled!

        cur.execute("SELECT artifact_id, sha256 FROM artifacts WHERE artifact_id = ?;", (art_id2,))
        row2 = cur.fetchone()
        assert row2[1] is None  # Remained NULL safely

        conn_check.close()
        engine.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


# ── Test 10: Download by Artifact ID vs Recovery Run ID ─────────────────────

def test_download_authorization_by_artifact_id_and_run_id():
    """Verify that an artifact can be securely downloaded using either its

    canonical artifact_id or its authoritative linked run_id, while unlinked
    or spoofed IDs are rejected.
    """
    payload = b'{"transaction_id":"TX-90210","amount":450.50}'
    payload_sha = hashlib.sha256(payload).hexdigest().lower()

    resp = client.post(
        "/api/recover-file",
        files={"file": ("tx.json", payload, "application/json")},
    )
    assert resp.status_code == 200
    data = resp.json()
    art_id = data["file_id"]
    run_id = data["run_id"]
    assert run_id is not None

    # Download by artifact_id
    dl_by_art = client.get(f"/api/recover-file/{art_id}/download")
    assert dl_by_art.status_code == 200
    assert dl_by_art.content == payload

    # Download by run_id
    dl_by_run = client.get(f"/api/recover-file/{run_id}/download")
    assert dl_by_run.status_code == 200
    assert dl_by_run.content == payload

    # Download with spoofed/unrelated ID
    dl_spoof = client.get("/api/recover-file/rec_run_nonexistent_fake/download")
    assert dl_spoof.status_code == 404


# ── Step 6B.2B Finding A: Concurrent SQLite Schema Migration Tests ─────────────

class _RacingConnectionProxy:
    """Proxy around sqlite3.Connection to simulate concurrent race conditions."""

    def __init__(self, conn: sqlite3.Connection, fail_col: Optional[str] = None, fail_msg: str = "duplicate column name"):
        self._conn = conn
        self._fail_col = fail_col
        self._fail_msg = fail_msg

    def cursor(self):
        return self._conn.cursor()

    def execute(self, sql: str, *args, **kwargs):
        if self._fail_col and f"ADD COLUMN {self._fail_col}" in sql:
            raise sqlite3.OperationalError(f"{self._fail_msg}: {self._fail_col}")
        return self._conn.execute(sql, *args, **kwargs)

    def __getattr__(self, name: str):
        return getattr(self._conn, name)


def test_safe_add_column_race_safety_and_error_handling():
    """Verify _safe_add_column handles concurrent race conditions and duplicate

    column errors gracefully when column is verified present, but re-raises
    unrelated or unverified errors.
    """
    from backend.app.storage.sqlite_engine import _safe_add_column

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT);")
        conn.commit()

        # 1. Normal addition
        _safe_add_column(conn, "test_table", "col_a", "TEXT")
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(test_table);")
        cols = {row[1] for row in cur.fetchall()}
        assert "col_a" in cols

        # 2. Idempotent re-addition (skips ALTER TABLE)
        _safe_add_column(conn, "test_table", "col_a", "TEXT")

        # 3. Simulate race: proxy raises OperationalError("duplicate column name: col_b")
        # while column col_b actually exists in the table
        conn.execute("ALTER TABLE test_table ADD COLUMN col_b TEXT;")
        conn.commit()

        racing_conn = _RacingConnectionProxy(conn, fail_col="col_b")
        # Should not raise because col_b is verified present in table_info
        _safe_add_column(racing_conn, "test_table", "col_b", "TEXT")

        # 4. Unrelated error should raise immediately (e.g. invalid table name)
        with pytest.raises(sqlite3.OperationalError):
            _safe_add_column(conn, "nonexistent_table", "col_c", "TEXT")

        # 5. OperationalError where column does NOT actually exist should raise
        false_racing_conn = _RacingConnectionProxy(conn, fail_col="col_c")
        with pytest.raises(sqlite3.OperationalError):
            _safe_add_column(false_racing_conn, "test_table", "col_c", "TEXT")

        conn.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_concurrent_schema_migration_multi_threaded():
    """Simulate multiple threads running SqliteEngine.initialize() concurrently

    against a pre-migration database.
    """
    import concurrent.futures

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        # Create full pre-migration database without created_at and sha256 in artifacts
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE cases (
                case_id TEXT PRIMARY KEY,
                case_name TEXT NOT NULL,
                investigator TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                evidence_count INTEGER NOT NULL DEFAULT 0,
                artifact_count INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE recovery_runs (
                run_id TEXT PRIMARY KEY,
                case_id TEXT REFERENCES cases(case_id) ON DELETE CASCADE,
                artifact_id TEXT,
                candidate_id TEXT,
                filename TEXT NOT NULL,
                format TEXT NOT NULL,
                status TEXT NOT NULL,
                detection_mode TEXT NOT NULL DEFAULT 'known_file',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                total_input_bytes INTEGER NOT NULL,
                total_verified_bytes INTEGER NOT NULL,
                total_reconstructed_bytes INTEGER NOT NULL,
                total_missing_bytes INTEGER NOT NULL,
                validation_json TEXT NOT NULL DEFAULT '{}',
                confidence_json TEXT NOT NULL DEFAULT '{}',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                output_json TEXT,
                fragments_json TEXT NOT NULL DEFAULT '[]',
                damage_regions_json TEXT NOT NULL DEFAULT '[]',
                reconstruction_steps_json TEXT NOT NULL DEFAULT '[]',
                events_json TEXT NOT NULL DEFAULT '[]'
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE artifacts (
                artifact_id TEXT PRIMARY KEY,
                case_id TEXT REFERENCES cases(case_id) ON DELETE CASCADE,
                run_id TEXT REFERENCES recovery_runs(run_id) ON DELETE SET NULL,
                original_filename TEXT,
                recovered_filename TEXT,
                format TEXT NOT NULL,
                status TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                verified_bytes INTEGER NOT NULL,
                reconstructed_bytes INTEGER NOT NULL,
                missing_bytes INTEGER NOT NULL,
                total_input_bytes INTEGER,
                reconstruction_method TEXT NOT NULL DEFAULT 'NONE',
                validation_status TEXT NOT NULL DEFAULT 'PENDING',
                is_downloadable INTEGER NOT NULL DEFAULT 1,
                download_url TEXT,
                content_preview TEXT,
                category TEXT,
                priority TEXT,
                ai_summary TEXT,
                score_breakdown_json TEXT NOT NULL DEFAULT '{}',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                validation_details_json TEXT NOT NULL DEFAULT '{}',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                fragments_json TEXT,
                damage_regions_json TEXT,
                reconstruction_steps_json TEXT
            );
            """
        )
        conn.execute("CREATE TABLE blobs (blob_key TEXT PRIMARY KEY, data BLOB, size_bytes INTEGER, created_at TEXT);")
        conn.commit()
        conn.close()

        errors = []
        def run_init():
            try:
                eng = SqliteEngine(db_path=db_path)
                eng.initialize()
                eng.close()
            except Exception as e:
                errors.append(e)

        # Run 8 concurrent initializers
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(run_init) for _ in range(8)]
            for fut in concurrent.futures.as_completed(futures):
                fut.result()

        assert len(errors) == 0

        # Verify columns exist
        verify_eng = SqliteEngine(db_path=db_path)
        conn_v = verify_eng.connect()
        cur = conn_v.cursor()
        cur.execute("PRAGMA table_info(artifacts);")
        art_cols = {row[1] for row in cur.fetchall()}
        assert "sha256" in art_cols
        assert "created_at" in art_cols

        cur.execute("PRAGMA table_info(recovery_runs);")
        rr_cols = {row[1] for row in cur.fetchall()}
        assert "case_name" in rr_cols
        assert "investigator" in rr_cols
        assert "notes" in rr_cols

        conn_v.close()
        verify_eng.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


# ── Step 6B.2B Finding B: Deterministic Legacy Backfill Tests ───────────────────

def test_deterministic_legacy_backfill_all_precedence_cases():
    """Verify deterministic backfill across all 7 precedence cases:

    1. Canonical blob key only ('artifact:{id}') -> computes sha256 from canonical payload.
    2. Legacy blob key only ('{id}', no collision) -> computes sha256 from legacy payload.
    3. Both canonical and legacy exist and are identical -> computes sha256.
    4. Both canonical and legacy exist and conflict -> canonical key STRICTLY wins!
    5. Legacy blob key exists, but {id} collides with evidence_files.case_id -> skipped (remains NULL).
    6. Orphan record (no blob in either namespace) -> remains NULL.
    7. Existing non-null sha256 -> preserved intact (not overwritten).
    Repeated initialization -> idempotent.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE cases (
                case_id TEXT PRIMARY KEY,
                case_name TEXT NOT NULL,
                investigator TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                evidence_count INTEGER NOT NULL DEFAULT 0,
                artifact_count INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE recovery_runs (
                run_id TEXT PRIMARY KEY,
                case_id TEXT REFERENCES cases(case_id) ON DELETE CASCADE,
                artifact_id TEXT,
                candidate_id TEXT,
                filename TEXT NOT NULL,
                format TEXT NOT NULL,
                status TEXT NOT NULL,
                detection_mode TEXT NOT NULL DEFAULT 'known_file',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                total_input_bytes INTEGER NOT NULL,
                total_verified_bytes INTEGER NOT NULL,
                total_reconstructed_bytes INTEGER NOT NULL,
                total_missing_bytes INTEGER NOT NULL,
                validation_json TEXT NOT NULL DEFAULT '{}',
                confidence_json TEXT NOT NULL DEFAULT '{}',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                output_json TEXT,
                fragments_json TEXT NOT NULL DEFAULT '[]',
                damage_regions_json TEXT NOT NULL DEFAULT '[]',
                reconstruction_steps_json TEXT NOT NULL DEFAULT '[]',
                events_json TEXT NOT NULL DEFAULT '[]'
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE evidence_files (
                case_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE artifacts (
                artifact_id TEXT PRIMARY KEY,
                case_id TEXT REFERENCES cases(case_id) ON DELETE CASCADE,
                run_id TEXT REFERENCES recovery_runs(run_id) ON DELETE SET NULL,
                original_filename TEXT,
                recovered_filename TEXT,
                format TEXT NOT NULL,
                status TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                verified_bytes INTEGER NOT NULL,
                reconstructed_bytes INTEGER NOT NULL,
                missing_bytes INTEGER NOT NULL,
                total_input_bytes INTEGER,
                reconstruction_method TEXT NOT NULL DEFAULT 'NONE',
                validation_status TEXT NOT NULL DEFAULT 'PENDING',
                is_downloadable INTEGER NOT NULL DEFAULT 1,
                download_url TEXT,
                content_preview TEXT,
                category TEXT,
                priority TEXT,
                ai_summary TEXT,
                score_breakdown_json TEXT NOT NULL DEFAULT '{}',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                validation_details_json TEXT NOT NULL DEFAULT '{}',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                fragments_json TEXT,
                damage_regions_json TEXT,
                reconstruction_steps_json TEXT,
                created_at TEXT,
                sha256 TEXT
            );
            """
        )
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

        # 1. Canonical only
        canon_bytes = b"PAYLOAD_CANON_ONLY"
        canon_sha = hashlib.sha256(canon_bytes).hexdigest()
        conn.execute("INSERT INTO artifacts (artifact_id, format, status, confidence_score, verified_bytes, reconstructed_bytes, missing_bytes) VALUES ('art_1', 'txt', 'FULLY_RECOVERED', 100.0, 10, 0, 0);")
        conn.execute("INSERT INTO blobs VALUES ('artifact:art_1', ?, 18, '2026-01-01T00:00:00Z');", (sqlite3.Binary(canon_bytes),))

        # 2. Legacy only (no collision)
        legacy_bytes = b"PAYLOAD_LEGACY_ONLY"
        legacy_sha = hashlib.sha256(legacy_bytes).hexdigest()
        conn.execute("INSERT INTO artifacts (artifact_id, format, status, confidence_score, verified_bytes, reconstructed_bytes, missing_bytes) VALUES ('art_2', 'txt', 'FULLY_RECOVERED', 100.0, 10, 0, 0);")
        conn.execute("INSERT INTO blobs VALUES ('art_2', ?, 19, '2026-01-01T00:00:00Z');", (sqlite3.Binary(legacy_bytes),))

        # 3. Both exist and identical
        ident_bytes = b"PAYLOAD_IDENTICAL"
        ident_sha = hashlib.sha256(ident_bytes).hexdigest()
        conn.execute("INSERT INTO artifacts (artifact_id, format, status, confidence_score, verified_bytes, reconstructed_bytes, missing_bytes) VALUES ('art_3', 'txt', 'FULLY_RECOVERED', 100.0, 10, 0, 0);")
        conn.execute("INSERT INTO blobs VALUES ('artifact:art_3', ?, 17, '2026-01-01T00:00:00Z');", (sqlite3.Binary(ident_bytes),))
        conn.execute("INSERT INTO blobs VALUES ('art_3', ?, 17, '2026-01-01T00:00:00Z');", (sqlite3.Binary(ident_bytes),))

        # 4. Both exist and CONFLICT -> canonical strictly wins!
        canon_win_bytes = b"CANONICAL_WINS"
        legacy_lose_bytes = b"LEGACY_LOSES"
        canon_win_sha = hashlib.sha256(canon_win_bytes).hexdigest()
        conn.execute("INSERT INTO artifacts (artifact_id, format, status, confidence_score, verified_bytes, reconstructed_bytes, missing_bytes) VALUES ('art_4', 'txt', 'FULLY_RECOVERED', 100.0, 10, 0, 0);")
        conn.execute("INSERT INTO blobs VALUES ('artifact:art_4', ?, 14, '2026-01-01T00:00:00Z');", (sqlite3.Binary(canon_win_bytes),))
        conn.execute("INSERT INTO blobs VALUES ('art_4', ?, 12, '2026-01-01T00:00:00Z');", (sqlite3.Binary(legacy_lose_bytes),))

        # 5. Legacy only, but collides with evidence_files.case_id -> MUST NOT backfill
        colliding_bytes = b"EVIDENCE_COLLISION"
        conn.execute("INSERT INTO evidence_files VALUES ('art_5', 'evidence.bin');")
        conn.execute("INSERT INTO artifacts (artifact_id, format, status, confidence_score, verified_bytes, reconstructed_bytes, missing_bytes) VALUES ('art_5', 'txt', 'FULLY_RECOVERED', 100.0, 10, 0, 0);")
        conn.execute("INSERT INTO blobs VALUES ('art_5', ?, 18, '2026-01-01T00:00:00Z');", (sqlite3.Binary(colliding_bytes),))

        # 6. Orphan artifact record (no blobs)
        conn.execute("INSERT INTO artifacts (artifact_id, format, status, confidence_score, verified_bytes, reconstructed_bytes, missing_bytes) VALUES ('art_6', 'txt', 'FULLY_RECOVERED', 100.0, 10, 0, 0);")

        # 7. Pre-existing non-null sha256 -> MUST NOT be overwritten even if blob has different content
        preexisting_sha = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        diff_bytes = b"DIFFERENT_BLOB_CONTENT"
        conn.execute("INSERT INTO artifacts (artifact_id, format, status, confidence_score, verified_bytes, reconstructed_bytes, missing_bytes, sha256) VALUES ('art_7', 'txt', 'FULLY_RECOVERED', 100.0, 10, 0, 0, ?);", (preexisting_sha,))
        conn.execute("INSERT INTO blobs VALUES ('artifact:art_7', ?, 22, '2026-01-01T00:00:00Z');", (sqlite3.Binary(diff_bytes),))

        conn.commit()
        conn.close()

        # Run initialize()
        engine = SqliteEngine(db_path=db_path)
        engine.initialize()

        conn_check = engine.connect()
        cur = conn_check.cursor()

        # Verify Case 1: Canonical only
        cur.execute("SELECT sha256 FROM artifacts WHERE artifact_id = 'art_1';")
        assert cur.fetchone()[0] == canon_sha

        # Verify Case 2: Legacy only
        cur.execute("SELECT sha256 FROM artifacts WHERE artifact_id = 'art_2';")
        assert cur.fetchone()[0] == legacy_sha

        # Verify Case 3: Both identical
        cur.execute("SELECT sha256 FROM artifacts WHERE artifact_id = 'art_3';")
        assert cur.fetchone()[0] == ident_sha

        # Verify Case 4: Both conflict -> canonical strictly won!
        cur.execute("SELECT sha256 FROM artifacts WHERE artifact_id = 'art_4';")
        assert cur.fetchone()[0] == canon_win_sha

        # Verify Case 5: Evidence collision -> remained NULL!
        cur.execute("SELECT sha256 FROM artifacts WHERE artifact_id = 'art_5';")
        assert cur.fetchone()[0] is None

        # Verify Case 6: Orphan -> remained NULL!
        cur.execute("SELECT sha256 FROM artifacts WHERE artifact_id = 'art_6';")
        assert cur.fetchone()[0] is None

        # Verify Case 7: Preexisting hash -> preserved intact!
        cur.execute("SELECT sha256 FROM artifacts WHERE artifact_id = 'art_7';")
        assert cur.fetchone()[0] == preexisting_sha

        # Verify Idempotency: run initialize() a second time
        conn_check.close()
        engine.initialize()

        conn_check2 = engine.connect()
        cur2 = conn_check2.cursor()
        cur2.execute("SELECT sha256 FROM artifacts WHERE artifact_id = 'art_4';")
        assert cur2.fetchone()[0] == canon_win_sha
        cur2.execute("SELECT sha256 FROM artifacts WHERE artifact_id = 'art_7';")
        assert cur2.fetchone()[0] == preexisting_sha
        conn_check2.close()
        engine.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


# ── Step 6B.2B Finding C: Pipeline A Atomic Artifact Persistence Tests ─────────

def test_pipeline_a_atomic_artifact_persistence_sqlite():
    """Verify store_case_artifact persists artifact, recovery run, link,

    and binary payload in a single atomic transaction.
    """
    from datetime import datetime, timezone
    from backend.app.models.recovery_run import RecoveryRun

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        sqlite_engine = SqliteEngine(db_path=db_path)
        sqlite_engine.initialize()
        sql_store = SqliteStore(engine=sqlite_engine)

        case = sql_store.create_case("CASE-ATOMIC-01", description="Atomic persistence test")
        case_id = case.case_id

        art_id = "art_atomic_test_01"
        run_id = "run_atomic_test_01"
        payload = b'{"atomic":"success","verified":true}'
        payload_sha = hashlib.sha256(payload).hexdigest()

        art = ArtifactResponse(
            artifact_id=art_id,
            case_id=case_id,
            format="json",
            size_bytes=len(payload),
            confidence_score=95,
            score_breakdown=ConfidenceBreakdownSchema(
                header_validity=20,
                footer_validity=20,
                structural_validation=20,
                size_plausibility=15,
                reconstruction_integrity=20,
                total=95,
            ),
            status="FULLY_RECOVERED",
            provenance=ArtifactProvenanceSchema(
                verified_bytes=len(payload),
                reconstructed_bytes=0,
                missing_bytes=0,
                reconstruction_method="DIRECT",
                validation_status="PASSED",
            ),
            sha256=payload_sha,
            metadata={"original_filename": "data.json", "sha256": payload_sha},
        )

        now = datetime.now(timezone.utc)
        run = RecoveryRun(
            run_id=run_id,
            case_id=case_id,
            artifact_id=art_id,
            filename="data.json",
            format="json",
            status="FULLY_RECOVERED",
            started_at=now,
            completed_at=now,
            total_input_bytes=len(payload),
            total_verified_bytes=len(payload),
            total_reconstructed_bytes=0,
            total_missing_bytes=0,
        )

        # Execute atomic store
        persisted_art = sql_store.store_case_artifact(artifact=art, content=payload, run=run)
        assert persisted_art.artifact_id == art_id

        # Verify all four entities are present and consistent
        fetched_art = sql_store.get_artifact(art_id)
        assert fetched_art is not None
        assert fetched_art.sha256 == payload_sha

        fetched_bytes = sql_store.get_artifact_bytes(art_id)
        assert fetched_bytes == payload

        fetched_run = sql_store.get_recovery_run(run_id)
        assert fetched_run is not None
        assert fetched_run.artifact_id == art_id

        linked_run = sql_store.get_recovery_run_by_artifact(art_id)
        assert linked_run is not None
        assert linked_run.run_id == run_id

        sqlite_engine.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_pipeline_a_atomic_rollback_on_failure_injection():
    """Verify that if an error occurs mid-way through store_case_artifact,

    the entire transaction is rolled back and no partial state (artifact,
    run, or payload) is persisted.
    """
    from datetime import datetime, timezone
    from backend.app.models.recovery_run import RecoveryRun

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        sqlite_engine = SqliteEngine(db_path=db_path)
        sqlite_engine.initialize()
        sql_store = SqliteStore(engine=sqlite_engine)

        case = sql_store.create_case("CASE-ROLLBACK-01", description="Atomic rollback test")
        case_id = case.case_id

        art_id = "art_rollback_test_01"
        run_id = "run_rollback_test_01"
        payload = b'{"rollback":"test"}'

        art = ArtifactResponse(
            artifact_id=art_id,
            case_id=case_id,
            format="json",
            size_bytes=len(payload),
            confidence_score=90,
            score_breakdown=ConfidenceBreakdownSchema(
                header_validity=20,
                footer_validity=20,
                structural_validation=20,
                size_plausibility=15,
                reconstruction_integrity=15,
                total=90,
            ),
            status="FULLY_RECOVERED",
            provenance=ArtifactProvenanceSchema(
                verified_bytes=len(payload),
                reconstructed_bytes=0,
                missing_bytes=0,
                reconstruction_method="DIRECT",
                validation_status="PASSED",
            ),
            metadata={"original_filename": "rollback.json"},
        )

        now = datetime.now(timezone.utc)
        run = RecoveryRun(
            run_id=run_id,
            case_id=case_id,
            artifact_id=art_id,
            filename="data.json",
            format="json",
            status="FULLY_RECOVERED",
            started_at=now,
            completed_at=now,
            total_input_bytes=len(payload),
            total_verified_bytes=len(payload),
            total_reconstructed_bytes=0,
            total_missing_bytes=0,
        )

        # Inject failure during store_artifact_bytes_on_cursor
        original_store_bytes = sql_store._store_artifact_bytes_on_cursor
        def failing_store_bytes(cursor, artifact_id, content, created_at=None):
            raise RuntimeError("Injected disk failure during blob persistence")

        sql_store._store_artifact_bytes_on_cursor = failing_store_bytes

        with pytest.raises(RuntimeError, match="Injected disk failure"):
            sql_store.store_case_artifact(artifact=art, content=payload, run=run)

        # Restore original function
        sql_store._store_artifact_bytes_on_cursor = original_store_bytes

        # Verify COMPLETE rollback: nothing in artifacts, recovery_runs, or blobs!
        assert sql_store.get_artifact(art_id) is None
        assert sql_store.get_artifact_bytes(art_id) is None
        assert sql_store.get_recovery_run(run_id) is None
        assert sql_store.get_recovery_run_by_artifact(art_id) is None

        sqlite_engine.close()
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)
