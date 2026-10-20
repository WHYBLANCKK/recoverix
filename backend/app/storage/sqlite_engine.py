"""
sqlite_engine.py — SQLite engine and schema management for Recoverix.

Provides an explicit, low-level SQLite database engine abstraction supporting:
- Configurable database paths (default, environment variable, or in-memory)
- Automatic directory creation for file-backed databases
- Production-grade PRAGMA settings (WAL mode, foreign keys, busy timeout, synchronous NORMAL)
- Safe in-memory database sharing across connections within an engine instance
- Idempotent schema creation and management
- Deterministic transaction context management with atomic commit and rollback
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from typing import Generator, Optional


DEFAULT_DB_PATH = "data/recoverix.db"
ENV_DB_PATH_KEY = "RECOVERIX_DB_PATH"
DEFAULT_TIMEOUT = 5.0
DEFAULT_BUSY_TIMEOUT_MS = 5000

SCHEMA_DDL = """
-- 1. Cases
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL
);

-- 2. Evidence Metadata
CREATE TABLE IF NOT EXISTS evidence_files (
    case_id TEXT PRIMARY KEY REFERENCES cases(case_id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    chunk_size INTEGER NOT NULL DEFAULT 4096,
    total_chunks INTEGER NOT NULL DEFAULT 0
);

-- 3. Evidence Chunks
CREATE TABLE IF NOT EXISTS evidence_chunks (
    chunk_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_chunks_case_idx ON evidence_chunks(case_id, chunk_index);

-- 4. Canonical Recovery Runs (Immutable Traces)
CREATE TABLE IF NOT EXISTS recovery_runs (
    run_id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(case_id) ON DELETE SET NULL,
    artifact_id TEXT,
    candidate_id TEXT,
    filename TEXT NOT NULL,
    format TEXT NOT NULL,
    status TEXT NOT NULL,
    detection_mode TEXT NOT NULL DEFAULT 'known_file',
    case_name TEXT,
    investigator TEXT,
    notes TEXT,
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
CREATE INDEX IF NOT EXISTS idx_recovery_runs_case_id ON recovery_runs(case_id);
CREATE INDEX IF NOT EXISTS idx_recovery_runs_status ON recovery_runs(status);

-- 5. Unified Artifacts
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(case_id) ON DELETE CASCADE,
    run_id TEXT REFERENCES recovery_runs(run_id) ON DELETE SET NULL,
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
    created_at TEXT,
    sha256 TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifacts_case_id ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_run_id ON artifacts(run_id);

-- 6. Artifact-to-Run Linkage Index (Authoritative)
CREATE TABLE IF NOT EXISTS artifact_runs (
    artifact_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES recovery_runs(run_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_artifact_runs_run ON artifact_runs(run_id);

-- 7. Dedicated Binary Payload Store
CREATE TABLE IF NOT EXISTS blobs (
    blob_key TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _safe_add_column(conn: sqlite3.Connection, table: str, col: str, col_type: str) -> None:
    """Add column to table idempotently and race-safely against concurrent processes.

    Guarantees:
    1. Inspects table schema first; skips ALTER TABLE if column exists.
    2. If ALTER TABLE fails with OperationalError, re-inspects table schema.
    3. Treats duplicate column errors as benign only if the column is confirmed present.
    4. Never swallows unrelated OperationalError exceptions.
    """
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table});")
    existing_cols = {row[1] for row in cur.fetchall()}
    if col in existing_cols:
        return

    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type};")
    except sqlite3.OperationalError as e:
        cur.execute(f"PRAGMA table_info({table});")
        verified_cols = {row[1] for row in cur.fetchall()}
        if col in verified_cols and "duplicate column name" in str(e).lower():
            return
        raise


class SqliteEngine:
    """Explicit SQLite database engine abstraction for Recoverix platform.

    Encapsulates connection lifecycle, WAL configuration, PRAGMA enforcement,
    and transaction management.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the SQLite engine.

        Args:
            db_path: Path to database file, ':memory:' for transient in-memory,
                or None to use RECOVERIX_DB_PATH / default.
            timeout: Connection timeout in seconds.
        """
        if db_path is None:
            db_path = os.environ.get(ENV_DB_PATH_KEY, DEFAULT_DB_PATH)

        self.db_path = db_path
        self.timeout = timeout
        self._is_memory = (self.db_path == ":memory:")
        self._lock = threading.RLock()
        self._closed = False

        if self._is_memory:
            # Use unique URI shared cache for this engine instance so multiple
            # connections/transactions within this engine access the same in-memory DB.
            self._uri: Optional[str] = (
                f"file:recoverix_mem_{id(self)}_{uuid.uuid4().hex}?mode=memory&cache=shared"
            )
            # Hold a persistent connection to keep the in-memory database alive
            # until engine.close() is called.
            self._keepalive: Optional[sqlite3.Connection] = sqlite3.connect(
                self._uri,
                uri=True,
                isolation_level=None,
            )
        else:
            self._uri = None
            self._keepalive = None
            # Ensure parent directory exists for file-backed database
            parent = os.path.dirname(os.path.abspath(self.db_path))
            if parent:
                os.makedirs(parent, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        """Create and configure a new SQLite connection with required PRAGMAs.

        Returns:
            A configured sqlite3.Connection.
        """
        if self._closed:
            raise RuntimeError("SqliteEngine is closed")

        if self._is_memory and self._uri:
            conn = sqlite3.connect(
                self._uri,
                uri=True,
                timeout=self.timeout,
                check_same_thread=False,
                isolation_level=None,
            )
        else:
            conn = sqlite3.connect(
                self.db_path,
                timeout=self.timeout,
                check_same_thread=False,
                isolation_level=None,
            )

        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(f"PRAGMA busy_timeout = {DEFAULT_BUSY_TIMEOUT_MS};")

        if not self._is_memory:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")

        return conn

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        """Context manager providing an atomic SQLite transaction.

        Yields:
            sqlite3.Cursor within an active transaction.

        On clean block exit, commits the transaction.
        On exception, rolls back the transaction and re-raises.
        Always closes the cursor and connection deterministically.
        """
        if self._closed:
            raise RuntimeError("SqliteEngine is closed")

        with self._lock:
            conn = self.connect()
            cursor = conn.cursor()
            try:
                conn.execute("BEGIN")
                yield cursor
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            finally:
                cursor.close()
                conn.close()

    def initialize(self) -> None:
        """Idempotently initialize all database tables and indexes."""
        if self._closed:
            raise RuntimeError("SqliteEngine is closed")

        with self._lock:
            conn = self.connect()
            try:
                conn.executescript(SCHEMA_DDL)
                # Race-safe defensive column migrations using _safe_add_column
                for col in ("case_name", "investigator", "notes"):
                    _safe_add_column(conn, "recovery_runs", col, "TEXT")

                _safe_add_column(conn, "artifacts", "created_at", "TEXT")
                _safe_add_column(conn, "artifacts", "sha256", "TEXT")

                # Safe, deterministic backfill of sha256 for legacy artifact records where sha256 is NULL.
                # Prioritizes canonical 'artifact:{id}' key over legacy '{id}' key.
                # If only legacy key exists, checks for collision with evidence_files.
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT
                        a.artifact_id,
                        bc.data AS canon_data,
                        bl.data AS legacy_data,
                        ef.case_id AS colliding_case_id
                    FROM artifacts a
                    LEFT JOIN blobs bc ON bc.blob_key = ('artifact:' || a.artifact_id)
                    LEFT JOIN blobs bl ON bl.blob_key = a.artifact_id
                    LEFT JOIN evidence_files ef ON ef.case_id = a.artifact_id
                    WHERE a.sha256 IS NULL;
                    """
                )
                legacy_rows = cur.fetchall()
                for legacy_row in legacy_rows:
                    art_id = legacy_row[0]
                    canon_data = legacy_row[1]
                    legacy_data = legacy_row[2]
                    colliding_case_id = legacy_row[3]

                    target_bytes: Optional[bytes] = None
                    if canon_data is not None:
                        target_bytes = bytes(canon_data)
                    elif legacy_data is not None and colliding_case_id is None:
                        target_bytes = bytes(legacy_data)

                    if target_bytes is not None:
                        digest = hashlib.sha256(target_bytes).hexdigest()
                        conn.execute(
                            "UPDATE artifacts SET sha256 = ? WHERE artifact_id = ? AND sha256 IS NULL;",
                            (digest, art_id),
                        )
            finally:
                conn.close()

    def clear_all_tables(self) -> None:
        """Clear all stored data across all tables respecting foreign key deletion order."""
        if self._closed:
            raise RuntimeError("SqliteEngine is closed")

        with self.transaction() as cursor:
            cursor.execute("DELETE FROM artifact_runs;")
            cursor.execute("DELETE FROM artifacts;")
            cursor.execute("DELETE FROM recovery_runs;")
            cursor.execute("DELETE FROM evidence_chunks;")
            cursor.execute("DELETE FROM evidence_files;")
            cursor.execute("DELETE FROM cases;")
            cursor.execute("DELETE FROM blobs;")

    def close(self) -> None:
        """Close the engine and release any held resources."""
        with self._lock:
            if not self._closed:
                if self._keepalive is not None:
                    self._keepalive.close()
                    self._keepalive = None
                self._closed = True

    def __enter__(self) -> SqliteEngine:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()
