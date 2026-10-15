"""
sqlite_blob_store.py — SQLite-backed implementation of the BlobStore contract.

Stores raw binary payloads (evidence content, recovered artifact bytes) directly
in SQLite BLOB storage with exact binary fidelity, atomic upserts, and transactional isolation.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from backend.app.storage.sqlite_engine import SqliteEngine


def _is_valid_sha256(val: object) -> bool:
    """Check if value is a valid 64-character hexadecimal SHA-256 string."""
    if not isinstance(val, str) or len(val) != 64:
        return False
    try:
        int(val, 16)
        return True
    except ValueError:
        return False


class SqliteBlobStore:
    """Thread-safe SQLite implementation of the BlobStore contract with domain isolation support."""

    def __init__(self, engine: SqliteEngine, namespace: str = "") -> None:
        """Initialize with a SqliteEngine instance and optional namespace prefix."""
        if not isinstance(engine, SqliteEngine):
            raise TypeError("engine must be an instance of SqliteEngine")
        self._engine = engine
        self._namespace = namespace

    def _make_key(self, key: str) -> str:
        """Construct namespaced key for storage while validating."""
        if not isinstance(key, str) or not key.strip():
            raise ValueError("Blob key must be a non-empty string")
        return f"{self._namespace}{key}" if self._namespace else key

    def _is_legacy_key_owned(self, cursor: sqlite3.Cursor, key: str) -> bool:
        """Verify whether an unprefixed legacy blob key safely belongs to this namespace domain."""
        if not self._namespace:
            return True

        if self._namespace == "evidence:":
            try:
                cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_files';")
                if cursor.fetchone() is None:
                    return False

                cursor.execute("PRAGMA table_info(evidence_files);")
                ev_cols = {r["name"] for r in cursor.fetchall()}
                if "sha256" not in ev_cols:
                    return False

                has_size = "file_size" in ev_cols
                query = "SELECT sha256, file_size FROM evidence_files WHERE case_id = ?;" if has_size else "SELECT sha256 FROM evidence_files WHERE case_id = ?;"
                cursor.execute(query, (key,))
                ev_row = cursor.fetchone()
                if ev_row is None:
                    return False

                expected_sha = ev_row["sha256"] if isinstance(ev_row, sqlite3.Row) else ev_row[0]
                expected_size = (ev_row["file_size"] if isinstance(ev_row, sqlite3.Row) else ev_row[1]) if has_size else None

                if not _is_valid_sha256(expected_sha):
                    return False

                cursor.execute("SELECT data FROM blobs WHERE blob_key = ?;", (key,))
                b_row = cursor.fetchone()
                if b_row is None:
                    return False
                blob_bytes = bytes(b_row["data"] if isinstance(b_row, sqlite3.Row) else b_row[0])

                if hashlib.sha256(blob_bytes).hexdigest().lower() != expected_sha.lower():
                    return False
                if expected_size is not None and expected_size >= 0 and len(blob_bytes) != expected_size:
                    return False

                return True
            except sqlite3.OperationalError:
                return False

        elif self._namespace == "artifact:":
            try:
                cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='artifacts';")
                if cursor.fetchone() is None:
                    return False
                cursor.execute("SELECT 1 FROM artifacts WHERE artifact_id = ?;", (key,))
                if cursor.fetchone() is None:
                    return False

                # Check if it collides with evidence_files
                cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_files';")
                if cursor.fetchone() is not None:
                    cursor.execute("SELECT 1 FROM evidence_files WHERE case_id = ?;", (key,))
                    if cursor.fetchone() is not None:
                        # Collision: legacy artifact payload was collapsed/ambiguous
                        return False

                return True
            except sqlite3.OperationalError:
                return False

        return True

    def put(self, key: str, data: bytes) -> None:
        """Store a binary blob under key with atomic overwrite semantics."""
        full_key = self._make_key(key)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Blob data must be bytes-like")

        raw_bytes = bytes(data)
        size_bytes = len(raw_bytes)
        created_at = datetime.now(timezone.utc).isoformat()

        with self._engine.transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO blobs (blob_key, data, size_bytes, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(blob_key) DO UPDATE SET
                    data = excluded.data,
                    size_bytes = excluded.size_bytes,
                    created_at = excluded.created_at;
                """,
                (full_key, sqlite3.Binary(raw_bytes), size_bytes, created_at),
            )

    def get(self, key: str) -> Optional[bytes]:
        """Retrieve binary blob for key, or None if not found."""
        if not isinstance(key, str) or not key.strip():
            return None

        full_key = self._make_key(key)

        with self._engine.transaction() as cursor:
            cursor.execute("SELECT data FROM blobs WHERE blob_key = ?;", (full_key,))
            row = cursor.fetchone()
            if row is not None:
                val = row["data"] if isinstance(row, sqlite3.Row) else row[0]
                return bytes(val)

            # Fallback to unprefixed key for backward compatibility with legacy databases,
            # strictly validated by domain ownership to prevent cross-namespace leakage.
            if self._namespace:
                if not self._is_legacy_key_owned(cursor, key):
                    return None
                cursor.execute("SELECT data FROM blobs WHERE blob_key = ?;", (key,))
                legacy_row = cursor.fetchone()
                if legacy_row is not None:
                    val = legacy_row["data"] if isinstance(legacy_row, sqlite3.Row) else legacy_row[0]
                    return bytes(val)

            return None

    def delete(self, key: str) -> bool:
        """Delete binary blob for key. Returns True if deleted, False if not found."""
        if not isinstance(key, str) or not key.strip():
            return False

        full_key = self._make_key(key)

        with self._engine.transaction() as cursor:
            cursor.execute("DELETE FROM blobs WHERE blob_key = ?;", (full_key,))
            deleted = cursor.rowcount > 0
            if not deleted and self._namespace:
                if not self._is_legacy_key_owned(cursor, key):
                    return False
                cursor.execute("DELETE FROM blobs WHERE blob_key = ?;", (key,))
                deleted = cursor.rowcount > 0
            return deleted

    def exists(self, key: str) -> bool:
        """Check if binary blob exists for key."""
        if not isinstance(key, str) or not key.strip():
            return False

        full_key = self._make_key(key)

        with self._engine.transaction() as cursor:
            cursor.execute("SELECT 1 FROM blobs WHERE blob_key = ? LIMIT 1;", (full_key,))
            if cursor.fetchone() is not None:
                return True
            if self._namespace:
                if not self._is_legacy_key_owned(cursor, key):
                    return False
                cursor.execute("SELECT 1 FROM blobs WHERE blob_key = ? LIMIT 1;", (key,))
                return cursor.fetchone() is not None
            return False

    def clear(self) -> None:
        """Clear all stored blobs for this namespace atomically."""
        with self._engine.transaction() as cursor:
            if self._namespace:
                cursor.execute("DELETE FROM blobs WHERE blob_key LIKE ?;", (f"{self._namespace}%",))
            else:
                cursor.execute("DELETE FROM blobs;")

    def __len__(self) -> int:
        """Return the count of stored blobs for this namespace."""
        with self._engine.transaction() as cursor:
            if self._namespace:
                cursor.execute("SELECT COUNT(*) FROM blobs WHERE blob_key LIKE ?;", (f"{self._namespace}%",))
            else:
                cursor.execute("SELECT COUNT(*) FROM blobs;")
            row = cursor.fetchone()
            return int(row[0]) if row else 0
