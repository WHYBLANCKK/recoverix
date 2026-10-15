"""
sqlite_blob_store.py — SQLite-backed implementation of the BlobStore contract.

Stores raw binary payloads (evidence content, recovered artifact bytes) directly
in SQLite BLOB storage with exact binary fidelity, atomic upserts, and transactional isolation.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional

from backend.app.storage.sqlite_engine import SqliteEngine


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

            # Fallback to unprefixed key for backward compatibility with legacy databases
            if self._namespace:
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
