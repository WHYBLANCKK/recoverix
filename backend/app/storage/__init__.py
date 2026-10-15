"""
backend/app/storage/__init__.py — Storage and repository exports for Recoverix platform.
"""

from backend.app.storage.contracts import (
    BlobStore,
    CaseRepository,
    ArtifactRepository,
    RecoveryRunRepository,
)
from backend.app.storage.blob_store import InMemoryBlobStore
from backend.app.storage.memory_store import InMemoryStore, MAX_EVIDENCE_SIZE
from backend.app.storage.sqlite_engine import SqliteEngine
from backend.app.storage.sqlite_blob_store import SqliteBlobStore
from backend.app.storage.sqlite_store import SqliteStore, migrate_legacy_blobs

__all__ = [
    "BlobStore",
    "CaseRepository",
    "ArtifactRepository",
    "RecoveryRunRepository",
    "InMemoryBlobStore",
    "InMemoryStore",
    "MAX_EVIDENCE_SIZE",
    "SqliteEngine",
    "SqliteBlobStore",
    "SqliteStore",
    "migrate_legacy_blobs",
]
