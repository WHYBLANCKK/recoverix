"""
contracts.py — Repository and storage contracts for Recoverix platform.

Defines protocol interfaces for:
- CaseRepository: Case creation, lookup, listing, evidence metadata, and chunks.
- ArtifactRepository: Unified artifact storage and retrieval (cases and standalone).
- RecoveryRunRepository: Canonical recovery execution traces and artifact linkage.
- BlobStore: Raw binary payload storage (evidence and recovered bytes).
"""

from __future__ import annotations

from typing import Protocol, List, Optional, runtime_checkable
from backend.app.models.case import CaseResponse, EvidenceMetadata
from backend.app.models.artifact import ArtifactResponse, ArtifactRecord
from backend.app.models.recovery_run import RecoveryRun
from backend.app.ingestion import Chunk


@runtime_checkable
class BlobStore(Protocol):
    """Storage interface for raw binary blobs (evidence and artifact bytes)."""

    def put(self, key: str, data: bytes) -> None:
        """Store a binary blob under key."""
        ...

    def get(self, key: str) -> Optional[bytes]:
        """Retrieve binary blob for key, or None if not found."""
        ...

    def delete(self, key: str) -> bool:
        """Delete binary blob for key. Returns True if deleted, False if not found."""
        ...

    def exists(self, key: str) -> bool:
        """Check if binary blob exists for key."""
        ...

    def clear(self) -> None:
        """Clear all stored blobs."""
        ...


@runtime_checkable
class CaseRepository(Protocol):
    """Repository interface for forensic cases and evidence metadata."""

    def create_case(self, name: str, description: Optional[str] = None) -> CaseResponse:
        """Create and store a new forensic case."""
        ...

    def get_case(self, case_id: str) -> Optional[CaseResponse]:
        """Retrieve case by case_id."""
        ...

    def list_cases(self) -> List[CaseResponse]:
        """List all stored cases."""
        ...

    def add_evidence(self, case_id: str, filename: str, content: bytes) -> EvidenceMetadata:
        """Ingest and record evidence metadata for a case."""
        ...

    def get_evidence_bytes(self, case_id: str) -> Optional[bytes]:
        """Retrieve evidence raw bytes for a case."""
        ...

    def get_evidence_chunks(self, case_id: str) -> Optional[List[Chunk]]:
        """Retrieve evidence chunks for a case."""
        ...


@runtime_checkable
class ArtifactRepository(Protocol):
    """Unified repository interface for recovered artifacts.

    Handles both case-associated recovery artifacts (Pipeline A) and
    standalone file recovery artifacts (Pipeline B).
    """

    def add_artifact(self, artifact: ArtifactResponse) -> ArtifactResponse:
        """Store a case-associated recovered artifact."""
        ...

    def save_artifact_record(self, record: ArtifactRecord) -> ArtifactRecord:
        """Store an internal ArtifactRecord directly."""
        ...

    def get_artifact(self, artifact_id: str) -> Optional[ArtifactResponse]:
        """Retrieve artifact as API-facing ArtifactResponse by artifact_id."""
        ...

    def get_artifact_record(self, artifact_id: str) -> Optional[ArtifactRecord]:
        """Retrieve internal ArtifactRecord by artifact_id."""
        ...

    def get_case_artifacts(self, case_id: str) -> Optional[List[ArtifactResponse]]:
        """Retrieve all artifacts associated with a case."""
        ...

    def store_artifact_bytes(self, artifact_id: str, content: bytes) -> None:
        """Store raw recovered bytes for an artifact."""
        ...

    def get_artifact_bytes(self, artifact_id: str) -> Optional[bytes]:
        """Retrieve raw recovered bytes for an artifact."""
        ...

    def delete_artifact(self, artifact_id: str) -> bool:
        """Delete an artifact by artifact_id. Returns True if deleted, False if not found."""
        ...


@runtime_checkable
class RecoveryRunRepository(Protocol):
    """Repository interface for canonical RecoveryRun execution traces."""

    def add_recovery_run(self, run: RecoveryRun) -> RecoveryRun:
        """Persist a canonical RecoveryRun exactly once."""
        ...

    def get_recovery_run(self, run_id: str) -> Optional[RecoveryRun]:
        """Retrieve RecoveryRun by run_id."""
        ...

    def list_recovery_runs(self) -> List[RecoveryRun]:
        """List all stored RecoveryRun instances."""
        ...

    def link_artifact_to_run(self, artifact_id: str, run_id: str) -> None:
        """Establish relationship between an artifact and a RecoveryRun."""
        ...

    def get_recovery_run_by_artifact(self, artifact_id: str) -> Optional[RecoveryRun]:
        """Retrieve RecoveryRun associated with an artifact_id."""
        ...
