"""
memory_store.py — In-memory repository implementation for Recoverix platform.

Implements CaseRepository, ArtifactRepository, RecoveryRunRepository,
and orchestrates BlobStore instances for evidence and recovered bytes.
"""

from __future__ import annotations

import hashlib
import time
import uuid
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from backend.app.models.case import CaseResponse, EvidenceMetadata
from backend.app.models.artifact import ArtifactResponse, ArtifactRecord
from backend.app.models.recovery_run import RecoveryRun
from backend.app.ingestion import compute_metadata, chunk_evidence, Chunk
from backend.app.storage.blob_store import InMemoryBlobStore
from backend.app.storage.contracts import (
    BlobStore,
    CaseRepository,
    ArtifactRepository,
    RecoveryRunRepository,
)

MAX_EVIDENCE_SIZE = 5 * 1024 * 1024  # 5 MiB limit


class InMemoryStore(CaseRepository, ArtifactRepository, RecoveryRunRepository):
    """Thread-safe in-memory repository conforming to CaseRepository, ArtifactRepository,
    RecoveryRunRepository, and managing BlobStore instances.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cases: Dict[str, dict] = {}
        self._chunks: Dict[str, List[Chunk]] = {}
        self._artifacts: Dict[str, ArtifactRecord] = {}
        self._case_artifacts: Dict[str, List[str]] = {}
        self._recovery_runs: Dict[str, RecoveryRun] = {}
        self._artifact_runs: Dict[str, str] = {}
        self._artifact_timestamps: Dict[str, float] = {}

        # Dedicated blob stores for binary data
        self._evidence_blobs = InMemoryBlobStore()
        self._artifact_blobs = InMemoryBlobStore()


    # ── Subsystem Accessors ──────────────────────────────────────────────

    @property
    def cases(self) -> CaseRepository:
        """Case repository access."""
        return self

    @property
    def artifacts(self) -> ArtifactRepository:
        """Artifact repository access."""
        return self

    @property
    def recovery_runs(self) -> RecoveryRunRepository:
        """RecoveryRun repository access."""
        return self

    @property
    def evidence_blobs(self) -> BlobStore:
        """Evidence raw byte blob store."""
        return self._evidence_blobs

    @property
    def artifact_blobs(self) -> BlobStore:
        """Recovered artifact raw byte blob store."""
        return self._artifact_blobs

    # ── Lifecycle / Maintenance ──────────────────────────────────────────

    def clear(self) -> None:
        """Clear all stored state (for test isolation)."""
        with self._lock:
            self._cases.clear()
            self._chunks.clear()
            self._artifacts.clear()
            self._case_artifacts.clear()
            self._recovery_runs.clear()
            self._artifact_runs.clear()
            self._artifact_timestamps.clear()
            self._evidence_blobs.clear()
            self._artifact_blobs.clear()

    # ── CaseRepository Implementation ────────────────────────────────────

    def create_case(self, name: str, description: Optional[str] = None) -> CaseResponse:
        """Create and store a new forensic case.

        Raises:
            ValueError: If name is empty or invalid.
        """
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Case name cannot be empty or invalid string")

        case_id = f"case_{uuid.uuid4().hex[:8]}"
        created_at = datetime.now(timezone.utc).isoformat()

        with self._lock:
            case_data = {
                "case_id": case_id,
                "name": name.strip(),
                "description": description.strip() if description else None,
                "created_at": created_at,
                "evidence": None,
                "artifact_count": 0,
            }
            self._cases[case_id] = case_data
            self._case_artifacts[case_id] = []
            return CaseResponse(**case_data)

    def get_case(self, case_id: str) -> Optional[CaseResponse]:
        """Retrieve case response model by case_id."""
        with self._lock:
            case_data = self._cases.get(case_id)
            if case_data is None:
                return None

            # Recalculate artifact_count from registered artifacts
            case_copy = dict(case_data)
            case_copy["artifact_count"] = len(self._case_artifacts.get(case_id, []))
            return CaseResponse(**case_copy)

    def list_cases(self) -> List[CaseResponse]:
        """List all stored cases."""
        with self._lock:
            res: List[CaseResponse] = []
            for cid, cdata in self._cases.items():
                ccopy = dict(cdata)
                ccopy["artifact_count"] = len(self._case_artifacts.get(cid, []))
                res.append(CaseResponse(**ccopy))
            return res

    def add_evidence(self, case_id: str, filename: str, content: bytes) -> EvidenceMetadata:
        """Add uploaded evidence bytes to a case using ingestion module.

        Raises:
            KeyError: If case_id does not exist.
            ValueError: If file size is 0 (empty) or exceeds MAX_EVIDENCE_SIZE.
        """
        with self._lock:
            if case_id not in self._cases:
                raise KeyError(f"Case '{case_id}' not found")

            if not content or len(content) == 0:
                raise ValueError("EMPTY_FILE")

            if len(content) > MAX_EVIDENCE_SIZE:
                raise ValueError("FILE_TOO_LARGE")

            ingestion_meta = compute_metadata(content, filename=filename or "evidence.img")
            chunks = chunk_evidence(content)

            meta = EvidenceMetadata(
                filename=ingestion_meta.filename,
                file_size=ingestion_meta.size_bytes,
                uploaded_at=datetime.now(timezone.utc).isoformat(),
                sha256=ingestion_meta.sha256,
            )

            self._cases[case_id]["evidence"] = meta
            self._evidence_blobs.put(case_id, content)
            self._chunks[case_id] = chunks
            return meta

    def get_evidence_bytes(self, case_id: str) -> Optional[bytes]:
        """Get uploaded evidence bytes for a case from evidence BlobStore."""
        return self._evidence_blobs.get(case_id)

    def get_evidence_chunks(self, case_id: str) -> Optional[List[Chunk]]:
        """Get uploaded evidence chunks for a case."""
        with self._lock:
            return self._chunks.get(case_id)

    # ── ArtifactRepository Implementation ────────────────────────────────

    def add_artifact(self, artifact: ArtifactResponse) -> ArtifactResponse:
        """Store a recovered artifact under a case (Pipeline A).

        Raises:
            KeyError: If case_id is not registered.
        """
        with self._lock:
            if artifact.case_id not in self._cases:
                raise KeyError(f"Case '{artifact.case_id}' not found")

            record = ArtifactRecord.from_artifact_response(artifact)
            self._artifacts[artifact.artifact_id] = record

            if artifact.artifact_id not in self._case_artifacts[artifact.case_id]:
                self._case_artifacts[artifact.case_id].append(artifact.artifact_id)

            # Establish artifact_id -> run_id linkage if run_id is present
            if record.run_id:
                self._artifact_runs[artifact.artifact_id] = record.run_id
                if record.run_id in self._recovery_runs:
                    run = self._recovery_runs[record.run_id]
                    if not run.artifact_id:
                        run.artifact_id = artifact.artifact_id

            self._cases[artifact.case_id]["artifact_count"] = len(self._case_artifacts[artifact.case_id])
            return artifact

    def store_case_artifact(
        self,
        artifact: ArtifactResponse,
        content: bytes,
        run: Optional[RecoveryRun] = None,
    ) -> ArtifactResponse:
        """Atomically persist a case-associated recovered artifact, its raw bytes, and optional recovery run."""
        with self._lock:
            if artifact.case_id not in self._cases:
                raise KeyError(f"Case '{artifact.case_id}' not found")

            content_sha = hashlib.sha256(content).hexdigest() if content else None
            if content_sha:
                artifact.sha256 = content_sha
                if artifact.metadata is not None:
                    artifact.metadata["sha256"] = content_sha

            record = ArtifactRecord.from_artifact_response(artifact)
            if content_sha:
                record.sha256 = content_sha
                if record.metadata is not None:
                    record.metadata["sha256"] = content_sha

            if run is not None:
                record.run_id = run.run_id
                if artifact.metadata is None:
                    artifact.metadata = {}
                artifact.metadata["run_id"] = run.run_id
                run.artifact_id = artifact.artifact_id
                self._recovery_runs[run.run_id] = run
                self._artifact_runs[artifact.artifact_id] = run.run_id

            self._artifacts[artifact.artifact_id] = record
            if artifact.artifact_id not in self._case_artifacts[artifact.case_id]:
                self._case_artifacts[artifact.case_id].append(artifact.artifact_id)
            self._cases[artifact.case_id]["artifact_count"] = len(self._case_artifacts[artifact.case_id])

            self._artifact_blobs.put(artifact.artifact_id, content)
            return artifact

    def save_artifact_record(self, record: ArtifactRecord) -> ArtifactRecord:
        """Directly store an internal ArtifactRecord (Pipeline B or internal ingestion)."""
        with self._lock:
            self._artifacts[record.artifact_id] = record
            if record.artifact_id not in self._artifact_timestamps:
                self._artifact_timestamps[record.artifact_id] = time.time()
            if record.case_id and record.case_id in self._cases:
                if record.artifact_id not in self._case_artifacts[record.case_id]:
                    self._case_artifacts[record.case_id].append(record.artifact_id)
                self._cases[record.case_id]["artifact_count"] = len(self._case_artifacts[record.case_id])

            if record.run_id:
                self._artifact_runs[record.artifact_id] = record.run_id
                if record.run_id in self._recovery_runs:
                    run = self._recovery_runs[record.run_id]
                    if not run.artifact_id:
                        run.artifact_id = record.artifact_id

            return record

    def get_artifact(self, artifact_id: str) -> Optional[ArtifactResponse]:
        """Get an artifact as API ArtifactResponse by artifact_id."""
        with self._lock:
            record = self._artifacts.get(artifact_id)
            if record is None:
                return None
            return record.to_artifact_response()

    def get_artifact_record(self, artifact_id: str) -> Optional[ArtifactRecord]:
        """Get internal ArtifactRecord by artifact_id."""
        with self._lock:
            return self._artifacts.get(artifact_id)

    def get_case_artifacts(self, case_id: str) -> Optional[List[ArtifactResponse]]:
        """Get all artifacts for a given case_id. Returns None if case does not exist."""
        with self._lock:
            if case_id not in self._cases:
                return None
            art_ids = self._case_artifacts.get(case_id, [])
            return [self._artifacts[aid].to_artifact_response() for aid in art_ids if aid in self._artifacts]

    def store_artifact_bytes(self, artifact_id: str, content: bytes) -> None:
        """Store raw bytes of a recovered artifact in the artifact BlobStore."""
        self._artifact_blobs.put(artifact_id, content)
        with self._lock:
            rec = self._artifacts.get(artifact_id)
            if rec is not None:
                digest = hashlib.sha256(content).hexdigest()
                rec.sha256 = digest
                if rec.metadata is not None:
                    rec.metadata["sha256"] = digest

    def get_artifact_bytes(self, artifact_id: str) -> Optional[bytes]:
        """Get raw bytes of a recovered artifact by artifact_id from artifact BlobStore."""
        return self._artifact_blobs.get(artifact_id)

    def update_artifact_ai_summary(self, artifact_id: str, ai_summary: str) -> None:
        """Update cached AI summary on an artifact record."""
        with self._lock:
            record = self._artifacts.get(artifact_id)
            if record is not None:
                record.ai_summary = ai_summary

    def delete_artifact(self, artifact_id: str) -> bool:
        """Delete an artifact and its associated blobs and linkages.

        Returns True if deleted, False if not found.
        """
        with self._lock:
            if artifact_id not in self._artifacts:
                return False
            rec = self._artifacts.pop(artifact_id)
            if rec.case_id and rec.case_id in self._case_artifacts:
                if artifact_id in self._case_artifacts[rec.case_id]:
                    self._case_artifacts[rec.case_id].remove(artifact_id)
                if rec.case_id in self._cases:
                    self._cases[rec.case_id]["artifact_count"] = len(self._case_artifacts[rec.case_id])
            self._artifact_runs.pop(artifact_id, None)
            self._artifact_timestamps.pop(artifact_id, None)
            self._artifact_blobs.delete(artifact_id)
            return True

    # ── Pipeline B Harmonized Methods ────────────────────────────────────

    def store_recovered_file(self, file_id: str, metadata: dict, content: bytes) -> dict:
        """Store single recovered file metadata and raw bytes into unified artifact storage."""
        content_sha = hashlib.sha256(content).hexdigest() if content else None
        if content_sha:
            metadata["sha256"] = content_sha
        record = ArtifactRecord.from_file_recovery_dict(metadata)
        if content_sha:
            record.sha256 = content_sha
        self.save_artifact_record(record)
        self.store_artifact_bytes(file_id, content)
        with self._lock:
            self._artifact_timestamps[file_id] = time.time()
        if record.run_id:
            self.link_artifact_to_run(file_id, record.run_id)
        return metadata

    def get_recovered_file_metadata(self, file_id: str) -> Optional[dict]:
        """Get single recovered file metadata by file_id from unified artifact storage."""
        with self._lock:
            record = self._artifacts.get(file_id)
            if record is None:
                return None
            return record.to_file_recovery_dict()

    def get_recovered_file_bytes(self, file_id: str) -> Optional[bytes]:
        """Get raw bytes of a single recovered file from artifact BlobStore."""
        return self.get_artifact_bytes(file_id)

    def purge_expired_recovered_files(self, ttl_hours: int = 24) -> int:
        """Purge standalone recovered files older than ttl_hours in memory."""
        cutoff = time.time() - (ttl_hours * 3600)
        purged = 0
        with self._lock:
            expired_ids = []
            for art_id, rec in list(self._artifacts.items()):
                if rec.case_id is None:
                    ts = self._artifact_timestamps.get(art_id)
                    if ts is not None and ts < cutoff:
                        expired_ids.append(art_id)

            for art_id in expired_ids:
                if self.delete_artifact(art_id):
                    purged += 1

        return purged

    # ── RecoveryRunRepository Implementation ─────────────────────────────

    def add_recovery_run(self, run: RecoveryRun) -> RecoveryRun:
        """Store a RecoveryRun model in memory (persisted exactly once)."""
        with self._lock:
            existing = self._recovery_runs.get(run.run_id)
            if existing:
                if not run.case_id and existing.case_id:
                    run.case_id = existing.case_id
                if not run.artifact_id and existing.artifact_id:
                    run.artifact_id = existing.artifact_id
            self._recovery_runs[run.run_id] = run
            if run.artifact_id:
                self._artifact_runs[run.artifact_id] = run.run_id
            return run

    def get_recovery_run(self, run_id: str) -> Optional[RecoveryRun]:
        """Retrieve RecoveryRun by run_id."""
        with self._lock:
            return self._recovery_runs.get(run_id)

    def list_recovery_runs(self) -> List[RecoveryRun]:
        """List all stored RecoveryRun models."""
        with self._lock:
            return list(self._recovery_runs.values())

    def get_case_recovery_runs(self, case_id: str) -> Optional[List[RecoveryRun]]:
        """Retrieve all RecoveryRun instances associated with a case_id, or None if case not found."""
        with self._lock:
            if case_id not in self._cases:
                return None
            return [run for run in self._recovery_runs.values() if run.case_id == case_id]

    def link_artifact_to_run(self, artifact_id: str, run_id: str) -> None:
        """Establish relationship between an artifact and a RecoveryRun."""
        with self._lock:
            self._artifact_runs[artifact_id] = run_id
            if run_id in self._recovery_runs:
                self._recovery_runs[run_id].artifact_id = artifact_id

    def get_recovery_run_by_artifact(self, artifact_id: str) -> Optional[RecoveryRun]:
        """Retrieve RecoveryRun associated with an artifact_id."""
        with self._lock:
            run_id = self._artifact_runs.get(artifact_id)
            if not run_id and artifact_id in self._artifacts:
                art = self._artifacts[artifact_id]
                run_id = art.run_id or (art.metadata.get("run_id") if art.metadata else None)
            if run_id and run_id in self._recovery_runs:
                return self._recovery_runs[run_id]

            for run in self._recovery_runs.values():
                if run.artifact_id == artifact_id:
                    return run

            return None
