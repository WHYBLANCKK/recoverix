"""
sqlite_store.py — Persistent SQLite repository implementation for Recoverix platform.

Implements CaseRepository, ArtifactRepository, and RecoveryRunRepository protocols
using SqliteEngine and SqliteBlobStore with full transactional integrity,
exact binary preservation, and authoritative artifact-to-run linkage.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from backend.app.ingestion import Chunk, chunk_evidence, compute_metadata
from backend.app.models.artifact import ArtifactRecord, ArtifactResponse
from backend.app.models.case import CaseResponse, EvidenceMetadata
from backend.app.models.recovery_run import (
    DamageRegion,
    Fragment,
    PipelineEvent,
    ReconstructionStep,
    RecoveryRun,
)
from backend.app.storage.contracts import (
    ArtifactRepository,
    BlobStore,
    CaseRepository,
    RecoveryRunRepository,
)
from backend.app.storage.memory_store import MAX_EVIDENCE_SIZE
from backend.app.storage.sqlite_blob_store import SqliteBlobStore
from backend.app.storage.sqlite_engine import SqliteEngine


def _parse_persisted_json(
    raw_val: Any,
    expected_type: type,
    default: Any = None,
) -> tuple[Any, bool]:
    """Parse persisted JSON from SQLite column, distinguishing absent/empty from corrupted data.

    Returns:
        tuple (parsed_value, is_corrupted):
          - If raw_val is None or empty: (default, False)  # Legitimately absent/empty
          - If raw_val is valid JSON of expected_type: (parsed, False)
          - If raw_val is malformed or wrong type: (default, True)  # Corrupted!
    """
    if raw_val is None:
        return default, False
    if isinstance(raw_val, (str, bytes)):
        s = raw_val.decode("utf-8", errors="replace") if isinstance(raw_val, bytes) else raw_val
        s = s.strip()
        if not s:
            return default, False
        try:
            parsed = json.loads(s)
        except (json.JSONDecodeError, TypeError, ValueError):
            return default, True
    elif isinstance(raw_val, (dict, list)):
        parsed = raw_val
    else:
        return default, True

    if not isinstance(parsed, expected_type):
        return default, True

    return parsed, False


def _safe_json_loads(val: Any, default: Any = None) -> Any:
    """Safely decode JSON string, returning default if None, empty, or corrupted."""
    res, _ = _parse_persisted_json(val, object if default is None else type(default), default)
    return res


def _row_to_artifact_record(row: sqlite3.Row) -> ArtifactRecord:
    """Convert an SQLite row from the artifacts table to an ArtifactRecord with corruption tracking."""
    corrupted_fields: list[str] = []

    score_breakdown, bad = _parse_persisted_json(row["score_breakdown_json"], dict, default={})
    if bad:
        corrupted_fields.append("score_breakdown_json")

    provenance, bad = _parse_persisted_json(row["provenance_json"], dict, default={})
    if bad:
        corrupted_fields.append("provenance_json")

    validation_details, bad = _parse_persisted_json(row["validation_details_json"], dict, default={})
    if bad:
        corrupted_fields.append("validation_details_json")

    metadata, bad = _parse_persisted_json(row["metadata_json"], dict, default={})
    if bad:
        corrupted_fields.append("metadata_json")

    fragments, bad = _parse_persisted_json(row["fragments_json"], list, default=None)
    if bad:
        corrupted_fields.append("fragments_json")

    damage_regions, bad = _parse_persisted_json(row["damage_regions_json"], list, default=None)
    if bad:
        corrupted_fields.append("damage_regions_json")

    reconstruction_steps, bad = _parse_persisted_json(row["reconstruction_steps_json"], list, default=None)
    if bad:
        corrupted_fields.append("reconstruction_steps_json")

    metadata_dict = dict(metadata) if isinstance(metadata, dict) else {}

    run_id = row["run_id"] or (metadata_dict.get("run_id") if isinstance(metadata_dict, dict) else None)

    v_bytes = int(row["verified_bytes"])
    r_bytes = int(row["reconstructed_bytes"])
    m_bytes = int(row["missing_bytes"])
    total_inp = (
        int(row["total_input_bytes"])
        if row["total_input_bytes"] is not None
        else (v_bytes + r_bytes + m_bytes)
    )

    status_val = row["status"]
    is_dl = bool(row["is_downloadable"])
    if status_val == "UNRECOVERABLE":
        is_dl = False

    return ArtifactRecord(
        artifact_id=row["artifact_id"],
        case_id=row["case_id"],
        run_id=run_id,
        original_filename=row["original_filename"],
        recovered_filename=row["recovered_filename"],
        format=row["format"],
        status=status_val,
        confidence_score=float(row["confidence_score"]),
        verified_bytes=v_bytes,
        reconstructed_bytes=r_bytes,
        missing_bytes=m_bytes,
        total_input_bytes=total_inp,
        reconstruction_method=row["reconstruction_method"],
        validation_status=row["validation_status"],
        is_downloadable=is_dl,
        download_url=row["download_url"],
        content_preview=row["content_preview"],
        score_breakdown=score_breakdown if isinstance(score_breakdown, dict) else {},
        provenance=provenance if isinstance(provenance, dict) else {},
        validation_details=validation_details if isinstance(validation_details, dict) else {},
        fragments=fragments if isinstance(fragments, list) else None,
        damage_regions=damage_regions if isinstance(damage_regions, list) else None,
        reconstruction_steps=reconstruction_steps if isinstance(reconstruction_steps, list) else None,
        category=row["category"],
        priority=row["priority"],
        ai_summary=row["ai_summary"],
        metadata=metadata_dict,
        corrupted_fields=corrupted_fields if corrupted_fields else None,
    )


def _row_to_recovery_run(row: sqlite3.Row) -> RecoveryRun:
    """Convert an SQLite row from recovery_runs table to a RecoveryRun with corruption tracking."""
    started_at = datetime.fromisoformat(row["started_at"])
    completed_at = (
        datetime.fromisoformat(row["completed_at"])
        if row["completed_at"]
        else None
    )

    corrupted_fields: list[str] = []

    raw_frags, bad = _parse_persisted_json(row["fragments_json"], list, default=[])
    if bad:
        corrupted_fields.append("fragments_json")
    fragments_data: list[Fragment] = []
    if isinstance(raw_frags, list):
        for f in raw_frags:
            if isinstance(f, Fragment):
                fragments_data.append(f)
            elif isinstance(f, dict):
                try:
                    fragments_data.append(Fragment.model_validate(f))
                except Exception:
                    corrupted_fields.append("fragments_json:invalid_item")

    raw_damages, bad = _parse_persisted_json(row["damage_regions_json"], list, default=[])
    if bad:
        corrupted_fields.append("damage_regions_json")
    damage_regions_data: list[DamageRegion] = []
    if isinstance(raw_damages, list):
        for d in raw_damages:
            if isinstance(d, DamageRegion):
                damage_regions_data.append(d)
            elif isinstance(d, dict):
                try:
                    damage_regions_data.append(DamageRegion.model_validate(d))
                except Exception:
                    corrupted_fields.append("damage_regions_json:invalid_item")

    raw_steps, bad = _parse_persisted_json(row["reconstruction_steps_json"], list, default=[])
    if bad:
        corrupted_fields.append("reconstruction_steps_json")
    reconstruction_steps_data: list[ReconstructionStep] = []
    if isinstance(raw_steps, list):
        for s in raw_steps:
            if isinstance(s, ReconstructionStep):
                reconstruction_steps_data.append(s)
            elif isinstance(s, dict):
                try:
                    reconstruction_steps_data.append(ReconstructionStep.model_validate(s))
                except Exception:
                    corrupted_fields.append("reconstruction_steps_json:invalid_item")

    raw_events, bad = _parse_persisted_json(row["events_json"], list, default=[])
    if bad:
        corrupted_fields.append("events_json")
    events_data: list[PipelineEvent] = []
    if isinstance(raw_events, list):
        for e in raw_events:
            if isinstance(e, PipelineEvent):
                events_data.append(e)
            elif isinstance(e, dict):
                try:
                    events_data.append(PipelineEvent.model_validate(e))
                except Exception:
                    corrupted_fields.append("events_json:invalid_item")

    validation, bad = _parse_persisted_json(row["validation_json"], dict, default=None)
    if bad:
        corrupted_fields.append("validation_json")

    confidence, bad = _parse_persisted_json(row["confidence_json"], dict, default=None)
    if bad:
        corrupted_fields.append("confidence_json")

    provenance, bad = _parse_persisted_json(row["provenance_json"], dict, default=None)
    if bad:
        corrupted_fields.append("provenance_json")

    output, bad = _parse_persisted_json(row["output_json"], dict, default=None)
    if bad:
        corrupted_fields.append("output_json")

    case_id = row["case_id"] if ("case_id" in row.keys() and row["case_id"]) else None

    return RecoveryRun(
        run_id=row["run_id"],
        case_id=case_id,
        artifact_id=row["artifact_id"],
        candidate_id=row["candidate_id"],
        filename=row["filename"],
        format=row["format"],
        status=row["status"],
        detection_mode=row["detection_mode"],
        started_at=started_at,
        completed_at=completed_at,
        total_input_bytes=int(row["total_input_bytes"]),
        total_verified_bytes=int(row["total_verified_bytes"]),
        total_reconstructed_bytes=int(row["total_reconstructed_bytes"]),
        total_missing_bytes=int(row["total_missing_bytes"]),
        fragments=fragments_data,
        damage_regions=damage_regions_data,
        reconstruction_steps=reconstruction_steps_data,
        events=events_data,
        validation=validation,
        confidence=confidence,
        provenance=provenance,
        output=output,
        corrupted_fields=corrupted_fields if corrupted_fields else None,
    )


def migrate_legacy_blobs(engine: SqliteEngine) -> dict[str, int]:
    """Migrate legacy unprefixed blobs in SQLite to isolated namespaces.

    Safely inspects unprefixed keys in `blobs` and deterministically assigns them
    based on authoritative ownership records:
      - Keys present in `evidence_files` and absent in `artifacts` -> migrated to `evidence:{key}`.
      - Keys present in `artifacts` and absent in `evidence_files` -> migrated to `artifact:{key}`.
      - Keys present in both:
          * If `evidence:{key}` already exists and `artifact:{key}` does not, unprefixed key is migrated to `artifact:{key}`.
          * If `artifact:{key}` already exists and `evidence:{key}` does not, unprefixed key is verified against `evidence_files.sha256` and migrated if matched.
          * If neither namespaced key exists:
              - If SHA-256 matches `evidence_files.sha256`: migrated to `evidence:{key}`.
                (Artifact payload was lost in legacy collision; not fabricated).
              - If SHA-256 does NOT match: ambiguous collision, preserved unmigrated.
      - Keys present in neither: orphaned blobs, preserved unmigrated.

    Properties:
      - Atomic: executes in a single transaction; rolls back completely on error.
      - Idempotent: safe to run multiple times without state changes or data loss.
      - Non-destructive: never overwrites existing namespaced keys.
      - Never invents synthetic data or claims corrupted data was recovered.
    """
    if not isinstance(engine, SqliteEngine):
        raise TypeError("engine must be an instance of SqliteEngine")

    with engine.transaction() as cursor:
        cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='blobs';")
        if cursor.fetchone() is None:
            return {"migrated_evidence": 0, "migrated_artifact": 0, "ambiguous": 0, "orphaned": 0}

        cursor.execute(
            """
            SELECT blob_key, data, size_bytes, created_at
            FROM blobs
            WHERE blob_key NOT LIKE 'evidence:%'
              AND blob_key NOT LIKE 'artifact:%';
            """
        )
        unprefixed_rows = cursor.fetchall()
        if not unprefixed_rows:
            return {"migrated_evidence": 0, "migrated_artifact": 0, "ambiguous": 0, "orphaned": 0}

        cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_files';")
        has_evidence_table = cursor.fetchone() is not None

        cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='artifacts';")
        has_artifacts_table = cursor.fetchone() is not None

        migrated_ev = 0
        migrated_art = 0
        ambiguous = 0
        orphaned = 0

        for row in unprefixed_rows:
            blob_key = row["blob_key"]
            data = bytes(row["data"])
            size_bytes = row["size_bytes"]
            created_at = row["created_at"]

            in_evidence = False
            evidence_sha = None
            if has_evidence_table:
                cursor.execute("SELECT sha256 FROM evidence_files WHERE case_id = ?;", (blob_key,))
                ev_r = cursor.fetchone()
                if ev_r is not None:
                    in_evidence = True
                    evidence_sha = ev_r["sha256"] if isinstance(ev_r, sqlite3.Row) else ev_r[0]

            in_artifacts = False
            if has_artifacts_table:
                cursor.execute("SELECT 1 FROM artifacts WHERE artifact_id = ?;", (blob_key,))
                if cursor.fetchone() is not None:
                    in_artifacts = True

            ev_key = f"evidence:{blob_key}"
            art_key = f"artifact:{blob_key}"

            cursor.execute("SELECT 1 FROM blobs WHERE blob_key = ?;", (ev_key,))
            has_ev_key = cursor.fetchone() is not None

            cursor.execute("SELECT 1 FROM blobs WHERE blob_key = ?;", (art_key,))
            has_art_key = cursor.fetchone() is not None

            if in_evidence and not in_artifacts:
                if not has_ev_key:
                    cursor.execute(
                        "INSERT INTO blobs (blob_key, data, size_bytes, created_at) VALUES (?, ?, ?, ?);",
                        (ev_key, sqlite3.Binary(data), size_bytes, created_at),
                    )
                cursor.execute("DELETE FROM blobs WHERE blob_key = ?;", (blob_key,))
                migrated_ev += 1

            elif in_artifacts and not in_evidence:
                if not has_art_key:
                    cursor.execute(
                        "INSERT INTO blobs (blob_key, data, size_bytes, created_at) VALUES (?, ?, ?, ?);",
                        (art_key, sqlite3.Binary(data), size_bytes, created_at),
                    )
                cursor.execute("DELETE FROM blobs WHERE blob_key = ?;", (blob_key,))
                migrated_art += 1

            elif in_evidence and in_artifacts:
                if has_ev_key and not has_art_key:
                    cursor.execute(
                        "INSERT INTO blobs (blob_key, data, size_bytes, created_at) VALUES (?, ?, ?, ?);",
                        (art_key, sqlite3.Binary(data), size_bytes, created_at),
                    )
                    cursor.execute("DELETE FROM blobs WHERE blob_key = ?;", (blob_key,))
                    migrated_art += 1
                elif has_art_key and not has_ev_key:
                    blob_sha = hashlib.sha256(data).hexdigest()
                    if blob_sha == evidence_sha:
                        cursor.execute(
                            "INSERT INTO blobs (blob_key, data, size_bytes, created_at) VALUES (?, ?, ?, ?);",
                            (ev_key, sqlite3.Binary(data), size_bytes, created_at),
                        )
                        cursor.execute("DELETE FROM blobs WHERE blob_key = ?;", (blob_key,))
                        migrated_ev += 1
                    else:
                        ambiguous += 1
                elif has_ev_key and has_art_key:
                    cursor.execute("DELETE FROM blobs WHERE blob_key = ?;", (blob_key,))
                else:
                    blob_sha = hashlib.sha256(data).hexdigest()
                    if blob_sha == evidence_sha:
                        cursor.execute(
                            "INSERT INTO blobs (blob_key, data, size_bytes, created_at) VALUES (?, ?, ?, ?);",
                            (ev_key, sqlite3.Binary(data), size_bytes, created_at),
                        )
                        cursor.execute("DELETE FROM blobs WHERE blob_key = ?;", (blob_key,))
                        migrated_ev += 1
                    else:
                        ambiguous += 1

            else:
                orphaned += 1

        return {
            "migrated_evidence": migrated_ev,
            "migrated_artifact": migrated_art,
            "ambiguous": ambiguous,
            "orphaned": orphaned,
        }


class SqliteStore(CaseRepository, ArtifactRepository, RecoveryRunRepository):
    """Thread-safe persistent SQLite store conforming to Recoverix repository contracts."""

    def __init__(self, engine: Optional[Union[SqliteEngine, str]] = None) -> None:
        """Initialize with an optional SqliteEngine instance or database path string.

        If engine is None, instantiates a default SqliteEngine.
        If engine is a str, instantiates SqliteEngine(db_path=engine).
        """
        if engine is None:
            engine = SqliteEngine()
        elif isinstance(engine, str):
            engine = SqliteEngine(db_path=engine)
        self._engine = engine
        self._engine.initialize()
        self.migrate_legacy_blobs()
        self._evidence_blobs = SqliteBlobStore(self._engine, namespace="evidence:")
        self._artifact_blobs = SqliteBlobStore(self._engine, namespace="artifact:")
        self._blobs = self._artifact_blobs

    def close(self) -> None:
        """Close the underlying SQLite engine and release resources."""
        self._engine.close()

    def reconfigure(self, engine: Optional[Union[SqliteEngine, str]] = None) -> None:
        """Reconfigure store to use a different engine or database path."""
        self._engine.close()
        if engine is None:
            engine = SqliteEngine()
        elif isinstance(engine, str):
            engine = SqliteEngine(db_path=engine)
        self._engine = engine
        self._engine.initialize()
        self.migrate_legacy_blobs()
        self._evidence_blobs = SqliteBlobStore(self._engine, namespace="evidence:")
        self._artifact_blobs = SqliteBlobStore(self._engine, namespace="artifact:")
        self._blobs = self._artifact_blobs

    def migrate_legacy_blobs(self) -> dict[str, int]:
        """Run idempotent migration of legacy unprefixed blobs to isolated namespaces."""
        return migrate_legacy_blobs(self._engine)

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
        """Clear all stored state across all tables in FK-safe reverse order."""
        self._engine.clear_all_tables()

    # ── CaseRepository Implementation ────────────────────────────────────

    def create_case(self, name: str, description: Optional[str] = None) -> CaseResponse:
        """Create and store a new forensic case.

        Raises:
            ValueError: If name is empty or whitespace.
        """
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Case name cannot be empty or invalid string")

        case_id = f"case_{uuid.uuid4().hex[:8]}"
        created_at = datetime.now(timezone.utc).isoformat()
        clean_name = name.strip()
        clean_desc = description.strip() if description else None

        with self._engine.transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO cases (case_id, name, description, created_at)
                VALUES (?, ?, ?, ?);
                """,
                (case_id, clean_name, clean_desc, created_at),
            )

        return CaseResponse(
            case_id=case_id,
            name=clean_name,
            description=clean_desc,
            created_at=created_at,
            evidence=None,
            artifact_count=0,
        )

    def get_case(self, case_id: str) -> Optional[CaseResponse]:
        """Retrieve case response model by case_id with dynamic artifact count."""
        with self._engine.transaction() as cursor:
            cursor.execute(
                """
                SELECT case_id, name, description, created_at
                FROM cases
                WHERE case_id = ?;
                """,
                (case_id,),
            )
            case_row = cursor.fetchone()
            if case_row is None:
                return None

            cursor.execute(
                """
                SELECT filename, file_size, uploaded_at, sha256
                FROM evidence_files
                WHERE case_id = ?;
                """,
                (case_id,),
            )
            ev_row = cursor.fetchone()
            evidence = None
            if ev_row is not None:
                evidence = EvidenceMetadata(
                    filename=ev_row["filename"],
                    file_size=ev_row["file_size"],
                    uploaded_at=ev_row["uploaded_at"],
                    sha256=ev_row["sha256"],
                )

            cursor.execute(
                """
                SELECT COUNT(*) FROM artifacts WHERE case_id = ?;
                """,
                (case_id,),
            )
            artifact_count = cursor.fetchone()[0]

            return CaseResponse(
                case_id=case_row["case_id"],
                name=case_row["name"],
                description=case_row["description"],
                created_at=case_row["created_at"],
                evidence=evidence,
                artifact_count=artifact_count,
            )

    def list_cases(self) -> List[CaseResponse]:
        """List all stored cases in creation order with dynamic artifact counts."""
        with self._engine.transaction() as cursor:
            cursor.execute(
                """
                SELECT 
                    c.case_id, c.name, c.description, c.created_at,
                    e.filename, e.file_size, e.uploaded_at, e.sha256,
                    (SELECT COUNT(*) FROM artifacts a WHERE a.case_id = c.case_id) AS artifact_count
                FROM cases c
                LEFT JOIN evidence_files e ON c.case_id = e.case_id
                ORDER BY c.rowid ASC;
                """
            )
            rows = cursor.fetchall()
            results: List[CaseResponse] = []
            for r in rows:
                ev = None
                if r["filename"] is not None:
                    ev = EvidenceMetadata(
                        filename=r["filename"],
                        file_size=r["file_size"],
                        uploaded_at=r["uploaded_at"],
                        sha256=r["sha256"],
                    )
                results.append(
                    CaseResponse(
                        case_id=r["case_id"],
                        name=r["name"],
                        description=r["description"],
                        created_at=r["created_at"],
                        evidence=ev,
                        artifact_count=r["artifact_count"],
                    )
                )
            return results

    def add_evidence(self, case_id: str, filename: str, content: bytes) -> EvidenceMetadata:
        """Add uploaded evidence bytes to a case using ingestion module atomically.

        Raises:
            KeyError: If case_id does not exist.
            ValueError: If file size is 0 (empty) or exceeds MAX_EVIDENCE_SIZE.
        """
        if not content or len(content) == 0:
            raise ValueError("EMPTY_FILE")

        if len(content) > MAX_EVIDENCE_SIZE:
            raise ValueError("FILE_TOO_LARGE")

        ingestion_meta = compute_metadata(content, filename=filename or "evidence.img")
        chunks = chunk_evidence(content)
        uploaded_at = datetime.now(timezone.utc).isoformat()

        meta = EvidenceMetadata(
            filename=ingestion_meta.filename,
            file_size=ingestion_meta.size_bytes,
            uploaded_at=uploaded_at,
            sha256=ingestion_meta.sha256,
        )

        with self._engine.transaction() as cursor:
            cursor.execute("SELECT 1 FROM cases WHERE case_id = ?;", (case_id,))
            if cursor.fetchone() is None:
                raise KeyError(f"Case '{case_id}' not found")

            cursor.execute(
                """
                INSERT INTO evidence_files (
                    case_id, filename, file_size, uploaded_at, sha256, chunk_size, total_chunks
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                    filename = excluded.filename,
                    file_size = excluded.file_size,
                    uploaded_at = excluded.uploaded_at,
                    sha256 = excluded.sha256,
                    chunk_size = excluded.chunk_size,
                    total_chunks = excluded.total_chunks;
                """,
                (
                    case_id,
                    meta.filename,
                    meta.file_size,
                    meta.uploaded_at,
                    meta.sha256,
                    ingestion_meta.chunk_size,
                    ingestion_meta.num_chunks,
                ),
            )

            cursor.execute("DELETE FROM evidence_chunks WHERE case_id = ?;", (case_id,))
            for chk in chunks:
                chunk_id = f"chk_{case_id}_{chk.index}"
                chunk_sha = hashlib.sha256(chk.data).hexdigest()
                cursor.execute(
                    """
                    INSERT INTO evidence_chunks (
                        chunk_id, case_id, chunk_index, offset, size, sha256
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (chunk_id, case_id, chk.index, chk.offset, chk.length, chunk_sha),
                )

            raw_bytes = bytes(content)
            cursor.execute(
                """
                INSERT INTO blobs (blob_key, data, size_bytes, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(blob_key) DO UPDATE SET
                    data = excluded.data,
                    size_bytes = excluded.size_bytes,
                    created_at = excluded.created_at;
                """,
                (self._evidence_blobs._make_key(case_id), sqlite3.Binary(raw_bytes), len(raw_bytes), uploaded_at),
            )

        return meta

    def get_evidence_bytes(self, case_id: str) -> Optional[bytes]:
        """Get uploaded evidence raw bytes for a case from evidence BlobStore."""
        return self._evidence_blobs.get(case_id)

    def get_evidence_chunks(self, case_id: str) -> Optional[List[Chunk]]:
        """Get uploaded evidence chunks for a case in sequential order."""
        with self._engine.transaction() as cursor:
            cursor.execute("SELECT case_id FROM evidence_files WHERE case_id = ?;", (case_id,))
            if cursor.fetchone() is None:
                return None

            cursor.execute(
                """
                SELECT chunk_index, offset, size
                FROM evidence_chunks
                WHERE case_id = ?
                ORDER BY chunk_index ASC;
                """,
                (case_id,),
            )
            rows = cursor.fetchall()
            if not rows:
                return []

            content = self.get_evidence_bytes(case_id)
            if content is None:
                return None

            chunks: List[Chunk] = []
            for r in rows:
                idx = r["chunk_index"]
                off = r["offset"]
                sz = r["size"]
                chunk_data = content[off : off + sz]
                chunks.append(Chunk(index=idx, offset=off, length=sz, data=chunk_data))

            return chunks

    # ── ArtifactRepository Implementation ────────────────────────────────

    def add_artifact(self, artifact: ArtifactResponse) -> ArtifactResponse:
        """Store a recovered artifact under a case (Pipeline A).

        Raises:
            KeyError: If case_id is not registered.
        """
        record = ArtifactRecord.from_artifact_response(artifact)
        self.save_artifact_record(record)
        return artifact

    def _save_artifact_record_on_cursor(
        self, cursor: sqlite3.Cursor, record: ArtifactRecord
    ) -> ArtifactRecord:
        """Execute artifact record persistence on an existing cursor."""
        if record.case_id:
            cursor.execute("SELECT 1 FROM cases WHERE case_id = ?;", (record.case_id,))
            if cursor.fetchone() is None:
                raise KeyError(f"Case '{record.case_id}' not found")

        # Determine if run_id exists in recovery_runs to satisfy foreign key constraint
        db_run_id = None
        if record.run_id:
            cursor.execute("SELECT 1 FROM recovery_runs WHERE run_id = ?;", (record.run_id,))
            if cursor.fetchone() is not None:
                db_run_id = record.run_id

        meta_dict = dict(record.metadata or {})
        if record.run_id and "run_id" not in meta_dict:
            meta_dict["run_id"] = record.run_id

        cursor.execute(
            """
            INSERT INTO artifacts (
                artifact_id, case_id, run_id, original_filename, recovered_filename,
                format, status, confidence_score, verified_bytes, reconstructed_bytes,
                missing_bytes, total_input_bytes, reconstruction_method, validation_status,
                is_downloadable, download_url, content_preview, category, priority,
                ai_summary, score_breakdown_json, provenance_json, validation_details_json,
                metadata_json, fragments_json, damage_regions_json, reconstruction_steps_json
            ) VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            ON CONFLICT(artifact_id) DO UPDATE SET
                case_id = excluded.case_id,
                run_id = excluded.run_id,
                original_filename = excluded.original_filename,
                recovered_filename = excluded.recovered_filename,
                format = excluded.format,
                status = excluded.status,
                confidence_score = excluded.confidence_score,
                verified_bytes = excluded.verified_bytes,
                reconstructed_bytes = excluded.reconstructed_bytes,
                missing_bytes = excluded.missing_bytes,
                total_input_bytes = excluded.total_input_bytes,
                reconstruction_method = excluded.reconstruction_method,
                validation_status = excluded.validation_status,
                is_downloadable = excluded.is_downloadable,
                download_url = excluded.download_url,
                content_preview = excluded.content_preview,
                category = excluded.category,
                priority = excluded.priority,
                ai_summary = excluded.ai_summary,
                score_breakdown_json = excluded.score_breakdown_json,
                provenance_json = excluded.provenance_json,
                validation_details_json = excluded.validation_details_json,
                metadata_json = excluded.metadata_json,
                fragments_json = excluded.fragments_json,
                damage_regions_json = excluded.damage_regions_json,
                reconstruction_steps_json = excluded.reconstruction_steps_json;
            """,
            (
                record.artifact_id,
                record.case_id,
                db_run_id,
                record.original_filename,
                record.recovered_filename,
                record.format,
                record.status,
                float(record.confidence_score),
                int(record.verified_bytes),
                int(record.reconstructed_bytes),
                int(record.missing_bytes),
                int(record.total_input_bytes) if record.total_input_bytes is not None else None,
                record.reconstruction_method,
                record.validation_status,
                1 if record.is_downloadable else 0,
                record.download_url,
                record.content_preview,
                record.category,
                record.priority,
                record.ai_summary,
                json.dumps(record.score_breakdown or {}),
                json.dumps(record.provenance or {}),
                json.dumps(record.validation_details or {}),
                json.dumps(meta_dict),
                json.dumps(record.fragments) if record.fragments is not None else None,
                json.dumps(record.damage_regions) if record.damage_regions is not None else None,
                json.dumps(record.reconstruction_steps) if record.reconstruction_steps is not None else None,
            ),
        )

        # Authoritative linkage if target recovery_run exists
        if db_run_id:
            cursor.execute(
                """
                INSERT INTO artifact_runs (artifact_id, run_id)
                VALUES (?, ?)
                ON CONFLICT(artifact_id) DO UPDATE SET run_id = excluded.run_id;
                """,
                (record.artifact_id, db_run_id),
            )
            cursor.execute(
                """
                UPDATE recovery_runs SET artifact_id = ?
                WHERE run_id = ? AND (artifact_id IS NULL OR artifact_id = '');
                """,
                (record.artifact_id, db_run_id),
            )

        return record

    def save_artifact_record(
        self, record: ArtifactRecord, cursor: Optional[sqlite3.Cursor] = None
    ) -> ArtifactRecord:
        """Directly store an internal ArtifactRecord with atomic linkage."""
        if cursor is not None:
            return self._save_artifact_record_on_cursor(cursor, record)

        with self._engine.transaction() as cur:
            return self._save_artifact_record_on_cursor(cur, record)

    def get_artifact(self, artifact_id: str) -> Optional[ArtifactResponse]:
        """Get an artifact as API ArtifactResponse by artifact_id."""
        record = self.get_artifact_record(artifact_id)
        if record is None:
            return None
        return record.to_artifact_response()

    def get_artifact_record(self, artifact_id: str) -> Optional[ArtifactRecord]:
        """Get internal ArtifactRecord by artifact_id with authoritative run_id."""
        with self._engine.transaction() as cursor:
            cursor.execute(
                """
                SELECT * FROM artifacts WHERE artifact_id = ?;
                """,
                (artifact_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None

            record = _row_to_artifact_record(row)

            cursor.execute(
                """
                SELECT run_id FROM artifact_runs WHERE artifact_id = ?;
                """,
                (artifact_id,),
            )
            link_row = cursor.fetchone()
            if link_row is not None:
                record.run_id = link_row["run_id"]
                if "run_id" not in record.metadata:
                    record.metadata["run_id"] = link_row["run_id"]

            return record

    def get_case_artifacts(self, case_id: str) -> Optional[List[ArtifactResponse]]:
        """Get all artifacts for a given case_id. Returns None if case does not exist."""
        with self._engine.transaction() as cursor:
            cursor.execute("SELECT 1 FROM cases WHERE case_id = ?;", (case_id,))
            if cursor.fetchone() is None:
                return None

            cursor.execute(
                """
                SELECT * FROM artifacts WHERE case_id = ? ORDER BY rowid ASC;
                """,
                (case_id,),
            )
            rows = cursor.fetchall()
            artifacts: List[ArtifactResponse] = []
            for r in rows:
                rec = _row_to_artifact_record(r)
                artifacts.append(rec.to_artifact_response())
            return artifacts

    def _store_artifact_bytes_on_cursor(
        self, cursor: sqlite3.Cursor, artifact_id: str, content: bytes
    ) -> None:
        """Store raw bytes on an active cursor."""
        raw_bytes = bytes(content)
        cursor.execute(
            """
            INSERT INTO blobs (blob_key, data, size_bytes, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(blob_key) DO UPDATE SET
                data = excluded.data,
                size_bytes = excluded.size_bytes,
                created_at = excluded.created_at;
            """,
            (self._artifact_blobs._make_key(artifact_id), sqlite3.Binary(raw_bytes), len(raw_bytes), datetime.now(timezone.utc).isoformat()),
        )

    def store_artifact_bytes(
        self, artifact_id: str, content: bytes, cursor: Optional[sqlite3.Cursor] = None
    ) -> None:
        """Store raw bytes of a recovered artifact in the artifact BlobStore."""
        if cursor is not None:
            self._store_artifact_bytes_on_cursor(cursor, artifact_id, content)
        else:
            self._artifact_blobs.put(artifact_id, content)

    def get_artifact_bytes(self, artifact_id: str) -> Optional[bytes]:
        """Get raw bytes of a recovered artifact by artifact_id from artifact BlobStore."""
        return self._artifact_blobs.get(artifact_id)

    def update_artifact_ai_summary(self, artifact_id: str, ai_summary: str) -> None:
        """Update cached AI summary on an artifact record."""
        with self._engine.transaction() as cursor:
            cursor.execute(
                """
                UPDATE artifacts SET ai_summary = ? WHERE artifact_id = ?;
                """,
                (ai_summary, artifact_id),
            )

    def delete_artifact(self, artifact_id: str) -> bool:
        """Delete an artifact and its associated blobs and linkages atomically.

        Returns True if deleted, False if not found.
        """
        with self._engine.transaction() as cursor:
            cursor.execute("SELECT 1 FROM artifacts WHERE artifact_id = ?;", (artifact_id,))
            if cursor.fetchone() is None:
                return False
            cursor.execute("DELETE FROM artifact_runs WHERE artifact_id = ?;", (artifact_id,))
            cursor.execute("DELETE FROM artifacts WHERE artifact_id = ?;", (artifact_id,))
            cursor.execute("DELETE FROM blobs WHERE blob_key = ?;", (self._artifact_blobs._make_key(artifact_id),))
            cursor.execute(
                """
                DELETE FROM blobs
                WHERE blob_key = ?
                  AND blob_key NOT IN (SELECT case_id FROM evidence_files);
                """,
                (artifact_id,),
            )
        return True

    # ── Pipeline B Harmonized Methods ────────────────────────────────────

    def store_recovered_file(self, file_id: str, metadata: dict, content: bytes) -> dict:
        """Store single recovered file metadata and raw bytes into unified artifact storage."""
        record = ArtifactRecord.from_file_recovery_dict(metadata)
        with self._engine.transaction() as cursor:
            self.save_artifact_record(record, cursor=cursor)
            self.store_artifact_bytes(file_id, content, cursor=cursor)
            if record.run_id:
                self.link_artifact_to_run(file_id, record.run_id, cursor=cursor)
        return metadata

    def get_recovered_file_metadata(self, file_id: str) -> Optional[dict]:
        """Get single recovered file metadata by file_id from unified artifact storage."""
        record = self.get_artifact_record(file_id)
        if record is None:
            return None
        return record.to_file_recovery_dict()

    def get_recovered_file_bytes(self, file_id: str) -> Optional[bytes]:
        """Get raw bytes of a single recovered file from artifact BlobStore."""
        return self.get_artifact_bytes(file_id)

    # ── RecoveryRunRepository Implementation ─────────────────────────────

    def add_recovery_run(self, run: RecoveryRun) -> RecoveryRun:
        """Store a RecoveryRun model in SQLite (persisted exactly once)."""
        started_at_str = run.started_at.isoformat()
        completed_at_str = run.completed_at.isoformat() if run.completed_at else None

        val_json = json.dumps(run.validation) if run.validation is not None else "{}"
        conf_json = json.dumps(run.confidence) if run.confidence is not None else "{}"
        prov_json = json.dumps(run.provenance) if run.provenance is not None else "{}"
        out_json = json.dumps(run.output) if run.output is not None else None

        frag_json = json.dumps([f.model_dump() for f in run.fragments])
        dam_json = json.dumps([d.model_dump() for d in run.damage_regions])
        rec_json = json.dumps([s.model_dump() for s in run.reconstruction_steps])
        evt_json = json.dumps([e.model_dump(mode="json") for e in run.events])

        with self._engine.transaction() as cursor:
            case_id_val = run.case_id
            if case_id_val:
                cursor.execute("SELECT 1 FROM cases WHERE case_id = ?;", (case_id_val,))
                if cursor.fetchone() is None:
                    case_id_val = None

            cursor.execute(
                """
                INSERT INTO recovery_runs (
                    run_id, case_id, artifact_id, candidate_id, filename, format, status,
                    detection_mode, started_at, completed_at, total_input_bytes,
                    total_verified_bytes, total_reconstructed_bytes, total_missing_bytes,
                    validation_json, confidence_json, provenance_json, output_json,
                    fragments_json, damage_regions_json, reconstruction_steps_json, events_json
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?
                )
                ON CONFLICT(run_id) DO UPDATE SET
                    case_id = COALESCE(excluded.case_id, recovery_runs.case_id),
                    artifact_id = COALESCE(excluded.artifact_id, recovery_runs.artifact_id),
                    candidate_id = COALESCE(excluded.candidate_id, recovery_runs.candidate_id),
                    filename = excluded.filename,
                    format = excluded.format,
                    status = excluded.status,
                    detection_mode = excluded.detection_mode,
                    started_at = excluded.started_at,
                    completed_at = excluded.completed_at,
                    total_input_bytes = excluded.total_input_bytes,
                    total_verified_bytes = excluded.total_verified_bytes,
                    total_reconstructed_bytes = excluded.total_reconstructed_bytes,
                    total_missing_bytes = excluded.total_missing_bytes,
                    validation_json = excluded.validation_json,
                    confidence_json = excluded.confidence_json,
                    provenance_json = excluded.provenance_json,
                    output_json = excluded.output_json,
                    fragments_json = excluded.fragments_json,
                    damage_regions_json = excluded.damage_regions_json,
                    reconstruction_steps_json = excluded.reconstruction_steps_json,
                    events_json = excluded.events_json;
                """,
                (
                    run.run_id,
                    case_id_val,
                    run.artifact_id,
                    run.candidate_id,
                    run.filename,
                    run.format,
                    run.status,
                    run.detection_mode or "known_file",
                    started_at_str,
                    completed_at_str,
                    run.total_input_bytes,
                    run.total_verified_bytes,
                    run.total_reconstructed_bytes,
                    run.total_missing_bytes,
                    val_json,
                    conf_json,
                    prov_json,
                    out_json,
                    frag_json,
                    dam_json,
                    rec_json,
                    evt_json,
                ),
            )

            if run.artifact_id:
                cursor.execute(
                    """
                    INSERT INTO artifact_runs (artifact_id, run_id)
                    VALUES (?, ?)
                    ON CONFLICT(artifact_id) DO UPDATE SET run_id = excluded.run_id;
                    """,
                    (run.artifact_id, run.run_id),
                )

            # Auto-link any artifacts that were saved with this run_id before run was created
            cursor.execute(
                """
                UPDATE artifacts SET run_id = ?
                WHERE run_id IS NULL AND json_extract(metadata_json, '$.run_id') = ?;
                """,
                (run.run_id, run.run_id),
            )
            cursor.execute(
                """
                INSERT INTO artifact_runs (artifact_id, run_id)
                SELECT artifact_id, ? FROM artifacts
                WHERE run_id = ?
                ON CONFLICT(artifact_id) DO UPDATE SET run_id = excluded.run_id;
                """,
                (run.run_id, run.run_id),
            )

        return run

    def get_recovery_run(self, run_id: str) -> Optional[RecoveryRun]:
        """Retrieve RecoveryRun by run_id."""
        with self._engine.transaction() as cursor:
            cursor.execute("SELECT * FROM recovery_runs WHERE run_id = ?;", (run_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return _row_to_recovery_run(row)

    def list_recovery_runs(self) -> List[RecoveryRun]:
        """List all stored RecoveryRun models in insertion order."""
        with self._engine.transaction() as cursor:
            cursor.execute("SELECT * FROM recovery_runs ORDER BY rowid ASC;")
            rows = cursor.fetchall()
            return [_row_to_recovery_run(r) for r in rows]

    def get_case_recovery_runs(self, case_id: str) -> Optional[List[RecoveryRun]]:
        """Retrieve all RecoveryRun instances associated with a case_id, or None if case not found."""
        with self._engine.transaction() as cursor:
            cursor.execute("SELECT 1 FROM cases WHERE case_id = ?;", (case_id,))
            if cursor.fetchone() is None:
                return None
            cursor.execute(
                "SELECT * FROM recovery_runs WHERE case_id = ? ORDER BY rowid ASC;",
                (case_id,),
            )
            rows = cursor.fetchall()
            return [_row_to_recovery_run(r) for r in rows]

    def _link_artifact_to_run_on_cursor(
        self, cursor: sqlite3.Cursor, artifact_id: str, run_id: str
    ) -> None:
        """Execute authoritative linkage on an active cursor."""
        cursor.execute(
            "SELECT 1 FROM recovery_runs WHERE run_id = ?;",
            (run_id,),
        )
        if cursor.fetchone() is not None:
            cursor.execute(
                """
                INSERT INTO artifact_runs (artifact_id, run_id)
                VALUES (?, ?)
                ON CONFLICT(artifact_id) DO UPDATE SET run_id = excluded.run_id;
                """,
                (artifact_id, run_id),
            )
            cursor.execute(
                """
                UPDATE artifacts SET run_id = ? WHERE artifact_id = ?;
                """,
                (run_id, artifact_id),
            )
            cursor.execute(
                """
                UPDATE recovery_runs SET artifact_id = ? WHERE run_id = ?;
                """,
                (artifact_id, run_id),
            )
        else:
            # If run_id is not yet in recovery_runs, update artifacts metadata_json
            # so the link will be automatically established when add_recovery_run() is called.
            cursor.execute(
                """
                UPDATE artifacts
                SET metadata_json = json_set(metadata_json, '$.run_id', ?)
                WHERE artifact_id = ?;
                """,
                (run_id, artifact_id),
            )

    def link_artifact_to_run(
        self, artifact_id: str, run_id: str, cursor: Optional[sqlite3.Cursor] = None
    ) -> None:
        """Establish authoritative relationship between an artifact and a RecoveryRun."""
        if cursor is not None:
            self._link_artifact_to_run_on_cursor(cursor, artifact_id, run_id)
        else:
            with self._engine.transaction() as cur:
                self._link_artifact_to_run_on_cursor(cur, artifact_id, run_id)

    def get_recovery_run_by_artifact(self, artifact_id: str) -> Optional[RecoveryRun]:
        """Retrieve RecoveryRun associated with an artifact_id via authoritative linkage."""
        with self._engine.transaction() as cursor:
            cursor.execute(
                "SELECT run_id FROM artifact_runs WHERE artifact_id = ?;",
                (artifact_id,),
            )
            row = cursor.fetchone()
            run_id = row["run_id"] if row else None

            if not run_id:
                cursor.execute(
                    "SELECT run_id, metadata_json FROM artifacts WHERE artifact_id = ?;",
                    (artifact_id,),
                )
                art_row = cursor.fetchone()
                if art_row:
                    run_id = art_row["run_id"]
                    if not run_id and art_row["metadata_json"]:
                        meta = _safe_json_loads(art_row["metadata_json"], default={})
                        if isinstance(meta, dict):
                            run_id = meta.get("run_id")

            if not run_id:
                cursor.execute(
                    "SELECT * FROM recovery_runs WHERE artifact_id = ?;",
                    (artifact_id,),
                )
                direct_row = cursor.fetchone()
                if direct_row is not None:
                    return _row_to_recovery_run(direct_row)
                return None

            cursor.execute("SELECT * FROM recovery_runs WHERE run_id = ?;", (run_id,))
            run_row = cursor.fetchone()
            if run_row is None:
                return None

            return _row_to_recovery_run(run_row)
