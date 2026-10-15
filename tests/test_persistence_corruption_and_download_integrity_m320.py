"""
test_persistence_corruption_and_download_integrity_m320.py — Persistence Corruption & Download Integrity Suite.

Milestone M3.20.0:
1. Verify download eligibility and downloaded bytes strictly agree with actual recovered artifacts.
2. Verify no fabricated bytes (e.g. content_preview encoding) or 0-byte files for unrecoverable/missing payloads.
3. Verify authoritative status overrides conflicting metadata (e.g. UNRECOVERABLE status overrides is_downloadable=True).
4. Verify SQLite store handles corrupted, malformed, and type-mismatched JSON gracefully while recording corrupted_fields.
5. Verify absent (NULL) and empty ("") JSON fields are cleanly distinguished from corrupted fields.
6. Verify negative offsets in Fragment and DamageRegion are rejected by Pydantic model validation.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.app.main import app
from backend.app.models.artifact import (
    ArtifactProvenanceSchema,
    ArtifactRecord,
    ArtifactResponse,
    ConfidenceBreakdownSchema,
)
from backend.app.models.recovery_run import (
    DamageRegion,
    Fragment,
    PipelineEvent,
    ReconstructionStep,
    RecoveryRun,
)
from backend.app.recovery.adapter import extract_recovered_bytes
from backend.app.storage.memory_store import InMemoryStore
from backend.app.storage.sqlite_store import SqliteStore, _parse_persisted_json
from backend.app.store import store

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_store():
    store.clear()
    yield
    store.clear()


# ── Case 1: Intact File Download (Pipeline A & Pipeline B) ───────────────────


def test_01_intact_file_download_integrity():
    """Verify intact file download yields HTTP 200, correct headers, and exact SHA-256 matching payload."""
    payload = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\xf3\xffa"
    sha = hashlib.sha256(payload).hexdigest()

    # Pipeline A: Case artifact
    case = store.create_case("Case 1 Intact Download")
    art_resp = ArtifactResponse(
        artifact_id="art-intact-01",
        case_id=case.case_id,
        format="png",
        size_bytes=len(payload),
        confidence_score=95,
        score_breakdown=ConfidenceBreakdownSchema(
            header_validity=20,
            footer_validity=20,
            structural_validation=35,
            size_plausibility=10,
            reconstruction_integrity=10,
            total=95,
        ),
        status="FULLY_RECOVERED",
        provenance=ArtifactProvenanceSchema(
            verified_bytes=len(payload),
            reconstructed_bytes=0,
            missing_bytes=0,
            reconstruction_method="NONE",
            validation_status="PASSED",
        ),
        metadata={"is_downloadable": True},
    )
    store.add_artifact(art_resp)
    store.store_artifact_bytes("art-intact-01", payload)

    resp_a = client.get("/api/artifacts/art-intact-01/download")
    assert resp_a.status_code == 200
    assert resp_a.content == payload
    assert hashlib.sha256(resp_a.content).hexdigest() == sha
    assert "attachment;" in resp_a.headers["content-disposition"]
    assert "recovered_artifact_art-intact-01.png" in resp_a.headers["content-disposition"]

    # Pipeline B: Single-file recovery
    meta_b = {
        "file_id": "file-intact-01",
        "original_filename": "test_image.png",
        "recovered_filename": "recovered_test_image.png",
        "format": "png",
        "status": "FULLY_RECOVERED",
        "confidence_score": 95.0,
        "verified_bytes": len(payload),
        "reconstructed_bytes": 0,
        "missing_bytes": 0,
        "reconstruction_method": "NONE",
        "validation_status": "PASSED",
        "is_downloadable": True,
        "download_url": "/api/recover-file/file-intact-01/download",
        "score_breakdown": {"total": 95.0},
        "validation_details": {"valid": True},
    }
    store.store_recovered_file("file-intact-01", meta_b, payload)

    resp_b = client.get("/api/recover-file/file-intact-01/download")
    assert resp_b.status_code == 200
    assert resp_b.content == payload
    assert hashlib.sha256(resp_b.content).hexdigest() == sha
    assert 'filename="recovered_test_image.png"' in resp_b.headers["content-disposition"]


# ── Case 2: Partially Recovered File Download ─────────────────────────────────


def test_02_partially_recovered_file_download():
    """Verify partially recovered file download serves actual recovered bytes without padding."""
    partial_payload = b'{"name": "partial", "data": [1, 2, 3]}'
    sha = hashlib.sha256(partial_payload).hexdigest()

    case = store.create_case("Case 2 Partial Download")
    rec = ArtifactRecord(
        artifact_id="art-partial-02",
        case_id=case.case_id,
        recovered_filename="recovered_data.json",
        format="json",
        status="PARTIALLY_RECOVERED",
        confidence_score=70.0,
        verified_bytes=len(partial_payload),
        reconstructed_bytes=0,
        missing_bytes=50,
        total_input_bytes=len(partial_payload) + 50,
        reconstruction_method="NONE",
        validation_status="PASSED",
        is_downloadable=True,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes("art-partial-02", partial_payload)

    resp = client.get("/api/artifacts/art-partial-02/download")
    assert resp.status_code == 200
    assert resp.content == partial_payload
    assert hashlib.sha256(resp.content).hexdigest() == sha
    assert len(resp.content) == len(partial_payload)


# ── Case 3: Reconstructed File with Validated Gap ────────────────────────────


def test_03_reconstructed_file_download():
    """Verify reconstructed file download serves full reconstructed payload matching stored blob."""
    reconstructed_payload = b'{"items": ["item1", "item2"]}'
    sha = hashlib.sha256(reconstructed_payload).hexdigest()

    case = store.create_case("Case 3 Reconstructed Download")
    rec = ArtifactRecord(
        artifact_id="art-recon-03",
        case_id=case.case_id,
        format="json",
        status="PARTIALLY_RECOVERED",
        confidence_score=80.0,
        verified_bytes=20,
        reconstructed_bytes=len(reconstructed_payload) - 20,
        missing_bytes=0,
        total_input_bytes=len(reconstructed_payload),
        reconstruction_method="BRACKET_INJECTION",
        validation_status="PASSED",
        is_downloadable=True,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes("art-recon-03", reconstructed_payload)

    resp = client.get("/api/artifacts/art-recon-03/download")
    assert resp.status_code == 200
    assert resp.content == reconstructed_payload
    assert hashlib.sha256(resp.content).hexdigest() == sha


# ── Case 4: Unrecoverable Candidate Returns 404 on Both Endpoints ─────────────


def test_04_unrecoverable_candidate_download_rejected():
    """Verify unrecoverable candidate returns HTTP 404 on both download endpoints."""
    case = store.create_case("Case 4 Unrecoverable")
    rec = ArtifactRecord(
        artifact_id="art-unrec-04",
        case_id=case.case_id,
        format="bin",
        status="UNRECOVERABLE",
        confidence_score=0.0,
        verified_bytes=0,
        reconstructed_bytes=0,
        missing_bytes=100,
        total_input_bytes=100,
        is_downloadable=False,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes("art-unrec-04", b"")

    resp_a = client.get("/api/artifacts/art-unrec-04/download")
    assert resp_a.status_code == 404

    # Pipeline B
    meta_b = {
        "file_id": "file-unrec-04",
        "original_filename": "corrupt.bin",
        "format": "bin",
        "status": "UNRECOVERABLE",
        "confidence_score": 0.0,
        "verified_bytes": 0,
        "reconstructed_bytes": 0,
        "missing_bytes": 100,
        "reconstruction_method": "NONE",
        "validation_status": "FAILED",
        "is_downloadable": False,
        "score_breakdown": {},
        "validation_details": {},
    }
    store.store_recovered_file("file-unrec-04", meta_b, b"")

    resp_b = client.get("/api/recover-file/file-unrec-04/download")
    assert resp_b.status_code == 404


# ── Case 5: Empty Recovered Payload Returns 404 ──────────────────────────────


def test_05_empty_recovered_payload_rejected():
    """Verify empty recovered payload (0 bytes) returns HTTP 404 and is never downloaded."""
    case = store.create_case("Case 5 Empty Payload")
    rec = ArtifactRecord(
        artifact_id="art-empty-05",
        case_id=case.case_id,
        format="txt",
        status="PARTIALLY_RECOVERED",
        confidence_score=50.0,
        verified_bytes=0,
        reconstructed_bytes=0,
        missing_bytes=0,
        is_downloadable=True,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes("art-empty-05", b"")

    resp = client.get("/api/artifacts/art-empty-05/download")
    assert resp.status_code == 404

    meta_b = {
        "file_id": "file-empty-05",
        "original_filename": "empty.txt",
        "format": "txt",
        "status": "PARTIALLY_RECOVERED",
        "confidence_score": 50.0,
        "verified_bytes": 0,
        "reconstructed_bytes": 0,
        "missing_bytes": 0,
        "reconstruction_method": "NONE",
        "validation_status": "PASSED",
        "is_downloadable": True,
        "score_breakdown": {},
        "validation_details": {},
    }
    store.store_recovered_file("file-empty-05", meta_b, b"")

    resp_b = client.get("/api/recover-file/file-empty-05/download")
    assert resp_b.status_code == 404


# ── Case 6: Missing Output Representation Never Falls Back to Preview ─────────


def test_06_missing_output_never_fabricates_preview_bytes():
    """Verify when output blob is missing/None, download returns 404 and NEVER fabricates preview text."""
    case = store.create_case("Case 6 No Output")
    # Artifact record has content_preview, but no bytes stored in blob store
    rec = ArtifactRecord(
        artifact_id="art-nopayload-06",
        case_id=case.case_id,
        format="txt",
        status="PARTIALLY_RECOVERED",
        confidence_score=50.0,
        verified_bytes=20,
        reconstructed_bytes=0,
        missing_bytes=10,
        is_downloadable=True,
        content_preview="This is preview text from an earlier stage",
    )
    store.save_artifact_record(rec)
    # Explicitly do NOT call store.store_artifact_bytes

    resp = client.get("/api/artifacts/art-nopayload-06/download")
    assert resp.status_code == 404
    # Must never return the preview text encoded as bytes!
    assert resp.content != b"This is preview text from an earlier stage"


# ── Case 7: Malformed Hex Output Handled Safely ──────────────────────────────


def test_07_malformed_hex_output_safely_handled():
    """Verify malformed hex in run output safely yields empty bytes and 404 download."""
    run = RecoveryRun(
        run_id="run-bad-hex",
        filename="corrupt.bin",
        format="bin",
        status="CORRUPTED",
        started_at=datetime.now(timezone.utc),
        total_input_bytes=100,
        total_verified_bytes=50,
        total_reconstructed_bytes=0,
        total_missing_bytes=50,
        output={"recovered_bytes": "NOT_HEX_CHARS_ZZZ!!"},
    )
    rec_bytes = extract_recovered_bytes(run)
    assert rec_bytes == b""

    meta_b = {
        "file_id": "file-bad-hex-07",
        "original_filename": "corrupt.bin",
        "format": "bin",
        "status": "CORRUPTED",
        "confidence_score": 30.0,
        "verified_bytes": 50,
        "reconstructed_bytes": 0,
        "missing_bytes": 50,
        "reconstruction_method": "NONE",
        "validation_status": "FAILED",
        "is_downloadable": False,
        "score_breakdown": {},
        "validation_details": {},
    }
    store.store_recovered_file("file-bad-hex-07", meta_b, rec_bytes)
    resp = client.get("/api/recover-file/file-bad-hex-07/download")
    assert resp.status_code == 404


# ── Case 8: Payload with Embedded Null Bytes ─────────────────────────────────


def test_08_payload_with_embedded_null_bytes():
    """Verify payload containing embedded null bytes round-trips without truncation."""
    payload_with_nulls = b"HEADER\x00\x00\x00MIDDLE\x00\xff\x00TRAILER\x00"
    sha = hashlib.sha256(payload_with_nulls).hexdigest()

    case = store.create_case("Case 8 Nulls")
    rec = ArtifactRecord(
        artifact_id="art-nulls-08",
        case_id=case.case_id,
        format="bin",
        status="FULLY_RECOVERED",
        confidence_score=90.0,
        verified_bytes=len(payload_with_nulls),
        reconstructed_bytes=0,
        missing_bytes=0,
        total_input_bytes=len(payload_with_nulls),
        is_downloadable=True,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes("art-nulls-08", payload_with_nulls)

    resp = client.get("/api/artifacts/art-nulls-08/download")
    assert resp.status_code == 200
    assert resp.content == payload_with_nulls
    assert len(resp.content) == len(payload_with_nulls)
    assert hashlib.sha256(resp.content).hexdigest() == sha


# ── Case 9: Binary Payload Containing Non-Text Bytes ─────────────────────────


def test_09_binary_payload_non_text_bytes():
    """Verify high-ASCII and non-printable binary bytes preserve exact byte-level integrity."""
    raw_binary = bytes(range(256))
    sha = hashlib.sha256(raw_binary).hexdigest()

    case = store.create_case("Case 9 Binary")
    rec = ArtifactRecord(
        artifact_id="art-bin-09",
        case_id=case.case_id,
        format="bin",
        status="FULLY_RECOVERED",
        confidence_score=95.0,
        verified_bytes=256,
        reconstructed_bytes=0,
        missing_bytes=0,
        total_input_bytes=256,
        is_downloadable=True,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes("art-bin-09", raw_binary)

    resp = client.get("/api/artifacts/art-bin-09/download")
    assert resp.status_code == 200
    assert resp.content == raw_binary
    assert hashlib.sha256(resp.content).hexdigest() == sha


# ── Case 10: Metadata Conflicts with Recovery Status ──────────────────────────


def test_10_metadata_conflicts_with_unrecoverable_status():
    """Verify recovery status authoritatively overrides conflicting metadata['is_downloadable']=True."""
    case = store.create_case("Case 10 Conflict")
    # ArtifactResponse has status="UNRECOVERABLE", but metadata claims is_downloadable=True
    art_resp = ArtifactResponse(
        artifact_id="art-conflict-10",
        case_id=case.case_id,
        format="bin",
        size_bytes=100,
        confidence_score=0,
        score_breakdown=ConfidenceBreakdownSchema(
            header_validity=0,
            footer_validity=0,
            structural_validation=0,
            size_plausibility=0,
            reconstruction_integrity=0,
            total=0,
        ),
        status="UNRECOVERABLE",
        provenance=ArtifactProvenanceSchema(
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=100,
            reconstruction_method="NONE",
            validation_status="FAILED",
        ),
        metadata={"is_downloadable": True},
    )
    # from_artifact_response must force is_downloadable=False
    rec = ArtifactRecord.from_artifact_response(art_resp)
    assert rec.is_downloadable is False

    store.save_artifact_record(rec)
    store.store_artifact_bytes("art-conflict-10", b"some bytes that should not be downloadable")

    resp = client.get("/api/artifacts/art-conflict-10/download")
    assert resp.status_code == 404

    # Pipeline B metadata conflict
    meta_b = {
        "file_id": "file-conflict-10",
        "original_filename": "corrupt.bin",
        "format": "bin",
        "status": "UNRECOVERABLE",
        "confidence_score": 0.0,
        "verified_bytes": 0,
        "reconstructed_bytes": 0,
        "missing_bytes": 100,
        "reconstruction_method": "NONE",
        "validation_status": "FAILED",
        "is_downloadable": True,  # Conflicting metadata!
        "score_breakdown": {},
        "validation_details": {},
    }
    store.store_recovered_file("file-conflict-10", meta_b, b"fake payload")
    resp_b = client.get("/api/recover-file/file-conflict-10/download")
    assert resp_b.status_code == 404


# ── Case 11: Stored Size Conflicts with Payload ──────────────────────────────


def test_11_stored_size_conflicts_with_actual_payload():
    """Verify download serves actual blob bytes (not fabricated padding) when size fields disagree."""
    case = store.create_case("Case 11 Size Discrepancy")
    actual_payload = b"short payload of 22 b."
    rec = ArtifactRecord(
        artifact_id="art-size-11",
        case_id=case.case_id,
        format="txt",
        status="PARTIALLY_RECOVERED",
        confidence_score=60.0,
        verified_bytes=1000,  # Discrepancy: claims 1000 verified bytes
        reconstructed_bytes=0,
        missing_bytes=500,
        total_input_bytes=1500,
        is_downloadable=True,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes("art-size-11", actual_payload)

    resp = client.get("/api/artifacts/art-size-11/download")
    assert resp.status_code == 200
    assert resp.content == actual_payload
    assert len(resp.content) == 22


# ── Case 12: Download Eligibility Conflicts with Payload ──────────────────────


def test_12_download_eligibility_false_with_stored_payload():
    """Verify artifact with is_downloadable=False returns 404 even if bytes exist in store."""
    case = store.create_case("Case 12 Non-Downloadable")
    payload = b"hidden bytes"
    rec = ArtifactRecord(
        artifact_id="art-nodl-12",
        case_id=case.case_id,
        format="bin",
        status="CORRUPTED",
        confidence_score=20.0,
        verified_bytes=len(payload),
        reconstructed_bytes=0,
        missing_bytes=100,
        total_input_bytes=len(payload) + 100,
        is_downloadable=False,
    )
    store.save_artifact_record(rec)
    store.store_artifact_bytes("art-nodl-12", payload)

    resp = client.get("/api/artifacts/art-nodl-12/download")
    assert resp.status_code == 404


# ── Persistence Corruption Handling Tests (SqliteStore) ──────────────────────


def test_persistence_absent_vs_empty_vs_corrupted_json(tmp_path):
    """Verify parse_persisted_json distinguishes absent/empty from corrupted/type-mismatched JSON."""
    # 1. Absent (None): default returned, not bad
    val, bad = _parse_persisted_json(None, dict, default={})
    assert val == {}
    assert bad is False

    # 2. Empty string: default returned, not bad
    val, bad = _parse_persisted_json("", list, default=[])
    assert val == []
    assert bad is False

    val, bad = _parse_persisted_json("   ", dict, default={})
    assert val == {}
    assert bad is False

    # 3. Corrupted / Malformed JSON: default returned, bad is TRUE
    val, bad = _parse_persisted_json("NOT_VALID_JSON{", dict, default={})
    assert val == {}
    assert bad is True

    val, bad = _parse_persisted_json('{"unclosed": ', list, default=[])
    assert val == []
    assert bad is True

    # 4. Type mismatch: valid JSON but wrong type -> bad is TRUE
    val, bad = _parse_persisted_json("12345", dict, default={})
    assert val == {}
    assert bad is True

    val, bad = _parse_persisted_json('{"key": "value"}', list, default=[])
    assert val == []
    assert bad is True

    # 5. Non-string primitive (e.g. integer in database column): bad is TRUE
    val, bad = _parse_persisted_json(999, dict, default={})
    assert val == {}
    assert bad is True

    # 6. Valid JSON matching expected type: parsed returned, bad is FALSE
    val, bad = _parse_persisted_json('{"score": 90}', dict, default={})
    assert val == {"score": 90}
    assert bad is False

    val, bad = _parse_persisted_json('["frag_1", "frag_2"]', list, default=[])
    assert val == ["frag_1", "frag_2"]
    assert bad is False


def test_sqlite_store_column_level_corruption_isolation(tmp_path):
    """Verify SqliteStore isolates corrupted JSON columns without crashing or losing uncorrupted columns."""
    db_file = str(tmp_path / "corruption_isolation.db")
    sql_store = SqliteStore(db_file)
    case = sql_store.create_case("Corruption Isolation Test")

    # Insert an artifact where only fragments_json and damage_regions_json are corrupt,
    # but score_breakdown_json and metadata_json are valid JSON.
    valid_sb = {"header_validity": 20, "footer_validity": 20, "total": 40}
    valid_meta = {"user_tag": "investigation_alpha"}

    with sql_store._engine.transaction() as cur:
        cur.execute(
            """
            INSERT INTO artifacts (
                artifact_id, case_id, format, status, confidence_score,
                verified_bytes, reconstructed_bytes, missing_bytes, total_input_bytes,
                reconstruction_method, validation_status, is_downloadable,
                score_breakdown_json, provenance_json, validation_details_json,
                metadata_json, fragments_json, damage_regions_json, reconstruction_steps_json
            ) VALUES (
                'art-isolated', ?, 'json', 'PARTIALLY_RECOVERED', 40.0,
                400, 0, 100, 500,
                'NONE', 'PASSED', 1,
                ?, '{}', '{}',
                ?, 'CORRUPT_FRAGMENTS_NOT_JSON', 'CORRUPT_DAMAGE_NOT_JSON', NULL
            );
            """,
            (case.case_id, json.dumps(valid_sb), json.dumps(valid_meta)),
        )

    record = sql_store.get_artifact_record("art-isolated")
    assert record is not None
    assert record.artifact_id == "art-isolated"
    # Valid columns preserved
    assert record.score_breakdown == valid_sb
    assert record.metadata == valid_meta
    # Absent/default columns are cleanly default and NOT in corrupted_fields
    assert record.provenance == {}
    assert record.validation_details == {}
    assert record.reconstruction_steps is None
    # Corrupted columns are defaulted safely AND recorded in corrupted_fields
    assert record.fragments is None
    assert record.damage_regions is None
    assert record.corrupted_fields is not None
    assert "fragments_json" in record.corrupted_fields
    assert "damage_regions_json" in record.corrupted_fields
    assert "score_breakdown_json" not in record.corrupted_fields
    assert "metadata_json" not in record.corrupted_fields
    assert "provenance_json" not in record.corrupted_fields

    # Verify to_artifact_response exports _corrupted_fields in metadata for API consumers
    resp = record.to_artifact_response()
    assert "_corrupted_fields" in resp.metadata
    assert "fragments_json" in resp.metadata["_corrupted_fields"]

    sql_store.close()


def test_sqlite_store_recovery_run_corruption_isolation(tmp_path):
    """Verify SqliteStore recovery_runs column corruption isolation."""
    db_file = str(tmp_path / "run_corruption.db")
    sql_store = SqliteStore(db_file)
    case = sql_store.create_case("Run Corruption Test")

    now_iso = datetime.now(timezone.utc).isoformat()
    valid_events = [
        {
            "event_id": "evt_1",
            "run_id": "run-corr-01",
            "sequence": 1,
            "event_type": "DISCOVERY",
            "timestamp": now_iso,
            "message": "Carved fragment",
            "relevant_fragment_ids": [],
        }
    ]

    with sql_store._engine.transaction() as cur:
        cur.execute(
            """
            INSERT INTO recovery_runs (
                run_id, case_id, artifact_id, filename, format, status,
                started_at, total_input_bytes, total_verified_bytes,
                total_reconstructed_bytes, total_missing_bytes,
                fragments_json, damage_regions_json, reconstruction_steps_json,
                events_json, validation_json, confidence_json, provenance_json, output_json
            ) VALUES (
                'run-corr-01', ?, 'art-01', 'sample.bin', 'bin', 'PARTIALLY_RECOVERED',
                ?, 100, 80, 0, 20,
                'CORRUPT_FRAGS', '[]', 'CORRUPT_STEPS',
                ?, '{}', '{}', '{}', '{"recovered_bytes": "616263"}'
            );
            """,
            (case.case_id, now_iso, json.dumps(valid_events)),
        )

    run = sql_store.get_recovery_run("run-corr-01")
    assert run is not None
    assert run.run_id == "run-corr-01"
    # Valid columns preserved
    assert len(run.events) == 1
    assert run.events[0].event_id == "evt_1"
    assert run.output == {"recovered_bytes": "616263"}
    # Absent columns are safely None or []
    assert run.damage_regions == []
    # Corrupted columns recorded
    assert run.corrupted_fields is not None
    assert "fragments_json" in run.corrupted_fields
    assert "reconstruction_steps_json" in run.corrupted_fields
    assert "events_json" not in run.corrupted_fields
    assert "output_json" not in run.corrupted_fields

    sql_store.close()


# ── Negative Offset Validation Tests ──────────────────────────────────────────


def test_negative_offset_validation_rejected():
    """Verify negative offsets in Fragment and DamageRegion are rejected by Pydantic model validation."""
    # DamageRegion start_offset must be >= 0
    with pytest.raises(ValidationError):
        DamageRegion(
            region_id="dr_neg",
            start_offset=-1,
            end_offset=10,
            length=11,
            type="MISSING",
            status="DETECTED",
        )

    # Valid DamageRegion succeeds
    dr = DamageRegion(
        region_id="dr_valid",
        start_offset=0,
        end_offset=10,
        length=10,
        type="MISSING",
        status="DETECTED",
    )
    assert dr.start_offset == 0
    assert dr.end_offset == 10

    # Fragment offset must be >= 0
    with pytest.raises(ValidationError):
        Fragment(
            fragment_id="frag_neg",
            offset=-5,
            length=20,
            end_offset=15,
            status="VERIFIED",
            source="carved",
            format="bin",
            verified_bytes=20,
            reconstructed_bytes=0,
            missing_bytes=0,
            validation_status="PASSED",
        )

    # Valid Fragment succeeds
    frag = Fragment(
        fragment_id="frag_valid",
        offset=0,
        length=20,
        end_offset=20,
        status="VERIFIED",
        source="carved",
        format="bin",
        verified_bytes=20,
        reconstructed_bytes=0,
        missing_bytes=0,
        validation_status="PASSED",
    )
    assert frag.offset == 0
    assert frag.length == 20
