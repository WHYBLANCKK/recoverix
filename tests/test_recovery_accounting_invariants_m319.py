"""
test_recovery_accounting_invariants_m319.py — Recovery Accounting and Persistence Invariant Audit Test Suite.

Milestone M3.19.0:
- Verifies byte accounting invariants: total_verified_bytes + total_missing_bytes == total_input_bytes, and total_verified_bytes + total_reconstructed_bytes == recovered_bytes
- Verifies exact payload byte and SHA-256 round-trip integrity across storage boundaries
- Verifies multi-candidate provenance, Fragment, and DamageRegion span invariants (end_offset - start_offset == length)
- Verifies payload size disambiguation (size_bytes vs total_input_bytes)
- Verifies safe JSON tolerance and bi-directional linkage fallbacks
"""

import hashlib
import json
import sqlite3
import pytest
from datetime import datetime, timezone

from backend.app.models.artifact import (
    ArtifactProvenanceSchema,
    ArtifactRecord,
    ArtifactResponse,
    ConfidenceBreakdownSchema,
)
from backend.app.models.recovery_run import DamageRegion, Fragment, RecoveryRun
from backend.app.recovery.tracer import execute_traced_recovery
from backend.app.storage.memory_store import InMemoryStore
from backend.app.storage.sqlite_store import SqliteStore


# ── Test 1: Byte Accounting Invariant (V + M == total_input_bytes, V + R == recovered_bytes) ────────


def test_accounting_invariant_across_recovery_statuses(tmp_path):
    """Verify that V + M == total_input_bytes and V + R == recovered_bytes across all recovery execution paths."""
    # 1. FULLY_RECOVERED (Clean JSON)
    valid_json = b'{"name": "Recoverix", "status": "active", "code": 100}'
    run_full = execute_traced_recovery(
        filename="test.json",
        content=valid_json,
        case_id="case-1",
        artifact_id="art-1",
    )
    assert run_full.status == "FULLY_RECOVERED"
    assert (
        run_full.total_verified_bytes
        + run_full.total_missing_bytes
        == run_full.total_input_bytes
    )
    assert run_full.total_input_bytes == len(valid_json)
    assert run_full.total_verified_bytes == len(valid_json)
    assert run_full.total_missing_bytes == 0
    assert run_full.total_reconstructed_bytes == 0
    recovered_full = bytes.fromhex(run_full.output["recovered_bytes"])
    assert len(recovered_full) == run_full.total_verified_bytes + run_full.total_reconstructed_bytes

    # 2. PARTIALLY_RECOVERED (Truncated JSON with reconstruction)
    trunc_json = b'{"name": "Recoverix", "items": [1, 2, 3'
    run_part = execute_traced_recovery(
        filename="test_trunc.json",
        content=trunc_json,
        case_id="case-1",
        artifact_id="art-2",
    )
    assert run_part.status == "PARTIALLY_RECOVERED"
    assert (
        run_part.total_verified_bytes
        + run_part.total_missing_bytes
        == run_part.total_input_bytes
    )
    assert run_part.total_input_bytes == len(trunc_json)
    assert run_part.total_verified_bytes == len(trunc_json)
    assert run_part.total_reconstructed_bytes > 0
    recovered_part = bytes.fromhex(run_part.output["recovered_bytes"])
    assert len(recovered_part) == run_part.total_verified_bytes + run_part.total_reconstructed_bytes

    # 3. UNRECOVERABLE (High entropy random garbage)
    garbage = b"\x00\xff\x1a\x2b\x3c\x4d\x5e\x6f" * 30
    run_unrec = execute_traced_recovery(
        filename="unrec.bin",
        content=garbage,
        case_id="case-1",
        artifact_id="art-3",
    )
    assert run_unrec.status == "UNRECOVERABLE"
    assert (
        run_unrec.total_verified_bytes
        + run_unrec.total_missing_bytes
        == run_unrec.total_input_bytes
    )
    assert run_unrec.total_input_bytes == len(garbage)
    assert run_unrec.total_verified_bytes == 0
    assert run_unrec.total_reconstructed_bytes == 0
    assert run_unrec.total_missing_bytes == len(garbage)


# ── Test 2: Payload Size vs Candidate Size Disambiguation ────────────────────


def test_payload_size_vs_candidate_size_disambiguation():
    """Verify size_bytes strictly reflects recovered payload size, not candidate span."""
    # Scenario A: UNRECOVERABLE candidate of 250 bytes
    art_unrec = ArtifactResponse(
        artifact_id="art-unrec",
        case_id="case-100",
        format="unknown",
        size_bytes=0,  # No recovered payload available
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
            missing_bytes=250,
            reconstruction_method="NONE",
            validation_status="FAILED",
        ),
        metadata={"total_input_bytes": 250, "run_id": "run-unrec"},
    )

    rec_unrec = ArtifactRecord.from_artifact_response(art_unrec)
    # Total input bytes must be 250, NOT 0 (art_unrec.size_bytes)
    assert rec_unrec.total_input_bytes == 250
    assert (
        rec_unrec.verified_bytes
        + rec_unrec.reconstructed_bytes
        + rec_unrec.missing_bytes
        == rec_unrec.total_input_bytes
    )
    assert rec_unrec.is_downloadable is False

    # Round trip back to response
    resp_unrec = rec_unrec.to_artifact_response()
    assert resp_unrec.size_bytes == 0
    assert resp_unrec.provenance.missing_bytes == 250
    assert resp_unrec.metadata["total_input_bytes"] == 250

    # Scenario B: PARTIALLY_RECOVERED candidate (4000 recovered, 1000 missing, total 5000)
    art_part = ArtifactResponse(
        artifact_id="art-part",
        case_id="case-100",
        format="csv",
        size_bytes=4000,  # Actual recovered payload is 4000 bytes
        confidence_score=80,
        score_breakdown=ConfidenceBreakdownSchema(
            header_validity=20,
            footer_validity=15,
            structural_validation=25,
            size_plausibility=10,
            reconstruction_integrity=10,
            total=80,
        ),
        status="PARTIALLY_RECOVERED",
        provenance=ArtifactProvenanceSchema(
            verified_bytes=4000,
            reconstructed_bytes=0,
            missing_bytes=1000,
            reconstruction_method="NONE",
            validation_status="PASSED",
        ),
        metadata={"total_input_bytes": 5000, "run_id": "run-part"},
    )

    rec_part = ArtifactRecord.from_artifact_response(art_part)
    assert rec_part.total_input_bytes == 5000
    assert rec_part.verified_bytes == 4000
    assert rec_part.missing_bytes == 1000
    assert (
        rec_part.verified_bytes
        + rec_part.reconstructed_bytes
        + rec_part.missing_bytes
        == rec_part.total_input_bytes
    )

    resp_part = rec_part.to_artifact_response()
    # size_bytes must be 4000, NOT 5000
    assert resp_part.size_bytes == 4000
    assert resp_part.metadata["total_input_bytes"] == 5000


# ── Test 3: Downloadable Flag Invariant ───────────────────────────────────────


def test_downloadable_flag_invariants():
    """Verify is_downloadable is False for UNRECOVERABLE artifacts by default."""
    # From ArtifactResponse
    art_unrec = ArtifactResponse(
        artifact_id="art-d1",
        case_id="case-1",
        format="bin",
        size_bytes=0,
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
    )
    rec_unrec = ArtifactRecord.from_artifact_response(art_unrec)
    assert rec_unrec.is_downloadable is False

    # From file recovery dict
    rec_dict_unrec = ArtifactRecord.from_file_recovery_dict({
        "file_id": "file-d1",
        "status": "UNRECOVERABLE",
        "verified_bytes": 0,
        "missing_bytes": 50,
    })
    assert rec_dict_unrec.is_downloadable is False

    # Non-downloadable artifact always yields size_bytes == 0 in ArtifactResponse
    rec_not_dl = ArtifactRecord(
        artifact_id="art-d2",
        format="txt",
        status="PARTIALLY_RECOVERED",
        confidence_score=50.0,
        verified_bytes=300,
        reconstructed_bytes=0,
        missing_bytes=100,
        is_downloadable=False,
    )
    resp_not_dl = rec_not_dl.to_artifact_response()
    assert resp_not_dl.size_bytes == 0


# ── Test 4: Exact Payload Byte & SHA-256 Round-Trip Across Storage ───────────


@pytest.mark.parametrize("store_type", ["sqlite", "memory"])
def test_payload_byte_and_sha256_roundtrip(tmp_path, store_type):
    """Verify exact payload byte preservation and SHA-256 consistency across storage."""
    if store_type == "sqlite":
        db_path = str(tmp_path / f"test_{store_type}.db")
        store = SqliteStore(db_path)
    else:
        store = InMemoryStore()

    payloads = {
        "empty": b"",
        "null_bytes": b"\x00\x00\xff\xfe\x00\x01\x02\x03\x00\x00\x7f\x80\xff",
        "unicode_utf8": "Forensic Evidence: 🔍 檔案 12345 — ¡Éxito! \u2603".encode("utf-8"),
        "large_binary": bytes([i % 256 for i in range(128 * 1024)]),  # 128 KB
    }

    for name, data in payloads.items():
        key = f"payload-{name}"
        expected_sha = hashlib.sha256(data).hexdigest()

        # Store in artifact blobs
        store.artifact_blobs.put(key, data)
        assert store.artifact_blobs.exists(key) is True

        retrieved = store.artifact_blobs.get(key)
        assert retrieved == data
        assert hashlib.sha256(retrieved).hexdigest() == expected_sha

    if store_type == "sqlite":
        store.close()


# ── Test 5: Fragment and DamageRegion Offset Span Invariants ─────────────────


def test_damage_region_span_invariants():
    """Verify DamageRegion enforces length == end_offset - start_offset."""
    # Valid DamageRegion
    dmg = DamageRegion(
        region_id="dmg-1",
        start_offset=100,
        end_offset=250,
        length=150,
        type="CORRUPTED",
        status="DETECTED",
    )
    assert dmg.length == 150
    assert dmg.end_offset - dmg.start_offset == dmg.length

    # Invalid length mismatch
    with pytest.raises(ValueError, match="does not match end_offset - start_offset"):
        DamageRegion(
            region_id="dmg-bad-len",
            start_offset=100,
            end_offset=250,
            length=140,  # Incorrect length
            type="CORRUPTED",
            status="DETECTED",
        )

    # Inverted offsets (end < start)
    with pytest.raises(ValueError, match="cannot be less than start_offset"):
        DamageRegion(
            region_id="dmg-invert",
            start_offset=200,
            end_offset=100,
            length=-100,
            type="CORRUPTED",
            status="DETECTED",
        )


def test_fragment_span_invariants():
    """Verify Fragment enforces length == end_offset - offset."""
    # Valid Fragment
    frag = Fragment(
        fragment_id="frag-1",
        offset=50,
        end_offset=150,
        length=100,
        status="VERIFIED",
        source="carved",
        format="json",
        verified_bytes=100,
        reconstructed_bytes=0,
        missing_bytes=0,
        validation_status="PASSED",
    )
    assert frag.length == 100
    assert frag.end_offset - frag.offset == frag.length

    # Invalid length mismatch
    with pytest.raises(ValueError, match="does not match end_offset - offset"):
        Fragment(
            fragment_id="frag-bad-len",
            offset=50,
            end_offset=150,
            length=99,
            status="VERIFIED",
            source="carved",
            format="json",
            verified_bytes=99,
            reconstructed_bytes=0,
            missing_bytes=0,
            validation_status="PASSED",
        )

    # Inverted offsets
    with pytest.raises(ValueError, match="cannot be less than offset"):
        Fragment(
            fragment_id="frag-invert",
            offset=150,
            end_offset=50,
            length=-100,
            status="VERIFIED",
            source="carved",
            format="json",
            verified_bytes=0,
            reconstructed_bytes=0,
            missing_bytes=0,
            validation_status="FAILED",
        )


# ── Test 6: Persistence Robustness and Corrupted JSON Tolerance ──────────────


def test_sqlite_store_corrupted_json_tolerance(tmp_path):
    """Verify SqliteStore tolerates malformed JSON columns without uncaught exceptions."""
    db_file = str(tmp_path / "corrupted_json.db")
    store = SqliteStore(db_file)
    case = store.create_case("Corrupted JSON Test")

    # Manually insert a row into artifacts with corrupt JSON strings
    with store._engine.transaction() as cur:
        cur.execute(
            """
            INSERT INTO artifacts (
                artifact_id, case_id, format, status, confidence_score,
                verified_bytes, reconstructed_bytes, missing_bytes, total_input_bytes,
                reconstruction_method, validation_status, is_downloadable,
                score_breakdown_json, provenance_json, validation_details_json,
                metadata_json, fragments_json, damage_regions_json, reconstruction_steps_json
            ) VALUES (
                'art-corrupt', ?, 'json', 'PARTIALLY_RECOVERED', 75.0,
                500, 50, 100, 650,
                'BRACKET_INJECTION', 'PASSED', 1,
                'NOT_VALID_JSON{', '{"unclosed": ', '[[bad json',
                '{invalid metadata', 'corrupt fragments', 'corrupt damage', 'corrupt steps'
            );
            """,
            (case.case_id,),
        )

    # Retrieve record: must not raise JSONDecodeError
    record = store.get_artifact_record("art-corrupt")
    assert record is not None
    assert record.artifact_id == "art-corrupt"
    assert record.score_breakdown == {}
    assert record.provenance == {}
    assert record.validation_details == {}
    assert record.metadata == {}
    assert record.fragments is None
    assert record.damage_regions is None
    assert record.reconstruction_steps is None

    # Retrieve response
    resp = store.get_artifact("art-corrupt")
    assert resp is not None
    assert resp.artifact_id == "art-corrupt"
    assert resp.size_bytes == 550  # 500 verified + 50 reconstructed
    assert resp.status == "PARTIALLY_RECOVERED"

    store.close()


# ── Test 7: Bi-Directional Linkage Fallback (artifact_id <-> run_id) ─────────


@pytest.mark.parametrize("store_type", ["sqlite", "memory"])
def test_bidirectional_linkage_fallback(tmp_path, store_type):
    """Verify get_recovery_run_by_artifact finds runs by recovery_runs.artifact_id fallback."""
    if store_type == "sqlite":
        db_path = str(tmp_path / f"linkage_{store_type}.db")
        store = SqliteStore(db_path)
    else:
        store = InMemoryStore()

    target_art_id = "art-unlinked-target"
    run = RecoveryRun(
        run_id="run-fallback-1",
        artifact_id=target_art_id,  # Direct field on RecoveryRun
        filename="unlinked.txt",
        format="txt",
        status="FULLY_RECOVERED",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        total_input_bytes=100,
        total_verified_bytes=100,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        fragments=[],
        damage_regions=[],
        reconstruction_steps=[],
        events=[],
    )
    store.add_recovery_run(run)

    # Retrieve by artifact_id even though no explicit artifact_runs entry was created
    found_run = store.get_recovery_run_by_artifact(target_art_id)
    assert found_run is not None
    assert found_run.run_id == "run-fallback-1"
    assert found_run.artifact_id == target_art_id

    # Nonexistent artifact returns None
    assert store.get_recovery_run_by_artifact("non-existent-artifact") is None

    if store_type == "sqlite":
        store.close()
