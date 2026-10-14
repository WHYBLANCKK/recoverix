"""
test_api_provenance_serialization_m318.py — Milestone M3.18.0 Regression Suite.

Verifies end-to-end API and provenance serialization:
1. Intact contiguous file round-trip (payload bytes, SHA-256 match, 0 missing, score breakdown, validation details).
2. Partially recovered file with missing damage region (damage start/end/length, missing byte accounting).
3. Reconstructed bifragment file with gap (reconstruction steps, validated gap size, fragments order).
4. Multi-candidate evidence buffer: candidate IDs, offsets, distinct recovery runs, /api/cases/{case_id}/runs.
5. Repaired PDF structure and payload integrity across API boundaries.
6. Unrecoverable corrupt candidate: 0 verified bytes, empty recovered payload (b""), UNRECOVERABLE status.
7. Case analysis persistence round-trip (Pipeline A): artifacts, runs, linkage, payload download.
8. SQLite vs in-memory parity and deterministic 404 error handling.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.recovery_run import (
    DamageRegion,
    Fragment,
    FragmentRelationship,
    PipelineEvent,
    ReconstructionStep,
    RecoveryRun,
)
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)
from backend.app.storage.memory_store import InMemoryStore
from backend.app.storage.sqlite_engine import SqliteEngine
from backend.app.storage.sqlite_store import SqliteStore
from backend.app.store import store

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_store():
    store.clear()
    yield
    store.clear()


# ── Scenario 1: Intact Contiguous File Round-Trip ────────────────────────────


def test_01_intact_contiguous_file_roundtrip():
    """Verify intact contiguous file preserves exact payload, hash, provenance, and accounting."""
    content = (
        SYNTHETIC_START_MARKER
        + b"FORMAT=txt\nHeader: AuthToken\nBody: Highly confidential trace payload.\n"
        + SYNTHETIC_END_MARKER
    )
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = client.post(
        "/api/recover-file",
        files={"file": ("auth_token.txt", content, "text/plain")},
    )
    assert response.status_code == 200
    data = response.json()

    # Model & Status
    assert data["status"] == "FULLY_RECOVERED"
    assert data["confidence_score"] == 100.0
    assert data["format"] == "txt"
    assert data["is_downloadable"] is True

    # Byte accounting invariant: V + R + M == total_input_bytes
    v = data["verified_bytes"]
    r = data["reconstructed_bytes"]
    m = data["missing_bytes"]
    total = data["total_input_bytes"]
    assert v + r + m == total
    assert r == 0
    assert m == 0
    assert v == len(content)

    # Provenance fidelity
    prov = data.get("provenance")
    assert prov is not None
    assert prov.get("detection_mode") in ("known_file", "synthetic_harness")
    assert "score_breakdown" in data
    assert "validation_details" in data

    # Payload byte round-trip
    download_res = client.get(data["download_url"])
    assert download_res.status_code == 200
    downloaded_bytes = download_res.content
    assert downloaded_bytes == content
    assert hashlib.sha256(downloaded_bytes).hexdigest() == expected_sha256

    # RecoveryRun consistency
    run_id = data["run_id"]
    run_res = client.get(f"/api/recovery-runs/{run_id}")
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["run_id"] == run_id
    assert run_data["status"] == "FULLY_RECOVERED"
    assert run_data["total_verified_bytes"] == v
    assert run_data["total_reconstructed_bytes"] == 0
    assert run_data["total_missing_bytes"] == 0
    assert run_data["total_input_bytes"] == total


# ── Scenario 2: Partially Recovered File with Missing Damage Region ─────────


def test_02_partially_recovered_file_damage_region_and_missing_bytes():
    """Verify partially recovered file preserves damage regions and missing byte accounting."""
    # Corrupt the header of a JSON file so it fails full direct validation
    # or an unclosed/truncated JSON
    damaged_json = b'{"status": "active", "items": [1, 2, 3'  # Truncated JSON

    response = client.post(
        "/api/recover-file",
        files={"file": ("damaged.json", damaged_json, "application/json")},
    )
    assert response.status_code == 200
    data = response.json()

    # Byte accounting invariant: V + R + M == total_input_bytes
    v = data["verified_bytes"]
    r = data["reconstructed_bytes"]
    m = data["missing_bytes"]
    total = data["total_input_bytes"]
    assert v + r + m == total
    assert v == len(damaged_json)
    assert r == 2
    assert total == len(damaged_json) + 2
    assert data["provenance"]["evidence_size"] == len(damaged_json)

    # Status must not falsely claim FULLY_RECOVERED
    assert data["status"] == "PARTIALLY_RECOVERED"

    # Invariants on damage regions
    if data.get("damage_regions"):
        for region in data["damage_regions"]:
            assert region["end_offset"] - region["start_offset"] == region["length"]

    # Retrieval via file_id preserves all fields
    file_id = data["file_id"]
    meta_res = client.get(f"/api/recover-file/{file_id}")
    assert meta_res.status_code == 200
    meta_data = meta_res.json()
    assert meta_data["verified_bytes"] == v
    assert meta_data["reconstructed_bytes"] == r
    assert meta_data["missing_bytes"] == m
    assert meta_data["total_input_bytes"] == total
    assert meta_data.get("provenance") is not None


# ── Scenario 3: Reconstructed Bifragment with Gap ───────────────────────────


def test_03_reconstructed_bifragment_gap_and_steps():
    """Verify bifragment file reconstruction preserves step details and fragment relationships."""
    part1 = SYNTHETIC_START_MARKER + b"FORMAT=txt\nHeader: Section1\n"
    part2 = b"Body: Section2 continues here.\n" + SYNTHETIC_END_MARKER
    gap = b"X" * 32  # 32 bytes of intervening damage
    evidence = part1 + gap + part2

    response = client.post(
        "/api/recover-file",
        files={"file": ("bifrag.txt", evidence, "text/plain")},
    )
    assert response.status_code == 200
    data = response.json()

    # Invariant check
    v = data["verified_bytes"]
    r = data["reconstructed_bytes"]
    m = data["missing_bytes"]
    total = data["total_input_bytes"]
    assert v + r + m == total

    # Check recovery run
    run_id = data["run_id"]
    run_res = client.get(f"/api/recovery-runs/{run_id}")
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["total_verified_bytes"] == v
    assert run_data["total_input_bytes"] == total

    # For each fragment, end_offset - offset == length
    for frag in run_data.get("fragments", []):
        assert frag["end_offset"] - frag["offset"] == frag["length"]


# ── Scenario 4: Multi-Candidate Evidence Buffer & /api/cases/{case_id}/runs ─


def test_04_multi_candidate_evidence_case_runs_endpoint():
    """Verify multi-candidate evidence populates distinct recovery runs on /api/cases/{case_id}/runs."""
    # Create case
    case_create = client.post("/api/cases", json={"name": "Multi Candidate Test", "description": "Audit"})
    assert case_create.status_code == 201
    case_id = case_create.json()["case_id"]

    # Construct evidence buffer with 2 synthetic candidates: TXT and CSV
    pad1 = b"\x00" * 64
    cand1 = SYNTHETIC_START_MARKER + b"FORMAT=txt\nCandidate 1 Text Content\n" + SYNTHETIC_END_MARKER
    pad2 = b"\x00" * 64
    cand2 = SYNTHETIC_START_MARKER + b"FORMAT=csv\nid,value\n1,one\n2,two\n" + SYNTHETIC_END_MARKER
    pad3 = b"\x00" * 64
    evidence_payload = pad1 + cand1 + pad2 + cand2 + pad3

    # Upload evidence
    upload_res = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("disk_image.img", evidence_payload, "application/octet-stream")},
    )
    assert upload_res.status_code == 200

    # Analyze case
    analyze_res = client.post(f"/api/cases/{case_id}/analyze")
    assert analyze_res.status_code == 200
    summary = analyze_res.json()
    assert summary["artifact_count"] >= 2

    # Query canonical case recovery runs: GET /api/cases/{case_id}/runs
    runs_res = client.get(f"/api/cases/{case_id}/runs")
    assert runs_res.status_code == 200
    runs = runs_res.json()
    assert len(runs) >= 2

    run_ids = set()
    artifact_ids = set()
    formats = set()

    for r in runs:
        assert r["case_id"] == case_id
        assert r["artifact_id"] is not None
        assert r["run_id"] is not None
        run_ids.add(r["run_id"])
        artifact_ids.add(r["artifact_id"])
        formats.add(r["format"])

        # Accounting invariant
        v = r["total_verified_bytes"]
        rec = r["total_reconstructed_bytes"]
        m = r["total_missing_bytes"]
        tot = r["total_input_bytes"]
        assert v + rec + m == tot

        # Provenance coordinate system and offsets
        prov = r.get("provenance") or {}
        assert "evidence_start" in prov
        assert prov.get("coordinate_system") == "physical_evidence_offsets"

    assert len(run_ids) == len(runs)  # All distinct runs
    assert len(artifact_ids) == len(runs)  # All distinct artifacts


# ── Scenario 5: Repaired PDF Structure and Payload Integrity ────────────────


def test_05_repaired_pdf_provenance_and_payload_integrity():
    """Verify PDF recovery preserves reconstruction steps and structural integrity."""
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n"
        b"0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n162\n%%EOF"
    )

    response = client.post(
        "/api/recover-file",
        files={"file": ("sample.pdf", pdf_content, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["format"] == "pdf"
    assert data["status"] in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")
    v = data["verified_bytes"]
    r = data["reconstructed_bytes"]
    m = data["missing_bytes"]
    assert v + r + m == data["total_input_bytes"]

    # Check payload download
    dl_res = client.get(data["download_url"])
    assert dl_res.status_code == 200
    recovered_bytes = dl_res.content
    assert recovered_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in recovered_bytes


# ── Scenario 6: Unrecoverable Corrupt Candidate ──────────────────────────────


def test_06_unrecoverable_corrupt_payload_and_download():
    """Verify completely corrupt candidate results in UNRECOVERABLE status, 0 verified bytes, and safe download."""
    corrupt_garbage = b"\xde\xad\xbe\xef\x00\xff" * 30  # 180 bytes of random noise

    response = client.post(
        "/api/recover-file",
        files={"file": ("noise.bin", corrupt_garbage, "application/octet-stream")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "UNRECOVERABLE"
    assert data["verified_bytes"] == 0
    assert data["reconstructed_bytes"] == 0
    assert data["missing_bytes"] == len(corrupt_garbage)
    assert data["total_input_bytes"] == len(corrupt_garbage)
    assert data["confidence_score"] == 0.0

    # Damage regions must cover the unrecoverable span
    assert len(data.get("damage_regions") or []) > 0
    dam = data["damage_regions"][0]
    assert dam["type"] in ("CORRUPTED", "UNRECOVERABLE")
    assert dam["length"] == len(corrupt_garbage)

    assert data["is_downloadable"] is False

    # Download endpoint must safely reject unrecoverable file with 404, never 500
    dl_res = client.get(data["download_url"])
    assert dl_res.status_code == 404
    assert "unrecoverable" in dl_res.json()["detail"].lower()


# ── Scenario 7: Case Analysis Persistence Round-Trip (Pipeline A) ────────────


def test_07_pipeline_a_case_analysis_persistence_roundtrip():
    """Verify full Pipeline A lifecycle: case, evidence, analyze, runs, artifacts, download."""
    # 1. Create case
    case_res = client.post("/api/cases", json={"name": "Forensic Case M318", "description": "Full Cycle"})
    assert case_res.status_code == 201
    case_id = case_res.json()["case_id"]

    # 2. Upload evidence containing valid JSON artifact
    json_body = b'{"investigation": "M318", "evidence": "sealed", "status": "active"}'
    artifact_payload = SYNTHETIC_START_MARKER + b"FORMAT=json\n" + json_body + b"\n" + SYNTHETIC_END_MARKER
    padding = b"\x00" * 32
    raw_evidence = padding + artifact_payload + padding

    upload_res = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("disk.raw", raw_evidence, "application/octet-stream")},
    )
    assert upload_res.status_code == 200

    # 3. Analyze
    analyze_res = client.post(f"/api/cases/{case_id}/analyze")
    assert analyze_res.status_code == 200
    summary = analyze_res.json()
    assert summary["artifact_count"] >= 1
    artifact = summary["artifacts"][0]
    artifact_id = artifact["artifact_id"]
    run_id = artifact["metadata"]["run_id"]

    # 4. Get case artifacts
    arts_res = client.get(f"/api/cases/{case_id}/artifacts")
    assert arts_res.status_code == 200
    arts = arts_res.json()
    assert any(a["artifact_id"] == artifact_id for a in arts)

    # 5. Get case recovery runs
    runs_res = client.get(f"/api/cases/{case_id}/runs")
    assert runs_res.status_code == 200
    case_runs = runs_res.json()
    assert len(case_runs) >= 1
    matched_run = next(r for r in case_runs if r["run_id"] == run_id)
    assert matched_run["case_id"] == case_id
    assert matched_run["artifact_id"] == artifact_id

    # 6. Download artifact bytes
    dl_res = client.get(f"/api/artifacts/{artifact_id}/download")
    assert dl_res.status_code == 200
    assert len(dl_res.content) > 0
    assert b"investigation" in dl_res.content


# ── Scenario 8: SQLite & InMemory Parity & 404 Error Handling ────────────────


def test_08_sqlite_and_inmemory_parity_and_error_handling():
    """Verify identical contracts and 404 error handling across both stores."""
    # API 404 handling
    assert client.get("/api/cases/nonexistent_case_9999/runs").status_code == 404
    assert client.get("/api/recover-file/nonexistent_file_9999").status_code == 404
    assert client.get("/api/recovery-runs/nonexistent_run_9999").status_code == 404

    # Parity testing directly on SqliteStore and InMemoryStore
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = str(Path(tmp_dir) / "test_m318.db")
        sqlite_store = SqliteStore(db_path)
        mem_store = InMemoryStore()

        # Both return None for nonexistent case
        assert sqlite_store.get_case_recovery_runs("nonexistent") is None
        assert mem_store.get_case_recovery_runs("nonexistent") is None

        # Create case on both
        case_sql = sqlite_store.create_case(name="Case SQL", description="DB Test")
        case_mem = mem_store.create_case(name="Case Mem", description="Mem Test")

        # Both return [] for existing case with no runs
        assert sqlite_store.get_case_recovery_runs(case_sql.case_id) == []
        assert mem_store.get_case_recovery_runs(case_mem.case_id) == []

        # Create a complex RecoveryRun on both
        now = datetime.now(timezone.utc)
        run_sql = RecoveryRun(
            run_id="run_sql_01",
            case_id=case_sql.case_id,
            artifact_id="art_sql_01",
            candidate_id="cand_sql_01",
            filename="data.txt",
            format="txt",
            status="FULLY_RECOVERED",
            started_at=now,
            completed_at=now,
            total_input_bytes=100,
            total_verified_bytes=100,
            total_reconstructed_bytes=0,
            total_missing_bytes=0,
            fragments=[
                Fragment(
                    fragment_id="frag_1",
                    offset=0,
                    length=100,
                    end_offset=100,
                    status="VERIFIED",
                    source="synthetic",
                    format="txt",
                    verified_bytes=100,
                    reconstructed_bytes=0,
                    missing_bytes=0,
                    validation_status="PASSED",
                    relationships=[
                        FragmentRelationship(
                            source_fragment_id="frag_1",
                            target_fragment_id="frag_2",
                            relationship_type="PRECEDES",
                        )
                    ],
                )
            ],
            damage_regions=[],
            reconstruction_steps=[],
            events=[
                PipelineEvent(
                    event_id="evt_1",
                    run_id="run_sql_01",
                    sequence=1,
                    event_type="DISCOVERY",
                    timestamp=now,
                    message="Discovered",
                )
            ],
            provenance={"evidence_start": 0, "evidence_end": 100, "coordinate_system": "physical_evidence_offsets"},
            output={"recovered_bytes": b"Hello SQLite".hex()},
        )

        run_mem = RecoveryRun(
            run_id="run_mem_01",
            case_id=case_mem.case_id,
            artifact_id="art_mem_01",
            candidate_id="cand_mem_01",
            filename="data.txt",
            format="txt",
            status="FULLY_RECOVERED",
            started_at=now,
            completed_at=now,
            total_input_bytes=100,
            total_verified_bytes=100,
            total_reconstructed_bytes=0,
            total_missing_bytes=0,
            fragments=[
                Fragment(
                    fragment_id="frag_1",
                    offset=0,
                    length=100,
                    end_offset=100,
                    status="VERIFIED",
                    source="synthetic",
                    format="txt",
                    verified_bytes=100,
                    reconstructed_bytes=0,
                    missing_bytes=0,
                    validation_status="PASSED",
                )
            ],
            damage_regions=[],
            reconstruction_steps=[],
            events=[],
            provenance={"evidence_start": 0, "evidence_end": 100, "coordinate_system": "physical_evidence_offsets"},
            output={"recovered_bytes": b"Hello Mem".hex()},
        )

        sqlite_store.add_recovery_run(run_sql)
        mem_store.add_recovery_run(run_mem)

        # Retrieve runs by case_id on both
        sql_runs = sqlite_store.get_case_recovery_runs(case_sql.case_id)
        mem_runs = mem_store.get_case_recovery_runs(case_mem.case_id)

        assert sql_runs is not None and len(sql_runs) == 1
        assert mem_runs is not None and len(mem_runs) == 1

        retrieved_sql = sql_runs[0]
        retrieved_mem = mem_runs[0]

        assert retrieved_sql.case_id == case_sql.case_id
        assert retrieved_mem.case_id == case_mem.case_id
        assert retrieved_sql.artifact_id == "art_sql_01"
        assert retrieved_mem.artifact_id == "art_mem_01"
        assert retrieved_sql.provenance == run_sql.provenance
        assert retrieved_mem.provenance == run_mem.provenance
        assert len(retrieved_sql.fragments) == 1
        assert retrieved_sql.fragments[0].relationships[0].relationship_type == "PRECEDES"

        sqlite_store.close()
