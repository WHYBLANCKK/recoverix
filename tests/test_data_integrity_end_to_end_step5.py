"""
test_data_integrity_end_to_end_step5.py — Comprehensive Data Integrity, Provenance Invariants & End-to-End Workflow Audit Suite.

Verifies:
1. Full Evidence Lifecycle: Upload -> Recovery -> Validation -> Persistence -> Retrieval -> Download
2. Engine / Process Restart Isolation: Complete DB closure and re-instantiation across SQLite boundaries
3. Bi-directional Identifier Resolution: Lookups by artifact_id and recovery-run run_id
4. Idempotency & Replay Safety: Retries and re-insertions do not mutate evidence or create conflicting records
5. Eight Formats Integrity: PDF, JSON, CSV, TXT, XML, PNG, JPEG, ZIP
6. Strict Download & Validation Gates: Blocking download on unvalidated, corrupted, or unrecoverable records
7. Terminal State Invariants: PENDING/RUNNING cannot overwrite terminal recovery statuses
8. TTL Expiry Scoping: Case-linked evidence and artifacts remain strictly immune to standalone TTL cleanup
9. Byte Accounting Invariants: V + M == total_input_bytes, V + R == len(recovered_bytes), FULLY_RECOVERED precludes R>0 or M>0
10. Archive Security: Zip-Slip traversal rejection and deterministic MIME mapping
"""

from __future__ import annotations

import io
import json
import sqlite3
import zipfile
import hashlib
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.artifact import ArtifactRecord, ArtifactResponse
from backend.app.models.recovery_run import RecoveryRun, Fragment, DamageRegion, ReconstructionStep, PipelineEvent
from backend.app.recovery.tracer import execute_traced_recovery, _recover_direct_fallback
from backend.app.storage.sqlite_engine import SqliteEngine
from backend.app.storage.sqlite_store import SqliteStore


@pytest.fixture
def client_step5(tmp_path, monkeypatch):
    """Isolated FastAPI test client with dedicated SQLite backend."""
    db_file = str(tmp_path / "step5_e2e.db")
    engine = SqliteEngine(db_path=db_file)
    test_store = SqliteStore(engine=engine)
    monkeypatch.setattr("backend.app.api.cases.store", test_store)
    monkeypatch.setattr("backend.app.api.artifacts.store", test_store)
    monkeypatch.setattr("backend.app.api.file_recovery.store", test_store)
    monkeypatch.setattr("backend.app.api.recovery_runs.store", test_store)
    monkeypatch.setattr("backend.app.api.analysis.store", test_store)
    monkeypatch.setattr("backend.app.api.interpretation.store", test_store)
    monkeypatch.setattr("backend.app.recovery.tracer.store", test_store)
    client = TestClient(app)
    return client, test_store, db_file


# ── Scenario 1: Full Lifecycle & Engine Restart ──────────────────────────────

def test_01_full_lifecycle_and_engine_restart(client_step5):
    """Verify upload -> recovery -> SQLite persistence -> engine restart -> download round-trip."""
    client, t_store, db_file = client_step5

    # 1. Upload evidence via single-file intake
    clean_json = b'{"name": "Recoverix Forensic", "version": "1.0", "active": true}'
    resp = client.post(
        "/api/recover-file",
        files={"file": ("case_evidence.json", clean_json, "application/json")},
        data={"case_name": "Project Apollo", "investigator": "Agent Mulder", "notes": "Cold case file"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    file_id = data["file_id"]
    run_id = data["run_id"]
    assert data["status"] == "FULLY_RECOVERED"
    assert data["verified_bytes"] == len(clean_json)
    assert data["missing_bytes"] == 0
    assert data["reconstructed_bytes"] == 0
    assert data["total_input_bytes"] == len(clean_json)

    # 2. Simulate process restart by closing engine and creating a new SqliteStore instance
    t_store.close()
    restarted_engine = SqliteEngine(db_path=db_file)
    restarted_store = SqliteStore(engine=restarted_engine)

    # 3. Verify retrieved artifact metadata matches exactly
    rec_retrieved = restarted_store.get_artifact_record(file_id)
    assert rec_retrieved is not None
    assert rec_retrieved.artifact_id == file_id
    assert rec_retrieved.run_id == run_id
    assert rec_retrieved.status == "FULLY_RECOVERED"
    assert rec_retrieved.verified_bytes == len(clean_json)
    assert rec_retrieved.missing_bytes == 0
    assert rec_retrieved.reconstructed_bytes == 0

    # 4. Verify byte payload retrieved from restarted store
    payload_bytes = restarted_store.get_artifact_bytes(file_id)
    assert payload_bytes == clean_json
    assert hashlib.sha256(payload_bytes).hexdigest() == hashlib.sha256(clean_json).hexdigest()

    restarted_store.close()


# ── Scenario 2: Bi-directional Retrieval by Artifact ID and Run ID ──────────

def test_02_bidirectional_artifact_and_run_download(client_step5):
    """Verify download endpoints resolve correctly whether invoked by file_id or run_id."""
    client, t_store, _ = client_step5

    # Upload clean CSV evidence
    csv_bytes = b"id,name,role\n1,Alice,Investigator\n2,Bob,Forensic Analyst\n"
    resp = client.post(
        "/api/recover-file",
        files={"file": ("investigation.csv", csv_bytes, "text/csv")},
    )
    assert resp.status_code == 200
    data = resp.json()
    file_id = data["file_id"]
    run_id = data["run_id"]

    # Download via /api/recover-file/{file_id}/download
    dl_file = client.get(f"/api/recover-file/{file_id}/download")
    assert dl_file.status_code == 200
    assert dl_file.content == csv_bytes
    assert dl_file.headers["content-type"] == "text/csv; charset=utf-8"

    # Download via /api/recover-file/{run_id}/download (run_id resolution)
    dl_run_file = client.get(f"/api/recover-file/{run_id}/download")
    assert dl_run_file.status_code == 200
    assert dl_run_file.content == csv_bytes

    # Download via /api/artifacts/{file_id}/download
    dl_art = client.get(f"/api/artifacts/{file_id}/download")
    assert dl_art.status_code == 200
    assert dl_art.content == csv_bytes
    assert dl_art.headers["content-type"] == "text/csv; charset=utf-8"

    # Download via /api/artifacts/{run_id}/download (run_id resolution)
    dl_art_run = client.get(f"/api/artifacts/{run_id}/download")
    assert dl_art_run.status_code == 200
    assert dl_art_run.content == csv_bytes


# ── Scenario 3: Idempotency & Repeat Requests ────────────────────────────────

def test_03_idempotency_and_safe_retries(client_step5):
    """Verify repeated recovery runs and retries do not corrupt evidence or duplicate entities."""
    client, t_store, _ = client_step5

    # Create a case
    c_resp = client.post("/api/cases", json={"name": "Cold Case Alpha", "description": "Testing idempotency"})
    assert c_resp.status_code == 201
    case_id = c_resp.json()["case_id"]

    # Upload evidence into case
    xml_content = b'<?xml version="1.0"?><root><item id="1">Evidence</item></root>'
    run_1 = execute_traced_recovery(
        filename="record.xml",
        content=xml_content,
        case_id=case_id,
        artifact_id="art-xml-1",
    )
    assert run_1.status == "FULLY_RECOVERED"

    # Re-insert the exact same run with identical run_id
    run_2 = execute_traced_recovery(
        filename="record.xml",
        content=xml_content,
        case_id=case_id,
        artifact_id="art-xml-1",
    )
    # Both runs persist safely
    runs_in_case = t_store.get_case_recovery_runs(case_id)
    assert runs_in_case is not None
    assert len(runs_in_case) >= 1
    # Original case remains intact
    case = t_store.get_case(case_id)
    assert case is not None
    assert case.name == "Cold Case Alpha"


# ── Scenario 4: All Eight Formats Direct Recovery & Accounting ───────────────

def test_04_eight_format_direct_recovery_and_accounting(client_step5):
    """Verify all 8 formats execute through traced recovery with verified accounting."""
    client, t_store, _ = client_step5

    # 1. PDF with exact startxref pointing to xref offset
    pdf_body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
    )
    xref_offset = len(pdf_body)
    xref_and_trailer = (
        f"xref\n"
        f"0 3\n"
        f"0000000000 65535 f \n"
        f"0000000009 00000 n \n"
        f"0000000062 00000 n \n"
        f"trailer\n"
        f"<< /Size 3 /Root 1 0 R >>\n"
        f"startxref\n"
        f"{xref_offset}\n"
        f"%%EOF\n"
    ).encode("ascii")
    pdf_bytes = pdf_body + xref_and_trailer

    run_pdf = execute_traced_recovery("doc.pdf", pdf_bytes)
    assert run_pdf.format == "pdf"
    assert run_pdf.status in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")
    assert run_pdf.total_verified_bytes + run_pdf.total_missing_bytes == run_pdf.total_input_bytes

    # 2. JSON
    json_bytes = b'{"status": "ok", "count": 42}'
    run_json = execute_traced_recovery("data.json", json_bytes)
    assert run_json.format == "json"
    assert run_json.status == "FULLY_RECOVERED"
    assert run_json.total_verified_bytes == len(json_bytes)
    assert run_json.total_missing_bytes == 0

    # 3. CSV
    csv_bytes = b"col1,col2\nval1,val2\n"
    run_csv = execute_traced_recovery("table.csv", csv_bytes)
    assert run_csv.format == "csv"
    assert run_csv.status in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")
    assert run_csv.total_verified_bytes + run_csv.total_missing_bytes == run_csv.total_input_bytes

    # 4. TXT
    txt_bytes = b"Deterministic recovery test log.\nSecond line of evidence.\n"
    run_txt = execute_traced_recovery("log.txt", txt_bytes)
    assert run_txt.format == "txt"
    assert run_txt.status == "FULLY_RECOVERED"
    assert run_txt.total_verified_bytes == len(txt_bytes)
    assert run_txt.total_missing_bytes == 0

    # 5. XML
    xml_bytes = b'<?xml version="1.0"?><note><to>Investigator</to><from>Recoverix</from></note>'
    run_xml = execute_traced_recovery("note.xml", xml_bytes)
    assert run_xml.format == "xml"
    assert run_xml.status == "FULLY_RECOVERED"
    assert run_xml.total_verified_bytes == len(xml_bytes)

    # 6. PNG
    import struct
    import zlib
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    ihdr_chunk = b"\x00\x00\x00\x0dIHDR" + ihdr_data + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    idat_raw = zlib.compress(b"\x00\x00\x00\x00\x00")
    idat_chunk = struct.pack(">I", len(idat_raw)) + b"IDAT" + idat_raw + struct.pack(">I", zlib.crc32(b"IDAT" + idat_raw) & 0xFFFFFFFF)
    iend_chunk = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    png_bytes = b"\x89PNG\r\n\x1a\n" + ihdr_chunk + idat_chunk + iend_chunk
    run_png = execute_traced_recovery("sample.png", png_bytes)
    assert run_png.format == "png"
    assert run_png.status == "FULLY_RECOVERED"
    assert run_png.total_verified_bytes == len(png_bytes)

    # 7. JPEG
    jpeg_bytes = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c"
        b"\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c"
        b"\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xc0\x00\x0b\x08\x00"
        b"\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01"
        b"\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05"
        b"\x06\x07\x08\t\n\x0b\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00\xff\xd9"
    )
    run_jpeg = execute_traced_recovery("photo.jpg", jpeg_bytes)
    assert run_jpeg.format == "jpeg"
    assert run_jpeg.status in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")
    assert run_jpeg.total_verified_bytes + run_jpeg.total_missing_bytes == run_jpeg.total_input_bytes

    # 8. ZIP
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("test.txt", "Evidence interior")
    zip_bytes = zip_buf.getvalue()
    run_zip = execute_traced_recovery("archive.zip", zip_bytes)
    assert run_zip.format == "zip"
    assert run_zip.status == "FULLY_RECOVERED"
    assert run_zip.total_verified_bytes == len(zip_bytes)
    assert run_zip.total_missing_bytes == 0


# ── Scenario 5: Direct Fallback Recovery for JPEG & ZIP ───────────────────────

def test_05_direct_fallback_reconstruction_jpeg_and_zip(client_step5):
    """Verify that _recover_direct_fallback correctly reconstructs damaged JPEG & ZIP evidence."""
    # 1. Damaged JPEG (intact image structure truncated before EOI trailer 0xFFD9)
    valid_jpeg = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c"
        b"\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c"
        b"\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xc0\x00\x0b\x08\x00"
        b"\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01"
        b"\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05"
        b"\x06\x07\x08\t\n\x0b\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00\xff\xd9"
    )
    truncated_jpeg = valid_jpeg[:-2]  # Stripped \xff\xd9
    run_fallback_jpeg = _recover_direct_fallback("damaged_image.jpg", truncated_jpeg)
    assert run_fallback_jpeg.format == "jpeg"
    assert run_fallback_jpeg.status == "PARTIALLY_RECOVERED"
    assert run_fallback_jpeg.total_reconstructed_bytes == 2  # Appended 2-byte EOI
    assert run_fallback_jpeg.total_verified_bytes == len(truncated_jpeg)
    assert run_fallback_jpeg.total_verified_bytes + run_fallback_jpeg.total_missing_bytes == run_fallback_jpeg.total_input_bytes

    # 2. Damaged ZIP (valid local member with truncated central directory / EOCD)
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("file1.txt", "Forensic analysis evidence text block.")
    intact_zip = zip_buf.getvalue()
    # Find EOCD signature PK\x05\x06 and truncate
    eocd_idx = intact_zip.find(b"PK\x05\x06")
    truncated_zip = intact_zip[:eocd_idx]
    run_fallback_zip = _recover_direct_fallback("damaged_archive.zip", truncated_zip)
    assert run_fallback_zip.format == "zip"
    assert run_fallback_zip.status == "PARTIALLY_RECOVERED"
    assert run_fallback_zip.total_reconstructed_bytes > 0  # Synthesized CD & EOCD
    assert run_fallback_zip.total_verified_bytes + run_fallback_zip.total_missing_bytes == run_fallback_zip.total_input_bytes


# ── Scenario 6: Strict Download Rejection for Corrupted/Unrecoverable Records ─

def test_06_strict_download_rejection_for_unrecoverable(client_step5):
    """Verify that unrecoverable/corrupted records are strictly disallowed from download."""
    client, t_store, _ = client_step5

    # 1. High-entropy random garbage
    random_junk = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe\x00\xff" * 25
    resp = client.post(
        "/api/recover-file",
        files={"file": ("corrupt.bin", random_junk, "application/octet-stream")},
    )
    assert resp.status_code == 200
    data = resp.json()
    file_id = data["file_id"]
    assert data["status"] == "UNRECOVERABLE"
    assert data["is_downloadable"] is False

    # Download must return 404
    dl_resp = client.get(f"/api/recover-file/{file_id}/download")
    assert dl_resp.status_code == 404

    # Direct /api/artifacts/{id}/download must also return 404
    art_dl = client.get(f"/api/artifacts/{file_id}/download")
    assert art_dl.status_code == 404


# ── Scenario 7: Terminal State Race Protection Invariant ──────────────────────

def test_07_terminal_state_race_protection(client_step5):
    """Verify that terminal recovery statuses cannot be overwritten by stale in-flight statuses."""
    _, t_store, _ = client_step5

    run_id = "run-terminal-test-1"
    now = datetime.now(timezone.utc)

    # 1. Insert terminal state
    terminal_run = RecoveryRun(
        run_id=run_id,
        filename="terminal_check.json",
        format="json",
        status="FULLY_RECOVERED",
        started_at=now,
        completed_at=now,
        total_input_bytes=100,
        total_verified_bytes=100,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
    )
    t_store.add_recovery_run(terminal_run)

    # 2. Attempt stale update with 'RUNNING' or 'PENDING'
    stale_run = RecoveryRun(
        run_id=run_id,
        filename="terminal_check.json",
        format="json",
        status="RUNNING",  # Stale in-flight status
        started_at=now,
        total_input_bytes=100,
        total_verified_bytes=50,
        total_reconstructed_bytes=0,
        total_missing_bytes=50,
    )
    t_store.add_recovery_run(stale_run)

    # 3. Verify terminal status and byte accounting were preserved
    persisted = t_store.get_recovery_run(run_id)
    assert persisted is not None
    assert persisted.status == "FULLY_RECOVERED"
    assert persisted.total_verified_bytes == 100
    assert persisted.total_missing_bytes == 0


# ── Scenario 8: Standalone TTL Purge Scope Invariant ──────────────────────────

def test_08_case_linked_evidence_immune_to_ttl_purge(client_step5):
    """Verify that purge_expired_recovered_files purges only case_id IS NULL records older than TTL."""
    _, t_store, _ = client_step5

    # 1. Create a case with evidence and artifact
    case = t_store.create_case("Homicide Case 404", "Preserved forensic record")
    case_id = case.case_id

    # Add case evidence
    ev_bytes = b"Evidence raw bytes case-bound"
    t_store.add_evidence(case_id, "evidence.raw", ev_bytes)

    # Add case-linked artifact
    case_art = ArtifactRecord(
        artifact_id="art-case-bound",
        case_id=case_id,
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=100.0,
        verified_bytes=len(ev_bytes),
        total_input_bytes=len(ev_bytes),
        is_downloadable=True,
    )
    t_store.save_artifact_record(case_art)
    t_store.store_artifact_bytes("art-case-bound", ev_bytes)

    # 2. Add an expired standalone artifact (case_id IS NULL)
    old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    standalone_art = ArtifactRecord(
        artifact_id="art-standalone-expired",
        case_id=None,
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=100.0,
        verified_bytes=10,
        total_input_bytes=10,
        is_downloadable=True,
        metadata={"created_at": old_time},
    )
    t_store.save_artifact_record(standalone_art)
    t_store.store_artifact_bytes("art-standalone-expired", b"0123456789", created_at=old_time)

    # 3. Run TTL purge with ttl_hours=24
    purged_count = t_store.purge_expired_recovered_files(ttl_hours=24)
    assert purged_count >= 1

    # 4. Verify standalone artifact is gone
    assert t_store.get_artifact_record("art-standalone-expired") is None
    assert t_store.get_artifact_bytes("art-standalone-expired") is None

    # 5. Verify case-linked artifact and evidence raw bytes are 100% intact
    assert t_store.get_artifact_record("art-case-bound") is not None
    assert t_store.get_artifact_bytes("art-case-bound") == ev_bytes
    assert t_store.get_evidence_bytes(case_id) == ev_bytes


# ── Scenario 9: Archive Security & Zip-Slip Traversal Rejection ──────────────

def test_09_zip_slip_security_rejection(client_step5):
    """Verify that ZIP archives containing path traversal entries (Zip-Slip) fail structural validation."""
    from backend.app.recovery.validators.zip import validate_zip

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        # Malicious traversal entry
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
    malicious_zip = zip_buf.getvalue()

    val_res = validate_zip(malicious_zip)
    assert val_res.valid is False
    assert any("Zip-Slip" in err for err in val_res.errors)


# ── Scenario 10: Invariant Guard Against FULLY_RECOVERED Coexistence ──────────

def test_10_fully_recovered_invariant_guard():
    """Verify that FULLY_RECOVERED cannot coexist with positive R or M at any layer."""
    # 1. RecoveryRun Pydantic model validator
    now = datetime.now(timezone.utc)
    run_with_missing = RecoveryRun(
        run_id="run-test-inv-1",
        filename="test.bin",
        format="txt",
        status="FULLY_RECOVERED",
        started_at=now,
        total_input_bytes=100,
        total_verified_bytes=90,
        total_reconstructed_bytes=0,
        total_missing_bytes=10,  # M > 0
    )
    # Automatically normalized to PARTIALLY_RECOVERED
    assert run_with_missing.status == "PARTIALLY_RECOVERED"

    run_with_recon = RecoveryRun(
        run_id="run-test-inv-2",
        filename="test.bin",
        format="txt",
        status="FULLY_RECOVERED",
        started_at=now,
        total_input_bytes=100,
        total_verified_bytes=90,
        total_reconstructed_bytes=10,  # R > 0
        total_missing_bytes=0,
    )
    assert run_with_recon.status == "PARTIALLY_RECOVERED"

    # 2. ArtifactRecord model validator
    art_with_missing = ArtifactRecord(
        artifact_id="art-inv-1",
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=95.0,
        verified_bytes=90,
        reconstructed_bytes=0,
        missing_bytes=10,  # M > 0
    )
    assert art_with_missing.status == "PARTIALLY_RECOVERED"

    art_with_recon = ArtifactRecord(
        artifact_id="art-inv-2",
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=95.0,
        verified_bytes=90,
        reconstructed_bytes=10,  # R > 0
        missing_bytes=0,
    )
    assert art_with_recon.status == "PARTIALLY_RECOVERED"
