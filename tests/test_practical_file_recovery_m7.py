"""
test_practical_file_recovery_m7.py — Milestone 7: Practical File Recovery & Usability Tests.

Validates:
1. End-to-end recovery of damaged-xref PDF files across contiguous, standalone, and fallback paths.
2. Direct format routing through reconstruct_artifact("pdf", ...).
3. End-to-end API single-file upload (/api/recover-file) and download (/api/recover-file/{id}/download).
4. End-to-end Case evidence upload (/api/cases/{id}/evidence) and analysis (/api/cases/{id}/analyze).
5. Accurate accounting invariants (V + M = input, V + R = output) and zero byte hallucination.
6. Fix for contiguous candidate reconstruction step iteration (preventing NameError on idx_m).
7. Conservative rejection when essential structural anchors (/Root, Catalog) are missing.
"""

from __future__ import annotations

import io
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.store import store
from backend.app.models.reconstruction import ReconstructionResult
from backend.app.recovery.tracer import (
    execute_traced_recovery,
    execute_traced_recoveries,
    _recover_contiguous_candidate,
    _recover_direct_fallback,
)
from backend.app.recovery.reconstruction import reconstruct_artifact
from backend.app.recovery.scanner import Candidate
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)
from backend.app.recovery.validators.pdf import validate_pdf
from tests.test_pdf_recovery import build_minimal_pdf


@pytest.fixture(autouse=True)
def clean_store():
    store.clear()
    yield
    store.clear()


client = TestClient(app)


def test_contiguous_pdf_with_damaged_xref_reconstruction():
    """Contiguous PDF with valid EOF but damaged xref must be reconstructed, not marked UNRECOVERABLE."""
    pdf_bytes = build_minimal_pdf()
    # Replace 'xref' with garbage while leaving %%EOF intact (so scanner treats candidate as bounded)
    corrupted_pdf = pdf_bytes.replace(b"xref", b"xxxx")

    run = execute_traced_recovery("damaged_doc.pdf", corrupted_pdf)

    assert run.status == "PARTIALLY_RECOVERED"
    assert run.format == "pdf"
    assert run.total_verified_bytes > 0
    assert run.total_reconstructed_bytes > 0
    assert any(s.method == "XREF_RECONSTRUCTION" for s in run.reconstruction_steps)

    recovered_hex = run.output.get("recovered_bytes", "")
    assert recovered_hex
    recovered_bytes = bytes.fromhex(recovered_hex)

    # Reconstructed file must be structurally valid PDF
    val = validate_pdf(recovered_bytes)
    assert val.valid is True
    assert recovered_bytes.startswith(b"%PDF-")
    assert recovered_bytes.endswith(b"%%EOF\n")

    # Conservation: verified bytes cannot exceed input
    assert run.total_verified_bytes <= len(corrupted_pdf)
    assert run.total_verified_bytes + run.total_missing_bytes == len(corrupted_pdf)
    assert run.total_verified_bytes + run.total_reconstructed_bytes == len(recovered_bytes)


def test_reconstruct_artifact_handles_pdf_format():
    """reconstruct_artifact('pdf', data) must execute deterministic xref reconstruction."""
    pdf_bytes = build_minimal_pdf()
    corrupted_pdf = pdf_bytes.replace(b"xref", b"xxxx")

    result = reconstruct_artifact("pdf", corrupted_pdf)

    assert isinstance(result, ReconstructionResult)
    assert result.format == "pdf"
    assert result.success is True
    assert result.status == "PARTIALLY_RECOVERED"
    assert result.verified_bytes > 0
    assert result.reconstructed_bytes > 0
    assert "XREF_RECONSTRUCTION" in result.reconstruction_methods
    assert result.validation_result is not None
    assert result.validation_result.valid is True


def test_reconstruct_artifact_rejects_unrecoverable_pdf():
    """reconstruct_artifact('pdf', data) fails conservatively when no catalog/objects exist."""
    garbage = b"%PDF-1.4\n1 0 obj\n<< /NotACatalog 1 >>\nendobj\n"

    result = reconstruct_artifact("pdf", garbage)

    assert isinstance(result, ReconstructionResult)
    assert result.format == "pdf"
    assert result.success is False
    assert result.status == "UNRECOVERABLE"
    assert result.verified_bytes == 0
    assert result.reconstructed_bytes == 0
    assert result.missing_bytes == len(garbage)
    assert result.recovered_bytes == b""


def test_direct_fallback_pdf_reconstruction():
    """_recover_direct_fallback must reconstruct PDF when candidate scanning is bypassed."""
    pdf_bytes = build_minimal_pdf()
    corrupted_pdf = pdf_bytes.replace(b"xref", b"xxxx")

    run = _recover_direct_fallback("raw_report.pdf", corrupted_pdf)

    assert run.status == "PARTIALLY_RECOVERED"
    assert run.format == "pdf"
    assert run.total_verified_bytes > 0
    assert run.total_reconstructed_bytes > 0
    assert any(s.method == "XREF_RECONSTRUCTION" for s in run.reconstruction_steps)

    recovered_hex = run.output.get("recovered_bytes", "")
    assert recovered_hex
    val = validate_pdf(bytes.fromhex(recovered_hex))
    assert val.valid is True


def test_single_file_api_upload_and_download_damaged_pdf():
    """POST /api/recover-file with damaged PDF produces downloadable valid reconstructed file."""
    pdf_bytes = build_minimal_pdf()
    corrupted_pdf = pdf_bytes.replace(b"xref", b"xxxx")

    upload_resp = client.post(
        "/api/recover-file",
        files={"file": ("damaged_quarterly.pdf", corrupted_pdf, "application/pdf")},
    )

    assert upload_resp.status_code == 200
    data = upload_resp.json()

    assert data["format"] == "pdf"
    assert data["status"] == "PARTIALLY_RECOVERED"
    assert data["is_downloadable"] is True
    assert data["verified_bytes"] > 0
    assert data["reconstructed_bytes"] > 0
    assert data["download_url"].startswith("/api/recover-file/")

    # Download recovered file
    dl_resp = client.get(data["download_url"])
    assert dl_resp.status_code == 200
    assert dl_resp.content.startswith(b"%PDF-")
    assert dl_resp.content.endswith(b"%%EOF\n")

    # Downloaded file is independently validated
    val = validate_pdf(dl_resp.content)
    assert val.valid is True


def test_case_evidence_upload_and_analysis_damaged_pdf():
    """Full workflow: create case -> upload evidence -> analyze -> retrieve artifact download."""
    # 1. Create case
    case_resp = client.post("/api/cases", json={"name": "Forensic Investigation 2026"})
    assert case_resp.status_code == 201
    case_id = case_resp.json()["case_id"]

    # 2. Upload damaged PDF evidence
    pdf_bytes = build_minimal_pdf()
    corrupted_pdf = pdf_bytes.replace(b"xref", b"xxxx")
    ev_resp = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("seized_drive_evidence.pdf", corrupted_pdf, "application/pdf")},
    )
    assert ev_resp.status_code == 200

    # 3. Analyze case
    an_resp = client.post(f"/api/cases/{case_id}/analyze")
    assert an_resp.status_code == 200
    an_data = an_resp.json()
    assert an_data["artifact_count"] >= 1
    art = an_data["artifacts"][0]
    assert art["format"] == "pdf"
    assert art["status"] == "PARTIALLY_RECOVERED"
    assert art["size_bytes"] > 0

    # 4. Download artifact payload
    art_dl = client.get(f"/api/artifacts/{art['artifact_id']}/download")
    assert art_dl.status_code == 200
    assert art_dl.content.startswith(b"%PDF-")
    val = validate_pdf(art_dl.content)
    assert val.valid is True


def test_contiguous_reconstruction_step_loop_no_name_error():
    """Contiguous candidates with partial reconstruction must not trigger NameError on idx_m."""
    raw_json = b'{"items": [1, 2, 3'
    payload = SYNTHETIC_START_MARKER + raw_json + SYNTHETIC_END_MARKER
    cand = Candidate(
        candidate_id="cand-contig-step-test",
        format="json",
        mime_type="application/json",
        category="structured",
        offset=0,
        detected_header_length=len(SYNTHETIC_START_MARKER),
        estimated_end_offset=len(payload),
        detection_method="synthetic_boundary",
    )

    run = _recover_contiguous_candidate("test.json", payload, cand)

    assert run.status == "PARTIALLY_RECOVERED"
    assert len(run.reconstruction_steps) >= 1
    assert run.reconstruction_steps[0].method == "JSON_STRUCTURAL_CLOSURE"
    assert run.reconstruction_steps[0].result == "SUCCESS"
