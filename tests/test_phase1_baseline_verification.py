"""
tests/test_phase1_baseline_verification.py — Comprehensive baseline verification for Phase 1.

Verifies existing reconstruction, validation, status classification, and byte-accounting
semantics for the 4 baseline formats: PDF, JSON, CSV, and TXT across:
  - Intact inputs
  - Representative corruption
  - Truncation
  - Unsupported/random binary noise
  - Safe failure
  - Forensic byte accounting invariants
  - Documented JSON UNACCOUNTED_GAP behavior
"""

import pytest
from backend.app.recovery.reconstruction import reconstruct_artifact
from backend.app.recovery.validators.pdf import validate_pdf
from backend.app.recovery.validators.json import validate_json
from backend.app.recovery.validators.csv import validate_csv
from backend.app.recovery.validators.text import validate_txt


# ── TXT Baseline ─────────────────────────────────────────────────────────────

def test_txt_intact():
    payload = b"Recoverix digital evidence test.\nLine 2 with UTF-8 characters: \xc3\xa9\xc3\xa8\xc3\xa0\n"
    res = reconstruct_artifact("txt", payload)
    assert res.status == "FULLY_RECOVERED"
    assert res.success is True
    assert res.recovered_bytes == payload
    assert res.verified_bytes == len(payload)
    assert res.reconstructed_bytes == 0
    assert res.missing_bytes == 0


def test_txt_truncated_utf8():
    # Euro sign \xe2\x82\xac truncated to 2 bytes
    payload = b"Account balance: 500 " + b"\xe2\x82"
    res = reconstruct_artifact("txt", payload)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.recovered_bytes == b"Account balance: 500 "
    assert res.verified_bytes == len(b"Account balance: 500 ")
    assert res.missing_bytes == 2
    assert res.verified_bytes + res.missing_bytes == len(payload)


def test_txt_embedded_null_corruption():
    payload = (
        b"First section with sufficient text content to verify density.\n"
        + (b"\x00" * 16)
        + b"Second section with sufficient text content to verify density.\n"
    )
    res = reconstruct_artifact("txt", payload)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert b"First section" in res.recovered_bytes
    assert b"Second section" in res.recovered_bytes
    assert b"\x00" not in res.recovered_bytes
    assert res.missing_bytes >= 16


def test_txt_unrecoverable_binary_noise():
    payload = bytes([i % 256 for i in range(256)])
    res = reconstruct_artifact("txt", payload)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0
    assert res.missing_bytes == len(payload)


# ── CSV Baseline ─────────────────────────────────────────────────────────────

def test_csv_intact():
    payload = b"id,name,department\n1,Alice,Security\n2,Bob,Forensics\n"
    res = reconstruct_artifact("csv", payload)
    assert res.status == "FULLY_RECOVERED"
    assert res.success is True
    assert res.verified_bytes == len(payload)
    assert res.missing_bytes == 0


def test_csv_truncated_trailing_row():
    payload = b"id,name,department\n1,Alice,Security\n2,Bob,Forensics\n3,Charlie"
    res = reconstruct_artifact("csv", payload)
    assert res.status in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")
    assert res.success is True
    val = validate_csv(res.recovered_bytes)
    assert val.valid is True


def test_csv_inconsistent_corrupted_row():
    # Row 2 only has 2 columns instead of 3
    payload = b"id,name,department\n1,Alice,Security\n2,Bob\n3,Charlie,Forensics\n"
    res = reconstruct_artifact("csv", payload)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.missing_bytes > 0
    val = validate_csv(res.recovered_bytes)
    assert val.valid is True


def test_csv_unrecoverable_garbage():
    payload = b"\x00\x01\x02\x03\x04\x05\x06\x07" * 20
    res = reconstruct_artifact("csv", payload)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


# ── JSON Baseline ────────────────────────────────────────────────────────────

def test_json_intact():
    payload = b'{"case_id": "IR-2026", "active": true, "items": [1, 2, 3]}'
    res = reconstruct_artifact("json", payload)
    assert res.status == "FULLY_RECOVERED"
    assert res.success is True
    assert res.verified_bytes == len(payload)
    assert res.reconstructed_bytes == 0
    assert res.missing_bytes == 0


def test_json_truncated_closable():
    payload = b'{"case_id": "IR-2026", "tags": ["malware", "network"'
    res = reconstruct_artifact("json", payload)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes == 2  # ]}
    assert res.recovered_bytes == b'{"case_id": "IR-2026", "tags": ["malware", "network"]}'
    assert res.verified_bytes == len(payload)
    val = validate_json(res.recovered_bytes)
    assert val.valid is True


def test_json_documented_unaccounted_gap():
    """Documents the fundamental marker-free JSON limitation:
    When an array is truncated without ground truth, e.g. ["a", "b",
    the engine can deterministically close it with ']}', but cannot know
    that a third element was originally lost.
    """
    surviving = b'{"probe": "P-1", "readings": ["s_a", "s_b"'
    res = reconstruct_artifact("json", surviving)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.verified_bytes == len(surviving)
    assert res.reconstructed_bytes == 2  # ]}
    assert res.missing_bytes == 0  # Surviving evidence alone contains no dropped bytes


def test_json_corrupted_syntax_unrecoverable():
    payload = b'{"unclosed_key: 12345, "broken"}'
    res = reconstruct_artifact("json", payload)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0
    assert res.missing_bytes == len(payload)


# ── PDF Baseline ─────────────────────────────────────────────────────────────

SAMPLE_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
    b"xref\n0 4\n"
    b"0000000000 65535 f \n"
    b"0000000010 00000 n \n"
    b"0000000060 00000 n \n"
    b"0000000118 00000 n \n"
    b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n172\n%%EOF\n"
)


def test_pdf_intact():
    res = reconstruct_artifact("pdf", SAMPLE_PDF)
    assert res.status == "FULLY_RECOVERED"
    assert res.success is True
    assert res.verified_bytes == len(SAMPLE_PDF)
    assert res.reconstructed_bytes == 0
    assert res.missing_bytes == 0


def test_pdf_missing_xref_reconstruction():
    xref_idx = SAMPLE_PDF.find(b"xref")
    pdf_damaged = SAMPLE_PDF[:xref_idx]  # Cut off xref table and trailer
    res = reconstruct_artifact("pdf", pdf_damaged)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes > 0
    val = validate_pdf(res.recovered_bytes)
    assert val.valid is True
    assert b"%%EOF" in res.recovered_bytes


def test_pdf_corrupted_catalog_unrecoverable():
    pdf_corrupted = b"%PDF-1.4\n1 0 obj\n<< /Type /NotACatalog >>\nendobj\n"
    res = reconstruct_artifact("pdf", pdf_corrupted)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0
