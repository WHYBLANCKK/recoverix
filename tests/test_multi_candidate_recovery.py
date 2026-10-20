"""
test_multi_candidate_recovery.py — Focused tests for multi-candidate canonical recovery.

Covers Scenarios A through L:
A. Single candidate through the new multi-candidate path produces exactly one RecoveryRun.
B. Multiple independent candidates produce multiple RecoveryRuns.
C. Candidate ordering is deterministic.
D. One candidate failing/unrecoverable does not prevent other candidates from being processed.
E. V/R/M are independent per candidate.
F. A fragmented candidate remains PARTIALLY_RECOVERED rather than being upgraded to FULLY_RECOVERED.
G. Reconstructed JSON preserves its reconstruction accounting.
H. Ambiguous bifragment candidates preserve ambiguity.
I. No ground-truth data is accessed.
J. Existing execute_traced_recovery() behavior remains unchanged.
K. Existing RecoveryRun invariants remain intact.
L. Running the same evidence twice produces equivalent candidate/run ordering and recovery semantics.
"""

from __future__ import annotations

import json
import pytest

from backend.app.recovery.scanner import Candidate
from backend.app.recovery.tracer import (
    execute_traced_recovery,
    execute_traced_recoveries,
    execute_traced_multi_recovery,
)
from backend.app.models.recovery_run import RecoveryRun
from backend.app.store import store


# ── Scenario A: Single Candidate ─────────────────────────────────────────────

def test_scenario_a_single_candidate():
    """A. Single candidate through the new multi-candidate path produces exactly one RecoveryRun."""
    json_bytes = b'{"case_id": "CAS-001", "active": true, "count": 42}'
    content = b"PADDING_START" + json_bytes + b"PADDING_END"
    offset = len(b"PADDING_START")
    end_offset = offset + len(json_bytes)

    cand = Candidate(
        candidate_id="cand-single",
        format="json",
        mime_type="application/json",
        category="structured",
        offset=offset,
        detected_header_length=1,
        estimated_end_offset=end_offset,
        detection_method="magic_bytes",
    )

    runs = execute_traced_recoveries("evidence.bin", content, candidates=[cand])
    assert len(runs) == 1
    run = runs[0]
    assert isinstance(run, RecoveryRun)
    assert run.candidate_id == "cand-single"
    assert run.format == "json"
    assert run.status == "FULLY_RECOVERED"
    assert run.total_verified_bytes == len(json_bytes)
    assert run.total_missing_bytes == 0
    assert run.total_reconstructed_bytes == 0


# ── Scenario B: Multiple Independent Candidates ──────────────────────────────

def test_scenario_b_multiple_independent_candidates():
    """B. Multiple independent candidates produce multiple independent RecoveryRuns."""
    doc1 = b'{"report_id": 101, "status": "verified"}'
    doc2 = b'{"report_id": 102, "status": "closed"}'
    content = doc1 + b"____SEPARATOR____" + doc2

    cand1 = Candidate(
        candidate_id="cand-001",
        format="json",
        mime_type="application/json",
        category="structured",
        offset=0,
        detected_header_length=1,
        estimated_end_offset=len(doc1),
        detection_method="magic_bytes",
    )
    offset2 = len(doc1) + len(b"____SEPARATOR____")
    cand2 = Candidate(
        candidate_id="cand-002",
        format="json",
        mime_type="application/json",
        category="structured",
        offset=offset2,
        detected_header_length=1,
        estimated_end_offset=offset2 + len(doc2),
        detection_method="magic_bytes",
    )

    runs = execute_traced_recoveries("case_dump.bin", content, candidates=[cand1, cand2])
    assert len(runs) == 2
    assert runs[0].candidate_id == "cand-001"
    assert runs[0].status == "FULLY_RECOVERED"
    assert runs[0].total_verified_bytes == len(doc1)

    assert runs[1].candidate_id == "cand-002"
    assert runs[1].status == "FULLY_RECOVERED"
    assert runs[1].total_verified_bytes == len(doc2)


# ── Scenario C: Deterministic Candidate Ordering ─────────────────────────────

def test_scenario_c_deterministic_candidate_ordering():
    """C. Candidate ordering is strictly deterministic based on (offset, header_length, candidate_id)."""
    p1 = b'{"pos": 1}'
    p2 = b'{"pos": 2}'
    p3 = b'{"pos": 3}'
    content = p1 + b"_" + p2 + b"_" + p3

    cand1 = Candidate("cand-first", "json", "application/json", "structured", 0, 1, len(p1), "magic")
    cand2 = Candidate("cand-second", "json", "application/json", "structured", len(p1) + 1, 1, len(p1) + 1 + len(p2), "magic")
    cand3 = Candidate("cand-third", "json", "application/json", "structured", len(p1) + 1 + len(p2) + 1, 1, len(content), "magic")

    # Pass in shuffled/reverse order: cand3, cand1, cand2
    runs = execute_traced_recoveries("ordered.bin", content, candidates=[cand3, cand1, cand2])
    assert len(runs) == 3
    assert runs[0].candidate_id == "cand-first"
    assert runs[1].candidate_id == "cand-second"
    assert runs[2].candidate_id == "cand-third"


# ── Scenario D: One Candidate Failing / Unrecoverable ────────────────────────

def test_scenario_d_candidate_failure_isolation():
    """D. One candidate failing/unrecoverable does not prevent other candidates from being processed."""
    valid_json = b'{"success": true, "code": 200}'
    corrupt_json = b'{"malformed_unclosed_string: 9999\xff\xfe'
    content = valid_json + b"===" + corrupt_json

    cand_valid = Candidate(
        candidate_id="cand-valid",
        format="json",
        mime_type="application/json",
        category="structured",
        offset=0,
        detected_header_length=1,
        estimated_end_offset=len(valid_json),
        detection_method="magic_bytes",
    )
    corrupt_offset = len(valid_json) + 3
    cand_corrupt = Candidate(
        candidate_id="cand-corrupt",
        format="json",
        mime_type="application/json",
        category="structured",
        offset=corrupt_offset,
        detected_header_length=1,
        estimated_end_offset=corrupt_offset + len(corrupt_json),
        detection_method="magic_bytes",
    )

    runs = execute_traced_recoveries("mixed.bin", content, candidates=[cand_valid, cand_corrupt])
    assert len(runs) == 2
    # Candidate 1: valid
    assert runs[0].candidate_id == "cand-valid"
    assert runs[0].status == "FULLY_RECOVERED"
    assert runs[0].validation["valid"] is True

    # Candidate 2: invalid/corrupt
    assert runs[1].candidate_id == "cand-corrupt"
    assert runs[1].status in ("UNRECOVERABLE", "CORRUPTED")
    assert runs[1].validation["valid"] is False


# ── Scenario E: Candidate Independence of V/R/M ──────────────────────────────

def test_scenario_e_v_r_m_independence():
    """E. V/R/M are independent per candidate; byte counts are strictly isolated and not summed."""
    doc_a = b'{"doc": "A", "val": 1}'
    doc_b = b'{"doc": "B", "val": 2, "extra": "extra_data_payload"}'
    content = doc_a + doc_b

    len_a = len(doc_a)
    len_b = len(doc_b)

    cand_a = Candidate(
        candidate_id="cand-A",
        format="json",
        mime_type="application/json",
        category="structured",
        offset=0,
        detected_header_length=1,
        estimated_end_offset=len_a,
        detection_method="magic_bytes",
    )
    cand_b = Candidate(
        candidate_id="cand-B",
        format="json",
        mime_type="application/json",
        category="structured",
        offset=len_a,
        detected_header_length=1,
        estimated_end_offset=len_a + len_b,
        detection_method="magic_bytes",
    )

    runs = execute_traced_recoveries("docs.bin", content, candidates=[cand_a, cand_b])
    assert len(runs) == 2

    # Run A byte accounting
    assert runs[0].total_input_bytes == len_a
    assert runs[0].total_verified_bytes == len_a
    assert runs[0].total_missing_bytes == 0
    assert runs[0].total_reconstructed_bytes == 0

    # Run B byte accounting
    assert runs[1].total_input_bytes == len_b
    assert runs[1].total_verified_bytes == len_b
    assert runs[1].total_missing_bytes == 0
    assert runs[1].total_reconstructed_bytes == 0

    # Neither run reflects the combined sum
    assert runs[0].total_verified_bytes != len_a + len_b
    assert runs[1].total_verified_bytes != len_a + len_b


# ── Scenario F: Fragmented Candidate Remains PARTIALLY_RECOVERED ────────────

def test_scenario_f_fragmented_candidate_remains_partially_recovered():
    """F. A fragmented candidate remains PARTIALLY_RECOVERED rather than being upgraded to FULLY_RECOVERED."""
    # Evidence with two CSV fragments separated by 50 null bytes
    frag1 = b"id,val\n1,10\n"
    gap = b"\x00" * 50
    frag2 = b"2,20\n3,30\n"
    content = frag1 + gap + frag2

    runs = execute_traced_recoveries("data.csv", content, detection_mode="known_file")
    assert len(runs) >= 1
    run = runs[0]
    assert run.status == "PARTIALLY_RECOVERED"
    assert run.status != "FULLY_RECOVERED"
    assert run.total_missing_bytes == 50
    assert run.total_verified_bytes == len(frag1) + len(frag2)
    assert run.total_verified_bytes + run.total_reconstructed_bytes + run.total_missing_bytes == len(content)


# ── Scenario G: Reconstructed JSON Preserves Reconstruction Accounting ───────

def test_scenario_g_reconstructed_json_accounting():
    """G. Reconstructed JSON preserves its reconstruction accounting (R > 0, PARTIALLY_RECOVERED)."""
    # Truncated JSON closable by structural reconstructor
    closable_json = b'{"status": "ok", "items": [1, 2, 3'
    runs = execute_traced_recoveries("config.json", closable_json, detection_mode="known_file")
    assert len(runs) == 1
    run = runs[0]

    assert run.format == "json"
    assert run.status == "PARTIALLY_RECOVERED"
    assert run.status != "FULLY_RECOVERED"
    assert run.total_reconstructed_bytes > 0
    assert run.provenance is not None
    assert run.provenance["reconstruction_method"] == "JSON_STRUCTURAL_CLOSURE"
    assert run.total_verified_bytes + run.total_missing_bytes == run.total_input_bytes
    assert run.total_verified_bytes + run.total_reconstructed_bytes == len(bytes.fromhex(run.output["recovered_bytes"]))


# ── Scenario H: Ambiguous Bifragment Preserves Ambiguity ─────────────────────

def test_scenario_h_ambiguous_bifragment_preserves_ambiguity():
    """H. Ambiguous bifragment candidates preserve ambiguity without arbitrary picking."""
    frag_a = b"First line of log\nSecond line of log\n"
    gap = b"\x00" * 30
    frag_b = b"Third line of log\nFourth line of log\n"
    content = frag_a + gap + frag_b

    runs = execute_traced_recoveries("server.txt", content, detection_mode="known_file")
    assert len(runs) >= 1
    run = runs[0]
    assert run.status == "PARTIALLY_RECOVERED"
    assert run.total_missing_bytes == len(gap)
    if run.reconstruction_steps:
        step = run.reconstruction_steps[0]
        assert step.validated_gap_size is None or step.gap_size == len(gap)


# ── Scenario I: No Ground Truth Data Accessed ────────────────────────────────

def test_scenario_i_no_ground_truth_accessed():
    """I. Production recovery operates strictly on input evidence bytes without ground truth access."""
    content = b'{"system": "recoverix", "standalone": true}'
    # Function accepts only operational parameters, no ground truth payload or metadata
    runs = execute_traced_recoveries(
        filename="unbiased.json",
        content=content,
        case_id="CAS-NO-TRUTH",
        detection_mode="known_file",
    )
    assert len(runs) == 1
    assert runs[0].status == "FULLY_RECOVERED"
    # Provenance contains only operational evidence metadata
    assert "ground_truth" not in runs[0].provenance


# ── Scenario J: Existing execute_traced_recovery Unchanged ───────────────────

def test_scenario_j_existing_execute_traced_recovery_unchanged():
    """J. Existing execute_traced_recovery() behavior remains unchanged, including artifact_id propagation."""
    content = b'{"api_version": "v1", "service": "recoverix"}'
    run = execute_traced_recovery(
        filename="service.json",
        content=content,
        case_id="CAS-999",
        artifact_id="art-explicit-id",
        detection_mode="known_file",
    )
    assert isinstance(run, RecoveryRun)
    assert store.get_recovery_run_by_artifact("art-explicit-id") is not None
    assert store.get_recovery_run_by_artifact("art-explicit-id").run_id == run.run_id
    assert run.status == "FULLY_RECOVERED"
    assert run.total_verified_bytes == len(content)
    assert run.total_missing_bytes == 0


# ── Scenario K: Existing RecoveryRun Invariants Remain Intact ────────────────

def test_scenario_k_recovery_run_invariants_intact():
    """K. Existing RecoveryRun invariants remain intact across all returned runs."""
    doc1 = b'{"pos": 1}'
    doc2 = b'{"pos": 2}'
    content = doc1 + b"___" + doc2

    cand1 = Candidate("c1", "json", "application/json", "structured", 0, 1, len(doc1), "magic")
    cand2 = Candidate("c2", "json", "application/json", "structured", len(doc1) + 3, 1, len(content), "magic")

    runs = execute_traced_recoveries("invariants.bin", content, candidates=[cand1, cand2])
    assert len(runs) == 2

    for r in runs:
        # Invariant 1: total_input_bytes == V + R + M
        assert r.total_input_bytes == r.total_verified_bytes + r.total_reconstructed_bytes + r.total_missing_bytes
        # Invariant 2: monotonic event sequence numbers starting at 1
        for idx_e, event in enumerate(r.events):
            assert event.sequence == idx_e + 1
            assert event.run_id == r.run_id
        # Invariant 3: completed_at >= started_at
        assert r.completed_at is not None
        assert r.completed_at >= r.started_at


# ── Scenario L: Idempotent Reproducibility ───────────────────────────────────

def test_scenario_l_idempotent_reproducibility():
    """L. Running the same evidence twice produces equivalent candidate/run ordering and recovery semantics."""
    payload = b'{"key": "test_idempotency", "count": 100}'
    cand = Candidate("cand-idemp", "json", "application/json", "structured", 0, 1, len(payload), "magic")

    runs_1 = execute_traced_recoveries("idemp.json", payload, candidates=[cand])
    runs_2 = execute_traced_recoveries("idemp.json", payload, candidates=[cand])

    assert len(runs_1) == len(runs_2) == 1
    assert runs_1[0].status == runs_2[0].status
    assert runs_1[0].total_verified_bytes == runs_2[0].total_verified_bytes
    assert runs_1[0].total_reconstructed_bytes == runs_2[0].total_reconstructed_bytes
    assert runs_1[0].total_missing_bytes == runs_2[0].total_missing_bytes
    assert runs_1[0].format == runs_2[0].format

# ── Scenario M: Primary Selection Regression (Ranking vs. Offset Order) ──────

def test_scenario_m_primary_selection_prefers_ranked_candidate_over_offset_order():
    """M. Legacy execute_traced_recovery() preserves _rank_candidate() selection.
    
    Candidate at offset 0 is weak (format mismatch, low score).
    Candidate at offset 100 matches filename extension with magic_bytes and known end.
    execute_traced_recoveries() returns BOTH in offset order [cand_weak, cand_strong].
    execute_traced_recovery() returns cand_strong (matching legacy ranking).
    """
    weak_payload = b"weak plain text content at start"
    pdf_payload = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF"
    content = weak_payload + (b"\x00" * 50) + pdf_payload
    pdf_offset = len(weak_payload) + 50

    cand_weak = Candidate(
        candidate_id="cand-weak-offset0",
        format="txt",
        mime_type="text/plain",
        category="text",
        offset=0,
        detected_header_length=0,
        estimated_end_offset=len(weak_payload),
        detection_method="raw",
    )
    cand_strong = Candidate(
        candidate_id="cand-strong-pdf",
        format="pdf",
        mime_type="application/pdf",
        category="document",
        offset=pdf_offset,
        detected_header_length=8,
        estimated_end_offset=pdf_offset + len(pdf_payload),
        detection_method="magic_bytes",
    )

    # Multi-candidate API: returns both in spatial offset order
    multi_runs = execute_traced_recoveries(
        "report.pdf", content, candidates=[cand_strong, cand_weak]
    )
    assert len(multi_runs) == 2
    assert multi_runs[0].candidate_id == "cand-weak-offset0"
    assert multi_runs[1].candidate_id == "cand-strong-pdf"

    # Legacy single-run API: selects the top-ranked candidate (report.pdf -> PDF candidate)
    single_run = execute_traced_recovery(
        "report.pdf", content, candidates=[cand_strong, cand_weak]
    )
    assert single_run.candidate_id == "cand-strong-pdf"
    assert single_run.format == "pdf"


# ── Scenario N: Candidate ID and Ordering Determinism ────────────────────────

def test_scenario_n_candidate_id_and_ordering_determinism():
    """N. Candidate IDs are deterministic from detection; fallback candidate_id is None."""
    # Fallback run (0 candidates detected)
    fallback_run = execute_traced_recovery("empty.dat", b"\x00" * 100)
    assert fallback_run.candidate_id is None

    # Deterministic candidate IDs from scan_evidence across repeated runs
    pdf_evidence = b"%PDF-1.4\n1 0 obj\nendobj\ntrailer<<>>\n%%EOF"
    runs_1 = execute_traced_recoveries("doc.pdf", pdf_evidence)
    runs_2 = execute_traced_recoveries("doc.pdf", pdf_evidence)

    assert len(runs_1) == len(runs_2)
    for r1, r2 in zip(runs_1, runs_2):
        assert r1.candidate_id == r2.candidate_id
        assert r1.format == r2.format
        assert r1.status == r2.status
        assert r1.total_verified_bytes == r2.total_verified_bytes


# ── Scenario O: Milestone 1 Seed-42 Physical Gap Regression ──────────────────

def test_scenario_o_milestone1_seed42_physical_gap_regression():
    """O. Milestone 1 deterministic seed=42 physical-gap accounting is preserved.
    
    Verifies that sparse/disk evidence containing the deterministic physical gap
    (missing null region) is correctly reported as PARTIALLY_RECOVERED with honest
    missing-byte accounting on both TXT and CSV fixtures.
    """
    from backend.app.generator import generate_fragment_case, STANDARD_FIXTURES, EvidenceDisk

    # 1. TXT fixture
    orig_name_txt, orig_bytes_txt = STANDARD_FIXTURES["txt"]
    fc_txt = generate_fragment_case(orig_bytes_txt, fmt="txt", seed=42, scenario="fragmented")
    m_txt = fc_txt.to_manifest()
    disk_txt = EvidenceDisk(len(orig_bytes_txt), fill=0x00)
    for frag in m_txt["fragments"]:
        disk_txt.write(frag["offset"], orig_bytes_txt[frag["offset"]:frag["end_offset"]])
    
    run_txt = execute_traced_recovery("server.txt", disk_txt.data, detection_mode="known_file")
    assert run_txt.status == "PARTIALLY_RECOVERED"
    assert run_txt.total_verified_bytes == 83
    assert run_txt.total_reconstructed_bytes == 0
    assert run_txt.total_missing_bytes == 209
    assert run_txt.total_input_bytes == 292
    assert len(run_txt.damage_regions) == 1
    assert run_txt.damage_regions[0].type == "MISSING"
    assert run_txt.damage_regions[0].length == 209

    # 2. CSV fixture
    orig_name_csv, orig_bytes_csv = STANDARD_FIXTURES["csv"]
    fc_csv = generate_fragment_case(orig_bytes_csv, fmt="csv", seed=42, scenario="fragmented")
    m_csv = fc_csv.to_manifest()
    disk_csv = EvidenceDisk(len(orig_bytes_csv), fill=0x00)
    for frag in m_csv["fragments"]:
        disk_csv.write(frag["offset"], orig_bytes_csv[frag["offset"]:frag["end_offset"]])
    
    run_csv = execute_traced_recovery("data.csv", disk_csv.data, detection_mode="known_file")
    assert run_csv.status == "PARTIALLY_RECOVERED"
    assert run_csv.total_verified_bytes == 289
    assert run_csv.total_reconstructed_bytes == 0
    assert run_csv.total_missing_bytes == 57
    assert run_csv.total_input_bytes == 346
    assert len(run_csv.damage_regions) == 1
    assert run_csv.damage_regions[0].type == "MISSING"
    assert run_csv.damage_regions[0].length == 57

