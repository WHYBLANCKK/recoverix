"""tests/test_benchmark_milestone2_json.py — Milestone 2 Marker-Free JSON Benchmark Tests.

Validates:
1. Clean marker-free JSON end-to-end recovery.
2. Candidate detection without synthetic markers (syntax_boundary method).
3. Coordinate mapping from physical evidence placement to original coordinates.
4. Exact payload SHA-256 verification (mandatory for FULLY_RECOVERED).
5. Truncated closable JSON is never falsely declared FULLY_RECOVERED.
6. Structural validity is distinct from original byte identity.
7. Unaccounted gap detection when physical gap exists in ground truth.
8. Refusal to hallucinate incomplete tokens (drops tail, accounts as missing).
9. Ambiguous or corrupted noise does not produce false recovery (negative control).
10. Incorrect recovered bytes fail byte-level verification (FALSE_VERIFIED_BYTES).
11. Unmappable or ambiguous coordinates remain unknown (None).
12. Zero ground-truth leakage into the recovery pipeline.
13. End-to-end JSON benchmark runner execution and report emission.
14. Preservation of existing baseline scenarios (zero regression).
"""

from __future__ import annotations

import copy
import hashlib
import json
from unittest.mock import patch

import pytest

from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)
from benchmark.evaluator import evaluate_scenario
from benchmark.expectations import derive_expected_recovery
from benchmark.json_benchmark import (
    build_clean_json_scenario,
    build_truncated_closable_scenario,
    build_truncated_closable_pure_scenario,
    build_truncated_closable_content_loss_scenario,
    build_truncated_incomplete_scenario,
    build_unrecoverable_noise_scenario,
    build_json_with_binary_noise_scenario,
    build_two_independent_json_scenario,
    evaluate_json_scenario,
    run_json_benchmark,
)
from benchmark.models import (
    BenchmarkGroundTruthManifest,
    ObservedArtifactRecoveryResult,
    ObservedRecoverySegment,
    PhysicalArtifactRecord,
    PhysicalDamageInterval,
    PhysicalPlacement,
)
from benchmark.run_baseline import run_baseline_benchmark, run_pipeline_and_observe


# ── TEST 1: CLEAN MARKER-FREE JSON END-TO-END RECOVERY ──────────────────────

def test_01_clean_marker_free_json_end_to_end():
    """Verify clean marker-free JSON is recovered end-to-end with exact byte identity."""
    gt_manifest, evidence_bytes = build_clean_json_scenario(seed=42)

    # 1. Assert evidence is strictly marker-free
    assert SYNTHETIC_START_MARKER not in evidence_bytes
    assert SYNTHETIC_END_MARKER not in evidence_bytes

    # 2. Run recovery pipeline on evidence bytes only
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # 3. Assert candidate detection used syntax boundaries, not synthetic markers
    assert len(obs_manifest.candidates) == 1
    cand = obs_manifest.candidates[0]
    assert cand.format == "json"
    assert cand.offset == 512
    assert cand.estimated_end_offset == 512 + gt_manifest.artifacts[0].original_size_bytes

    # 4. Evaluate against ground truth
    report = evaluate_scenario(gt_manifest, obs_manifest)
    assert len(report.artifact_evaluations) == 1
    ae = report.artifact_evaluations[0]

    assert ae.expected_status == "FULLY_RECOVERED"
    assert ae.observed_status == "FULLY_RECOVERED"
    assert ae.status_match is True
    assert ae.false_fully_recovered is False
    assert ae.whole_payload_hash_match is True
    assert ae.v_volume_accuracy == 1.0
    assert ae.v_interval_iou == 1.0
    assert ae.v_byte_correctness == 1.0
    assert len(report.forensic_violations) == 0


# ── TEST 2: DETECTION WITHOUT SYNTHETIC MARKERS ────────────────────────────

def test_02_detection_method_is_syntax_boundary():
    """Assert candidate discovery uses syntax boundary detection and not synthetic markers."""
    gt_manifest, evidence_bytes = build_clean_json_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    from backend.app.recovery.scanner import scan_evidence
    raw_cands = scan_evidence(evidence_bytes)
    assert len(raw_cands) == 1
    assert raw_cands[0].detection_method == "syntax_boundary"
    assert raw_cands[0].detection_method != "synthetic_boundary"


# ── TEST 3: CORRECT ORIGINAL-SPACE COORDINATE MAPPING ───────────────────────

def test_03_original_coordinate_mapping():
    """Verify that evidence coordinates [512, 512+N) map to original coordinates [0, N)."""
    gt_manifest, evidence_bytes = build_clean_json_scenario(seed=42)
    art = gt_manifest.artifacts[0]
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    rec = obs_manifest.recoveries[0]
    from benchmark.evaluator import map_recovery_to_ground_truth
    mapped_rec = map_recovery_to_ground_truth(rec, art)

    assert len(mapped_rec.verified_segments) == 1
    seg = mapped_rec.verified_segments[0]
    assert seg.evidence_start == 512
    assert seg.evidence_end == 512 + art.original_size_bytes
    assert seg.original_start == 0
    assert seg.original_end == art.original_size_bytes
    assert seg.recovered_start == 0
    assert seg.recovered_end == art.original_size_bytes


# ── TEST 4: EXACT PAYLOAD HASH VERIFICATION ────────────────────────────────

def test_04_exact_payload_hash_verification():
    """Verify whole_payload_hash_match is True for exact payload and False if 1 byte differs."""
    gt_manifest, evidence_bytes = build_clean_json_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Clean run: match is True
    report = evaluate_scenario(gt_manifest, obs_manifest)
    assert report.artifact_evaluations[0].whole_payload_hash_match is True

    # Mutate 1 byte of recovered payload: match must become False
    mutated_obs = copy.deepcopy(obs_manifest)
    original_payload = bytearray(mutated_obs.recoveries[0].recovered_payload_bytes)
    original_payload[10] ^= 0x01
    mutated_obs.recoveries[0].recovered_payload_bytes = bytes(original_payload)

    report_mutated = evaluate_scenario(gt_manifest, mutated_obs)
    assert report_mutated.artifact_evaluations[0].whole_payload_hash_match is False


# ── TEST 5: TRUNCATED JSON NOT FALSELY DECLARED FULLY RECOVERED ─────────────

def test_05_truncated_closable_not_falsely_fully_recovered():
    """Assert truncated closable JSON is observed as PARTIALLY_RECOVERED, never FULLY_RECOVERED."""
    # Both pure structural closure and content-loss cases must be PARTIALLY_RECOVERED
    for builder in (build_truncated_closable_pure_scenario, build_truncated_closable_content_loss_scenario):
        gt_manifest, evidence_bytes = builder(seed=42)
        obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

        assert len(obs_manifest.recoveries) == 1
        rec = obs_manifest.recoveries[0]
        assert rec.observed_status == "PARTIALLY_RECOVERED"
        assert rec.observed_status != "FULLY_RECOVERED"
        assert rec.total_reconstructed_bytes > 0

        report = evaluate_scenario(gt_manifest, obs_manifest)
        ae = report.artifact_evaluations[0]
        assert ae.expected_status == "PARTIALLY_RECOVERED"
        assert ae.observed_status == "PARTIALLY_RECOVERED"
        assert ae.status_match is True
        assert ae.false_fully_recovered is False


# ── TEST 6: STRUCTURAL VALIDITY DISTINCT FROM ORIGINAL IDENTITY ────────────

def test_06_structural_validity_distinct_from_byte_identity():
    """Verify that structurally valid repaired JSON does NOT pass payload hash matching when content was lost."""
    import json
    gt_manifest, evidence_bytes = build_truncated_closable_content_loss_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    rec = obs_manifest.recoveries[0]
    # 1. Structural validity: parses as valid JSON
    parsed = json.loads(rec.recovered_payload_bytes)
    assert isinstance(parsed, dict)
    assert "readings" in parsed

    # 2. Byte identity: original payload SHA-256 does NOT match
    report = evaluate_scenario(gt_manifest, obs_manifest)
    ae = report.artifact_evaluations[0]
    assert ae.whole_payload_hash_match is False
    assert hashlib.sha256(rec.recovered_payload_bytes).hexdigest() != gt_manifest.artifacts[0].original_sha256


# ── TEST 7: UNACCOUNTED GAP DETECTION ON CLOSABLE TRUNCATION ───────────────

def test_07_unaccounted_gap_detected_on_closable_truncation():
    """Verify that evaluator flags UNACCOUNTED_GAP when engine reports missing=0 despite ground-truth gap."""
    gt_manifest, evidence_bytes = build_truncated_closable_content_loss_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    report = evaluate_scenario(gt_manifest, obs_manifest)
    # The reconstructor appends closers and reports missing_bytes = 0.
    # The evaluator detects the 14-byte physical gap from ground truth.
    unacc_violations = [v for v in report.forensic_violations if "UNACCOUNTED_GAP" in v]
    assert len(unacc_violations) == 1
    assert "Physical gap present in ground truth" in unacc_violations[0]


# ── TEST 8: REFUSAL TO HALLUCINATE INCOMPLETE TOKENS ───────────────────────

def test_08_truncated_incomplete_refuses_hallucination():
    """Assert engine drops incomplete token tail, preserves verified prefix, and does not hallucinate."""
    gt_manifest, evidence_bytes = build_truncated_incomplete_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    rec = obs_manifest.recoveries[0]
    assert rec.observed_status == "PARTIALLY_RECOVERED"
    # Reconstructed bytes must be 0 (no hallucinated completions)
    assert rec.total_reconstructed_bytes == 0
    # The unterminated 'act' string is dropped as missing bytes
    assert rec.total_missing_bytes > 0
    assert rec.total_verified_bytes == len(b'{"session_id": "sess-9921", "user_id": 501')

    # Evaluator byte correctness on preserved prefix
    report = evaluate_scenario(gt_manifest, obs_manifest)
    ae = report.artifact_evaluations[0]
    assert ae.v_byte_correctness == 1.0


# ── TEST 9: AMBIGUOUS NOISE NEGATIVE CONTROL ───────────────────────────────

def test_09_unrecoverable_noise_negative_control():
    """Assert corrupted non-JSON noise with braces is safely classified as UNRECOVERABLE."""
    gt_manifest, evidence_bytes = build_unrecoverable_noise_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Scanner must not produce a false positive candidate, or tracer falls back to UNRECOVERABLE
    report = evaluate_scenario(gt_manifest, obs_manifest)
    ae = report.artifact_evaluations[0]
    assert ae.expected_status == "UNRECOVERABLE"
    assert ae.observed_status == "UNRECOVERABLE"
    assert ae.status_match is True
    assert ae.false_fully_recovered is False
    assert len(report.forensic_violations) == 0


# ── TEST 10: INCORRECT RECOVERED BYTES FAIL VERIFICATION ───────────────────

def test_10_incorrect_recovered_bytes_fail_verification():
    """Verify that byte divergence in verified segment triggers FALSE_VERIFIED_BYTES."""
    gt_manifest, evidence_bytes = build_clean_json_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Tamper with the recovered payload bytes while keeping segment bounds
    mutated_obs = copy.deepcopy(obs_manifest)
    raw = bytearray(mutated_obs.recoveries[0].recovered_payload_bytes)
    raw[5] = ord("X")  # Tamper with byte
    mutated_obs.recoveries[0].recovered_payload_bytes = bytes(raw)

    report = evaluate_scenario(gt_manifest, mutated_obs)
    false_v_violations = [v for v in report.forensic_violations if "FALSE_VERIFIED_BYTES" in v]
    assert len(false_v_violations) >= 1
    ae = report.artifact_evaluations[0]
    assert ae.v_byte_correctness < 1.0


# ── TEST 11: UNMAPPABLE COORDINATES REMAIN UNKNOWN ─────────────────────────

def test_11_unmappable_coordinates_remain_none():
    """Verify that observed segments with unmappable evidence bounds preserve original_start=None."""
    from benchmark.evaluator import map_recovery_to_ground_truth

    raw_bytes = b"A" * 50
    import base64
    art = PhysicalArtifactRecord(
        artifact_id="art-test",
        original_filename="test.json",
        format="json",
        original_size_bytes=50,
        original_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        original_bytes_b64=base64.b64encode(raw_bytes).decode("ascii"),
        header_evidence_offset=100,
        placements=[PhysicalPlacement(fragment_index=0, evidence_offset=100, evidence_length=50, original_offset=0)],
        damage_intervals=[],
    )

    # Segment at offset 5000 is outside any known placement
    seg = ObservedRecoverySegment(
        segment_id="orphan-seg",
        category="VERIFIED",
        evidence_start=5000,
        evidence_end=5020,
        recovered_start=0,
        recovered_end=20,
    )
    rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-test",
        detected_format="json",
        observed_status="PARTIALLY_RECOVERED",
        confidence_score=50,
        total_input_bytes=20,
        total_verified_bytes=20,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=b"B" * 20,
        verified_segments=[seg],
    )

    mapped = map_recovery_to_ground_truth(rec, art)
    assert mapped.verified_segments[0].original_start is None
    assert mapped.verified_segments[0].original_end is None


# ── TEST 12: ZERO GROUND TRUTH LEAKAGE INTO PIPELINE ───────────────────────

def test_12_no_ground_truth_leaked_to_pipeline():
    """Verify that scan_evidence and execute_traced_recoveries receive only evidence bytes and filename."""
    gt_manifest, evidence_bytes = build_clean_json_scenario(seed=42)

    with patch("benchmark.run_baseline.scan_evidence") as mock_scan, patch(
        "benchmark.run_baseline.execute_traced_recoveries"
    ) as mock_trace:
        from backend.app.recovery.scanner import scan_evidence
        from backend.app.recovery.tracer import execute_traced_recoveries

        mock_scan.side_effect = scan_evidence
        mock_trace.side_effect = execute_traced_recoveries

        run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

        mock_scan.assert_called_once()
        scan_args, scan_kwargs = mock_scan.call_args
        assert scan_args == (evidence_bytes,)
        assert scan_kwargs == {}

        mock_trace.assert_called_once()
        trace_args, trace_kwargs = mock_trace.call_args
        assert trace_kwargs.get("filename") == gt_manifest.evidence_buffer_id or trace_args[0] == gt_manifest.evidence_buffer_id
        content_passed = trace_kwargs.get("content") if "content" in trace_kwargs else trace_args[1]
        assert content_passed == evidence_bytes


# ── TEST 13: END-TO-END JSON BENCHMARK RUNNER ──────────────────────────────

def test_13_json_benchmark_runner():
    """Verify that run_json_benchmark executes all scenarios and emits structured report."""
    report = run_json_benchmark(seed=42, verbose=False)

    summary = report["summary"]
    assert summary["scenarios_total"] == 7
    assert summary["marker_free_verified"] is True
    assert len(report["scenarios"]) == 7

    scenario_ids = [s["scenario_id"] for s in report["scenarios"]]
    assert scenario_ids == [
        "json-clean",
        "json-truncated-closable",
        "json-truncated-closable-content-loss",
        "json-truncated-incomplete",
        "json-unrecoverable-noise",
        "json-with-binary-noise",
        "json-multi-candidate-independent",
    ]

    # Clean scenario must pass
    clean_sc = next(s for s in report["scenarios"] if s["scenario_id"] == "json-clean")
    assert clean_sc["passed"] is True
    assert clean_sc["artifacts"][0]["whole_payload_hash_match"] is True

    # Truncated closable pure repair must pass cleanly with matching payload hash
    pure_sc = next(s for s in report["scenarios"] if s["scenario_id"] == "json-truncated-closable")
    assert pure_sc["passed"] is True
    assert pure_sc["artifacts"][0]["status_match"] is True
    assert pure_sc["artifacts"][0]["whole_payload_hash_match"] is True
    assert pure_sc["artifacts"][0]["v_byte_correctness"] == 1.0
    assert pure_sc["artifacts"][0]["r_byte_correctness"] == 1.0
    assert len(pure_sc["forensic_violations"]) == 0

    # Truncated closable with content loss must record the honest UNACCOUNTED_GAP capability gap
    loss_sc = next(s for s in report["scenarios"] if s["scenario_id"] == "json-truncated-closable-content-loss")
    assert loss_sc["artifacts"][0]["status_match"] is True
    assert loss_sc["artifacts"][0]["whole_payload_hash_match"] is False
    assert any("UNACCOUNTED_GAP" in v for v in loss_sc["forensic_violations"])


# ── TEST 14: EXISTING BASELINE SCENARIOS REMAIN UNCHANGED ──────────────────

def test_14_existing_baseline_scenarios_remain_unchanged():
    """Assert all 6 existing baseline scenarios continue to pass without regression."""
    baseline_report = run_baseline_benchmark(seed=42, verbose=False)
    assert baseline_report["summary"]["scenarios_total"] == 6
    assert baseline_report["summary"]["scenarios_passed"] == 6
    assert baseline_report["summary"]["scenarios_failed"] == 0
    assert baseline_report["summary"]["total_forensic_violations"] == 0


# ── TEST 15: PURE STRUCTURAL CLOSER REPAIR EXACT ACCOUNTING ────────────────

def test_15_pure_structural_closer_repair_exact_accounting():
    """Verify exact accounting for pure structural closer repair (Case 2).

    When evidence loses only closing brackets:
    - Verified bytes = surviving prefix bytes
    - Reconstructed bytes = closing brackets
    - Missing bytes = 0
    - Status = PARTIALLY_RECOVERED (R > 0)
    - Whole-payload SHA-256 matches original ground truth
    - Reconstructed closing brackets map to original coordinates
    - Reconstructed byte correctness = 1.0 (matches expected deterministic repair)
    - Zero forensic violations (no UNACCOUNTED_GAP)
    """
    gt_manifest, evidence_bytes = build_truncated_closable_pure_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    assert len(obs_manifest.recoveries) == 1
    rec = obs_manifest.recoveries[0]
    art = gt_manifest.artifacts[0]

    assert rec.observed_status == "PARTIALLY_RECOVERED"
    assert rec.total_verified_bytes == 89
    assert rec.total_reconstructed_bytes == 2
    assert rec.total_missing_bytes == 0
    assert rec.total_input_bytes == 91
    assert rec.recovered_payload_bytes == art.original_bytes

    report = evaluate_scenario(gt_manifest, obs_manifest)
    assert len(report.artifact_evaluations) == 1
    ae = report.artifact_evaluations[0]

    assert ae.status_match is True
    assert ae.whole_payload_hash_match is True
    assert ae.false_fully_recovered is False
    assert ae.v_volume_accuracy == 1.0
    assert ae.r_volume_accuracy == 1.0
    assert ae.m_volume_accuracy == 1.0
    assert ae.v_interval_iou == 1.0
    assert ae.r_interval_iou == 1.0
    assert ae.v_byte_correctness == 1.0
    assert ae.r_byte_correctness == 1.0
    assert len(report.forensic_violations) == 0


# ── TEST 16: CONTENT LOSS PRECEDING CLOSERS SEGREGATION & UNACCOUNTED GAP ──

def test_16_content_loss_preceding_closers_segregation_and_unaccounted_gap():
    """Verify that when original content is lost preceding closers (Case 1):
    1. Surviving prefix remains verified only on known correspondence [0, 89).
    2. Appended closing brackets are NOT presented as original bytes (original_start is None).
    3. Appended closing brackets are NOT presented as evidence bytes (evidence_start is None).
    4. Absent content is not silently counted as recovered.
    5. Evaluator flags UNACCOUNTED_GAP due to ground-truth physical gap (14 bytes).
    6. Whole-payload SHA-256 does NOT match.
    """
    gt_manifest, evidence_bytes = build_truncated_closable_content_loss_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    rec = obs_manifest.recoveries[0]
    art = gt_manifest.artifacts[0]

    assert rec.observed_status == "PARTIALLY_RECOVERED"
    assert rec.total_verified_bytes == 89
    assert rec.total_reconstructed_bytes == 2
    assert rec.total_missing_bytes == 0

    # Segregate coordinates
    from benchmark.evaluator import map_recovery_to_ground_truth
    mapped_rec = map_recovery_to_ground_truth(rec, art)

    # 1. Verified segment correspondence
    assert len(mapped_rec.verified_segments) == 1
    v_seg = mapped_rec.verified_segments[0]
    assert v_seg.evidence_start == 0
    assert v_seg.evidence_end == 89
    assert v_seg.recovered_start == 0
    assert v_seg.recovered_end == 89
    assert v_seg.original_start == 0
    assert v_seg.original_end == 89

    # 2. Reconstructed segment: closing brackets appended at recovered offset [89, 91)
    assert len(mapped_rec.reconstructed_segments) == 1
    r_seg = mapped_rec.reconstructed_segments[0]
    assert r_seg.recovered_start == 89
    assert r_seg.recovered_end == 91
    # MUST NOT be presented as original bytes
    assert r_seg.original_start is None
    assert r_seg.original_end is None
    # MUST NOT be presented as evidence bytes
    assert r_seg.evidence_start is None
    assert r_seg.evidence_end is None

    # 3. Absent content detection
    report = evaluate_scenario(gt_manifest, obs_manifest)
    ae = report.artifact_evaluations[0]
    assert ae.whole_payload_hash_match is False
    assert ae.v_byte_correctness == 1.0
    assert ae.r_byte_correctness is None

    unacc_violations = [v for v in report.forensic_violations if "UNACCOUNTED_GAP" in v]
    assert len(unacc_violations) == 1
    assert "Physical gap present in ground truth" in unacc_violations[0]


# ── TEST 17: ADVERSARIAL RECONSTRUCTED CLOSER DIVERGENCE ───────────────────

def test_17_adversarial_reconstructed_closer_divergence():
    """Assert byte tampering in deterministic reconstructed segment triggers FALSE_RECONSTRUCTED_BYTES."""
    gt_manifest, evidence_bytes = build_truncated_closable_pure_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Tamper with the reconstructed closing brackets (replace with invalid closer)
    mutated_obs = copy.deepcopy(obs_manifest)
    payload_buf = bytearray(mutated_obs.recoveries[0].recovered_payload_bytes)
    # The last 2 bytes are reconstructed "]}"
    payload_buf[-2:] = b"XX"
    mutated_obs.recoveries[0].recovered_payload_bytes = bytes(payload_buf)

    report = evaluate_scenario(gt_manifest, mutated_obs)
    false_r_violations = [v for v in report.forensic_violations if "FALSE_RECONSTRUCTED_BYTES" in v]
    assert len(false_r_violations) == 1
    assert "diverge from expected deterministic repair" in false_r_violations[0]
    ae = report.artifact_evaluations[0]
    assert ae.r_byte_correctness < 1.0


# ── TEST 18: ADVERSARIAL FALSIFIED FULLY RECOVERED INVARIANT ───────────────

def test_18_adversarial_falsified_fully_recovered_invariant():
    """Assert claiming FULLY_RECOVERED on repaired closable JSON triggers INVALID_STATUS_INVARIANT."""
    gt_manifest, evidence_bytes = build_truncated_closable_pure_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Tamper with observed status to falsely claim full recovery despite R=2
    mutated_obs = copy.deepcopy(obs_manifest)
    mutated_obs.recoveries[0].observed_status = "FULLY_RECOVERED"

    report = evaluate_scenario(gt_manifest, mutated_obs)
    invariant_violations = [v for v in report.forensic_violations if "INVALID_STATUS_INVARIANT" in v]
    assert len(invariant_violations) >= 1
    assert any("INVALID_STATUS_INVARIANT" in v for v in report.forensic_violations)


# ── TEST 19: RECONSTRUCTED SUFFIX OF UNKNOWN POSITION REMAINS UNMAPPED ─────

def test_19_reconstructed_suffix_unknown_position_remains_unmapped():
    """Verify that reconstructed bytes whose original position is unprovable retain original_start=None.

    If ground truth records no matching terminal deterministic repair interval,
    reconstructed segments must never be mapped to original coordinates.
    """
    from benchmark.evaluator import map_recovery_to_ground_truth
    from benchmark.models import PhysicalDamageInterval

    # Create artifact with an unrepairable physical gap (NOT deterministic repair)
    gt_manifest, evidence_bytes = build_truncated_closable_pure_scenario(seed=42)
    art = gt_manifest.artifacts[0]

    # Mutate damage interval to RECONSTRUCTION_NONE (unknown original bytes)
    mutated_damage = [
        PhysicalDamageInterval(
            original_start=89,
            original_end=91,
            length=2,
            damage_type="PHYSICAL_GAP",
            reconstruction_mode="RECONSTRUCTION_NONE",
        )
    ]
    mutated_art = art.model_copy(update={"damage_intervals": mutated_damage})

    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)
    rec = obs_manifest.recoveries[0]

    mapped_rec = map_recovery_to_ground_truth(rec, mutated_art)
    assert len(mapped_rec.reconstructed_segments) == 1
    r_seg = mapped_rec.reconstructed_segments[0]

    # Must NOT have original coordinates assigned
    assert r_seg.original_start is None
    assert r_seg.original_end is None
    # Must NOT have evidence coordinates assigned
    assert r_seg.evidence_start is None
    assert r_seg.evidence_end is None
    # Recovered coordinates remain valid
    assert r_seg.recovered_start == 89
    assert r_seg.recovered_end == 91


# ── TEST 20: INCONSISTENT SEGMENT AND COUNT ACCOUNTING REJECTED ────────────

def test_20_inconsistent_segment_and_count_accounting_rejected():
    """Verify that inconsistent segment/count accounting or unrepresented payload volume is rejected.

    Specifically tests the reported numerical inconsistency:
    - Claiming V=87 when payload has 91 bytes and R=2 triggers UNCONSERVED_PAYLOAD_VOLUME.
    - Claiming V=87 when verified segments cover 89 bytes triggers INCONSISTENT_SEGMENT_ACCOUNTING.
    - Segment interval length [0, 87) triggers volume accuracy < 1.0 and interval IoU < 1.0.
    """
    gt_manifest, evidence_bytes = build_truncated_closable_pure_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # 1. Mutate total_verified_bytes to 87 (the exact error from the flawed report)
    # while segment remains [0, 89) and payload remains 91 bytes.
    mutated_obs_1 = copy.deepcopy(obs_manifest)
    mutated_obs_1.recoveries[0].total_verified_bytes = 87

    report_1 = evaluate_scenario(gt_manifest, mutated_obs_1)
    ae_1 = report_1.artifact_evaluations[0]

    # Both violations must be caught
    unconserved_violations = [v for v in report_1.forensic_violations if "UNCONSERVED_PAYLOAD_VOLUME" in v]
    assert len(unconserved_violations) == 1
    assert "Payload length (91) != observed V (87) + R (2)" in unconserved_violations[0]

    inconsistent_violations = [v for v in report_1.forensic_violations if "INCONSISTENT_SEGMENT_ACCOUNTING" in v]
    assert len(inconsistent_violations) == 1
    assert "Verified segment length sum (89) != total_verified_bytes (87)" in inconsistent_violations[0]

    assert report_1.passed is False
    assert ae_1.v_volume_accuracy == 87 / 89
    assert ae_1.v_volume_accuracy < 1.0

    # 2. Mutate segment bounds to [0, 87), leaving bytes [87, 89) unaccounted in payload
    mutated_obs_2 = copy.deepcopy(obs_manifest)
    mutated_obs_2.recoveries[0].total_verified_bytes = 87
    mutated_obs_2.recoveries[0].verified_segments[0].recovered_end = 87
    mutated_obs_2.recoveries[0].verified_segments[0].evidence_end = 87

    report_2 = evaluate_scenario(gt_manifest, mutated_obs_2)
    ae_2 = report_2.artifact_evaluations[0]

    # Payload volume is unconserved (91 != 87 + 2)
    assert any("UNCONSERVED_PAYLOAD_VOLUME" in v for v in report_2.forensic_violations)
    assert ae_2.v_volume_accuracy < 1.0
    assert ae_2.v_interval_iou < 1.0
    assert report_2.passed is False


# ── TEST 21: SYNTACTICALLY VALID JSON WITH PAYLOAD HASH MISMATCH ───────────

def test_21_valid_json_syntax_with_payload_hash_mismatch():
    """Verify that structurally valid JSON syntax is never conflated with original byte identity."""
    gt_manifest, evidence_bytes = build_truncated_closable_pure_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Produce an alternative, completely valid JSON payload of the exact same length (91 bytes)
    # Original: b'{"device": "telemetry-probe-4", "firmware": "v2.1.0", "readings": ["sensor_a", "sensor_b"]}'
    alt_payload = b'{"device": "telemetry-probe-X", "firmware": "v2.1.0", "readings": ["sensor_a", "sensor_b"]}'
    assert len(alt_payload) == 91
    parsed = json.loads(alt_payload)
    assert isinstance(parsed, dict)

    mutated_obs = copy.deepcopy(obs_manifest)
    mutated_obs.recoveries[0].recovered_payload_bytes = alt_payload

    report = evaluate_scenario(gt_manifest, mutated_obs)
    ae = report.artifact_evaluations[0]

    # Syntactic validity does NOT produce whole payload hash match
    assert ae.whole_payload_hash_match is False
    # Verified byte divergence is detected
    assert ae.v_byte_correctness < 1.0
    assert any("FALSE_VERIFIED_BYTES" in v for v in report.forensic_violations)
    assert report.passed is False


# ── TEST 22: CROSS-DOMAIN COORDINATE CONSERVATION INVARIANTS ──────────────

def test_22_cross_domain_coordinate_conservation_invariants():
    """Verify strict conservation invariants across Original (O), Evidence (E), and Recovered (R) domains.

    Enforces that:
    1. In Domain R (Recovered Payload Space):
       sum(len(v_R)) + sum(len(r_R)) == len(recovered_payload)
    2. In Domain E (Evidence Space):
       sum(len(v_E)) == len(evidence_bytes)
       Reconstructed segments have evidence_start=None, evidence_end=None.
    3. In Domain O (Original Artifact Space):
       Pure repair: sum(len(v_O)) + sum(len(r_O)) == original_size_bytes == 91.
       Content loss: sum(len(v_O)) + sum(len(r_O)) + gap_len == original_size_bytes == 103.
    4. Numeric sanity:
       rec.total_verified_bytes MUST be 89 (and NEVER 87).
       rec.total_reconstructed_bytes MUST be 2.
       rec.total_missing_bytes MUST be 0.
       V + R + M MUST be 91.
    """
    from benchmark.evaluator import map_recovery_to_ground_truth

    # ── Case A: Pure structural closer repair (Scenario B1) ──
    gt_pure, ev_pure = build_truncated_closable_pure_scenario(seed=42)
    art_pure = gt_pure.artifacts[0]
    obs_pure = run_pipeline_and_observe(gt_pure.evidence_buffer_id, ev_pure)
    rec_pure = obs_pure.recoveries[0]
    mapped_pure = map_recovery_to_ground_truth(rec_pure, art_pure)

    # Numerical truth
    assert rec_pure.total_verified_bytes == 89, f"Expected V=89, got {rec_pure.total_verified_bytes}"
    assert rec_pure.total_verified_bytes != 87, "Discrepancy: V must be 89, not 87!"
    assert rec_pure.total_reconstructed_bytes == 2
    assert rec_pure.total_missing_bytes == 0
    assert rec_pure.total_input_bytes == 91
    assert art_pure.original_size_bytes == 91
    assert len(ev_pure) == 89
    assert len(rec_pure.recovered_payload_bytes) == 91

    # Domain R conservation
    r_v_len = sum(s.recovered_end - s.recovered_start for s in mapped_pure.verified_segments)
    r_r_len = sum(s.recovered_end - s.recovered_start for s in mapped_pure.reconstructed_segments)
    assert r_v_len == 89
    assert r_r_len == 2
    assert r_v_len + r_r_len == len(rec_pure.recovered_payload_bytes) == 91

    # Domain E conservation
    e_v_len = sum(s.evidence_end - s.evidence_start for s in mapped_pure.verified_segments)
    assert e_v_len == len(ev_pure) == 89
    for r_seg in mapped_pure.reconstructed_segments:
        assert r_seg.evidence_start is None
        assert r_seg.evidence_end is None

    # Domain O conservation (for pure repair, original is completely covered)
    o_v_len = sum(s.original_end - s.original_start for s in mapped_pure.verified_segments if s.original_start is not None)
    o_r_len = sum(s.original_end - s.original_start for s in mapped_pure.reconstructed_segments if s.original_start is not None)
    assert o_v_len == 89
    assert o_r_len == 2
    assert o_v_len + o_r_len == art_pure.original_size_bytes == 91

    # ── Case B: Content loss preceding closers (Scenario B2) ──
    gt_loss, ev_loss = build_truncated_closable_content_loss_scenario(seed=42)
    art_loss = gt_loss.artifacts[0]
    obs_loss = run_pipeline_and_observe(gt_loss.evidence_buffer_id, ev_loss)
    rec_loss = obs_loss.recoveries[0]
    mapped_loss = map_recovery_to_ground_truth(rec_loss, art_loss)

    assert art_loss.original_size_bytes == 103
    assert len(ev_loss) == 89
    assert rec_loss.total_verified_bytes == 89
    assert rec_loss.total_reconstructed_bytes == 2
    assert rec_loss.total_missing_bytes == 0

    # In Domain O for content loss, reconstructed brackets CANNOT map to original coordinates
    o_loss_v_len = sum(s.original_end - s.original_start for s in mapped_loss.verified_segments if s.original_start is not None)
    o_loss_r_len = sum(s.original_end - s.original_start for s in mapped_loss.reconstructed_segments if s.original_start is not None)
    assert o_loss_v_len == 89
    assert o_loss_r_len == 0  # Unmapped!
    # Missing gap is 14 bytes: 89 + 14 = 103
    gap_len = art_loss.damage_intervals[0].length
    assert gap_len == 14
    assert o_loss_v_len + gap_len == art_loss.original_size_bytes == 103


# ── TEST 23: EMPTY SEGMENTS WITH NONZERO COUNTS REJECTED ──────────────────

def test_23_empty_segments_with_nonzero_counts_rejected():
    """Audit Cases 1 & 2: Assert claiming V > 0 or R > 0 with empty segment lists is rejected."""
    gt_manifest, evidence_bytes = build_truncated_closable_pure_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # 1. total_verified_bytes > 0, but verified_segments is empty
    mut_obs_1 = copy.deepcopy(obs_manifest)
    mut_obs_1.recoveries[0].verified_segments = []
    report_1 = evaluate_scenario(gt_manifest, mut_obs_1)
    assert any("INCONSISTENT_SEGMENT_ACCOUNTING" in v and "verified_segments is empty" in v for v in report_1.forensic_violations)
    assert report_1.passed is False

    # 2. total_reconstructed_bytes > 0, but reconstructed_segments is empty
    mut_obs_2 = copy.deepcopy(obs_manifest)
    mut_obs_2.recoveries[0].reconstructed_segments = []
    report_2 = evaluate_scenario(gt_manifest, mut_obs_2)
    assert any("INCONSISTENT_SEGMENT_ACCOUNTING" in v and "reconstructed_segments is empty" in v for v in report_2.forensic_violations)
    assert report_2.passed is False


# ── TEST 24: OVERLAPPING AND GAPPED PAYLOAD PARTITIONS REJECTED ───────────

def test_24_overlapping_and_gapped_payload_partitions_rejected():
    """Audit Cases 4, 5, 6: Overlapping segments and uncovered payload gaps trigger forensic violations."""
    from benchmark.models import ObservedRecoverySegment

    gt_manifest, evidence_bytes = build_truncated_closable_pure_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Overlapping segments whose lengths match total payload length:
    # Payload is 91 bytes. V covers [0, 60) (len 60), R covers [50, 81) (len 31).
    # 60 + 31 = 91 == len(payload).
    # They overlap at [50, 60), and leave an uncovered gap at [81, 91).
    v_mut = ObservedRecoverySegment(
        segment_id="v-overlap",
        category="VERIFIED",
        evidence_start=0,
        evidence_end=60,
        recovered_start=0,
        recovered_end=60,
    )
    r_mut = ObservedRecoverySegment(
        segment_id="r-overlap",
        category="RECONSTRUCTED",
        recovered_start=50,
        recovered_end=81,
    )

    mut_obs = copy.deepcopy(obs_manifest)
    mut_obs.recoveries[0].total_verified_bytes = 60
    mut_obs.recoveries[0].total_reconstructed_bytes = 31
    mut_obs.recoveries[0].verified_segments = [v_mut]
    mut_obs.recoveries[0].reconstructed_segments = [r_mut]

    report = evaluate_scenario(gt_manifest, mut_obs)
    overlap_violations = [v for v in report.forensic_violations if "OVERLAPPING_RECOVERED_SEGMENTS" in v]
    assert len(overlap_violations) == 1
    assert "v-overlap [0, 60) and r-overlap [50, 81)" in overlap_violations[0]
    assert report.passed is False

    # Disjoint segments leaving an uncovered gap in the middle:
    # V covers [0, 50), R covers [60, 91), total V+R = 50 + 31 = 81 != 91
    # Also test an internal gap where V+R == len(payload) is bypassed
    v_gap = ObservedRecoverySegment(
        segment_id="v-gap",
        category="VERIFIED",
        evidence_start=0,
        evidence_end=40,
        recovered_start=0,
        recovered_end=40,
    )
    r_gap = ObservedRecoverySegment(
        segment_id="r-gap",
        category="RECONSTRUCTED",
        recovered_start=50,
        recovered_end=81,
    )
    mut_obs_gap = copy.deepcopy(obs_manifest)
    mut_obs_gap.recoveries[0].total_verified_bytes = 40
    mut_obs_gap.recoveries[0].total_reconstructed_bytes = 31
    mut_obs_gap.recoveries[0].recovered_payload_bytes = obs_manifest.recoveries[0].recovered_payload_bytes[:81]
    mut_obs_gap.recoveries[0].verified_segments = [v_gap]
    mut_obs_gap.recoveries[0].reconstructed_segments = [r_gap]

    report_gap = evaluate_scenario(gt_manifest, mut_obs_gap)
    gap_violations = [v for v in report_gap.forensic_violations if "UNCOVERED_PAYLOAD_GAP" in v]
    assert len(gap_violations) >= 1
    assert any("[40, 50)" in v for v in gap_violations)
    assert report_gap.passed is False


# ── TEST 25: EVIDENCE-RECOVERED LENGTH MISMATCH REJECTED ──────────────────

def test_25_evidence_recovered_length_mismatch_rejected():
    """Audit Case 9: Verified segment where evidence length != recovered length is rejected."""
    from benchmark.models import ObservedRecoverySegment

    gt_manifest, evidence_bytes = build_truncated_closable_pure_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Segment claims evidence [0, 50) (len 50) but recovered [0, 60) (len 60)
    v_mismatch = ObservedRecoverySegment(
        segment_id="v-mismatch",
        category="VERIFIED",
        evidence_start=0,
        evidence_end=50,
        recovered_start=0,
        recovered_end=60,
    )
    mut_obs = copy.deepcopy(obs_manifest)
    mut_obs.recoveries[0].verified_segments = [v_mismatch]
    mut_obs.recoveries[0].total_verified_bytes = 60

    report = evaluate_scenario(gt_manifest, mut_obs)
    mismatch_violations = [v for v in report.forensic_violations if "MALFORMED_COORDINATE_INTERVAL" in v]
    assert len(mismatch_violations) >= 1
    assert any("evidence 50 != recovered 60" in v for v in mismatch_violations)
    assert report.passed is False


# ── TEST 26: RECONSTRUCTED UNCERTIFIED ORIGINAL COORDS FLAGGED & STRIPPED ─

def test_26_reconstructed_uncertified_original_coords_flagged_and_stripped():
    """Audit Case 10: Reconstructed segment claiming uncertified original coordinates is flagged and stripped."""
    from benchmark.evaluator import map_recovery_to_ground_truth
    from benchmark.models import ObservedRecoverySegment

    # Use content loss scenario where closing brackets do NOT have deterministic ground-truth certification
    gt_manifest, evidence_bytes = build_truncated_closable_content_loss_scenario(seed=42)
    art = gt_manifest.artifacts[0]
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Mutate reconstructed segment to fabricate original coordinates [89, 91)
    mut_obs = copy.deepcopy(obs_manifest)
    mut_obs.recoveries[0].reconstructed_segments[0].original_start = 89
    mut_obs.recoveries[0].reconstructed_segments[0].original_end = 91

    # 1. Evaluator flags UNCERTIFIED_RECONSTRUCTED_COORDINATES
    report = evaluate_scenario(gt_manifest, mut_obs)
    uncert_violations = [v for v in report.forensic_violations if "UNCERTIFIED_RECONSTRUCTED_COORDINATES" in v]
    assert len(uncert_violations) == 1
    assert "without ground-truth deterministic certification" in uncert_violations[0]

    # 2. Evaluator mapping defensively strips the uncertified coordinates
    mapped = map_recovery_to_ground_truth(mut_obs.recoveries[0], art)
    r_seg = mapped.reconstructed_segments[0]
    assert r_seg.original_start is None
    assert r_seg.original_end is None


# ── TEST 27: UNRECOVERABLE / EMPTY PAYLOAD NONZERO VOLUME REJECTED ─────────

def test_27_unrecoverable_and_empty_payload_nonzero_volume_rejected():
    """Audit Case 11: Unrecoverable status or empty payload claiming V > 0 or R > 0 is rejected."""
    gt_manifest, evidence_bytes = build_unrecoverable_noise_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Mutate to claim V=10, R=5 despite UNRECOVERABLE status and empty payload
    mut_obs = copy.deepcopy(obs_manifest)
    mut_obs.recoveries[0].total_verified_bytes = 10
    mut_obs.recoveries[0].total_reconstructed_bytes = 5

    report = evaluate_scenario(gt_manifest, mut_obs)
    unrec_violations = [v for v in report.forensic_violations if "UNCONSERVED_PAYLOAD_VOLUME" in v]
    assert len(unrec_violations) == 1
    assert "Status is UNRECOVERABLE with payload length 0, but observed V=10, R=5 (must be 0)" in unrec_violations[0]
    assert report.passed is False


# ── TEST 28: EVALUATOR IDEMPOTENCE AND NON-MUTATION ───────────────────────

def test_28_evaluator_idempotence_and_non_mutation():
    """Audit Case 12: Repeated evaluation of the same manifests produces identical results without mutation."""
    gt_manifest, evidence_bytes = build_truncated_closable_pure_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Capture initial states
    raw_v_start = obs_manifest.recoveries[0].verified_segments[0].original_start
    raw_r_start = obs_manifest.recoveries[0].reconstructed_segments[0].original_start
    assert raw_v_start is None
    assert raw_r_start is None

    rep1 = evaluate_scenario(gt_manifest, obs_manifest)
    rep2 = evaluate_scenario(gt_manifest, obs_manifest)
    rep3 = evaluate_scenario(gt_manifest, obs_manifest)

    # Results are completely deterministic and identical
    assert rep1 == rep2 == rep3
    assert rep1.passed is True
    assert len(rep1.forensic_violations) == 0

    # Underlying manifest objects were not mutated
    assert obs_manifest.recoveries[0].verified_segments[0].original_start is None
    assert obs_manifest.recoveries[0].reconstructed_segments[0].original_start is None


# ── TEST 29: MULTI-CANDIDATE JSON WITH BINARY NOISE ───────────────────────

def test_29_multi_candidate_json_with_binary_noise():
    """Scenario E: Candidate boundary isolates JSON from trailing high-entropy noise."""
    gt_manifest, evidence_bytes = build_json_with_binary_noise_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Candidate boundary must stop at the closing '}', excluding trailing noise
    assert len(obs_manifest.candidates) == 1
    cand = obs_manifest.candidates[0]
    art = gt_manifest.artifacts[0]
    assert cand.offset == art.header_evidence_offset
    assert cand.estimated_end_offset == cand.offset + art.original_size_bytes

    report = evaluate_scenario(gt_manifest, obs_manifest)
    assert report.passed is True
    assert len(report.artifact_evaluations) == 1
    ae = report.artifact_evaluations[0]
    assert ae.expected_status == "FULLY_RECOVERED"
    assert ae.observed_status == "FULLY_RECOVERED"
    assert ae.whole_payload_hash_match is True
    assert ae.v_volume_accuracy == 1.0
    assert ae.r_volume_accuracy == 1.0
    assert ae.m_volume_accuracy == 1.0
    assert len(report.forensic_violations) == 0


# ── TEST 30: TWO INDEPENDENT JSON DOCUMENTS SEPARATED BY NOISE ────────────

def test_30_two_independent_json_documents_separated_by_noise():
    """Scenario F: Multi-candidate discovery and independent recovery without cross-contamination."""
    gt_manifest, evidence_bytes = build_two_independent_json_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Exactly 2 candidates discovered
    assert len(obs_manifest.candidates) == 2
    c0 = obs_manifest.candidates[0]
    c1 = obs_manifest.candidates[1]

    art1 = gt_manifest.artifacts[0]
    art2 = gt_manifest.artifacts[1]

    assert c0.offset == art1.header_evidence_offset
    assert c0.estimated_end_offset == art1.header_evidence_offset + art1.original_size_bytes
    assert c1.offset == art2.header_evidence_offset
    assert c1.estimated_end_offset == art2.header_evidence_offset + art2.original_size_bytes

    # Both recovered independently into separate RecoveryRun records
    assert len(obs_manifest.recoveries) == 2
    r0 = obs_manifest.recoveries[0]
    r1 = obs_manifest.recoveries[1]

    assert r0.observed_status == "FULLY_RECOVERED"
    assert r1.observed_status == "FULLY_RECOVERED"
    assert r0.total_verified_bytes == art1.original_size_bytes
    assert r1.total_verified_bytes == art2.original_size_bytes

    # Evaluator validates both artifacts independently
    report = evaluate_scenario(gt_manifest, obs_manifest)
    assert report.passed is True
    assert len(report.artifact_evaluations) == 2
    assert all(ae.status_match for ae in report.artifact_evaluations)
    assert all(ae.whole_payload_hash_match for ae in report.artifact_evaluations)
    assert len(report.forensic_violations) == 0


# ── TEST 31: MATCHING INTEGRITY — FALSE POSITIVES & DUPLICATES PENALIZED ──

def test_31_multi_candidate_ground_truth_matching_and_fp_detection():
    """Evaluator strictly rejects runs containing unexpected false-positive candidates or duplicates."""
    gt_manifest, evidence_bytes = build_two_independent_json_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Inject an unexpected phantom candidate into the observed manifest
    from benchmark.models import ObservedCandidateResult
    mut_obs = copy.deepcopy(obs_manifest)
    phantom_cand = ObservedCandidateResult(
        candidate_id="cand-phantom",
        evidence_buffer_id=gt_manifest.evidence_buffer_id,
        format="json",
        offset=999,
        detected_header_length=1,
        estimated_end_offset=1050,
        is_unbounded=False,
    )
    mut_obs.candidates.append(phantom_cand)

    report = evaluate_scenario(gt_manifest, mut_obs)
    # The scenario must fail because of the false-positive candidate
    assert report.passed is False
    assert report.candidate_metrics.false_positives == 1
    fp_violations = [v for v in report.forensic_violations if "FALSE_POSITIVE_CANDIDATE" in v]
    assert len(fp_violations) == 1
    assert "cand-phantom" in fp_violations[0]


# ── TEST 32: CANDIDATE MATCHING PERMUTATION INVARIANCE ────────────────────

def test_32_candidate_matching_permutation_invariance():
    """Order of observed candidates in manifest does not alter ground-truth association."""
    gt_manifest, evidence_bytes = build_two_independent_json_scenario(seed=42)
    obs_manifest = run_pipeline_and_observe(gt_manifest.evidence_buffer_id, evidence_bytes)

    # Invert candidate and recovery ordering
    permuted_obs = copy.deepcopy(obs_manifest)
    permuted_obs.candidates.reverse()
    permuted_obs.recoveries.reverse()

    report_orig = evaluate_scenario(gt_manifest, obs_manifest)
    report_perm = evaluate_scenario(gt_manifest, permuted_obs)

    assert report_orig.passed is True
    assert report_perm.passed is True
    assert len(report_orig.artifact_evaluations) == len(report_perm.artifact_evaluations) == 2

    # Both orderings map each candidate to the correct artifact
    evals_by_id_orig = {ae.artifact_id: ae for ae in report_orig.artifact_evaluations}
    evals_by_id_perm = {ae.artifact_id: ae for ae in report_perm.artifact_evaluations}

    for art_id in ("art-json-multi-01", "art-json-multi-02"):
        assert evals_by_id_orig[art_id].whole_payload_hash_match is True
        assert evals_by_id_perm[art_id].whole_payload_hash_match is True
        assert evals_by_id_orig[art_id].v_volume_accuracy == evals_by_id_perm[art_id].v_volume_accuracy == 1.0


# ── TEST 33: CORRUPTED JSON SYNTAX HONEST ACCOUNTING ──────────────────────

def test_33_corrupted_json_syntax_honest_accounting():
    """A candidate with syntax corruption (NUL in string) reports CORRUPTED with V=0 and M=len(input)."""
    from backend.app.recovery.reconstructors.json import reconstruct_json

    corrupt_evidence = b'{"user": "alice", "bio": "developer \x00 admin", "active": true}'
    r = reconstruct_json(corrupt_evidence)

    assert r.status == "CORRUPTED"
    assert r.success is False
    assert r.verified_bytes == 0
    assert r.reconstructed_bytes == 0
    assert r.missing_bytes == len(corrupt_evidence)
    # Accounting invariant holds: V + R + M == len(input)
    assert r.verified_bytes + r.reconstructed_bytes + r.missing_bytes == len(corrupt_evidence)
    assert len(r.damage_regions) == 1
    assert r.damage_regions[0]["type"] == "CORRUPTED"
    assert r.damage_regions[0]["status"] == "UNRECOVERABLE"
