"""tests/test_evaluator_status_gate_m315.py — Regression tests for evaluator status_match gate (Milestone 3.15.0).

Verifies:
1. Status mismatch between expected and observed fails report.passed.
2. Malformed, empty, or unknown status strings fail status_match and report.passed.
3. Identical invalid status strings do not accidentally pass status_match.
4. Missing / unrecovered artifacts fail report.passed.
5. Overall engine status in run_baseline fails if any scenario fails.
6. Valid matching status with zero violations passes report.passed.
"""

from __future__ import annotations

import base64
import hashlib
from unittest.mock import patch
import pytest

from benchmark.evaluator import evaluate_scenario, EvaluationReport
from benchmark.expectations import DerivedExpectation, derive_expected_recovery
from benchmark.metrics import compute_evaluation_metrics
from benchmark.models import (
    BenchmarkGroundTruthManifest,
    BenchmarkObservedManifest,
    ObservedArtifactRecoveryResult,
    ObservedCandidateResult,
    ObservedRecoverySegment,
    PhysicalArtifactRecord,
    PhysicalPlacement,
)
from benchmark.run_baseline import run_baseline_benchmark


def _make_sample_artifact(
    artifact_id: str = "art-01",
    payload: bytes = b"Deterministic Evidence Payload 1234567890",
    fmt: str = "txt",
) -> PhysicalArtifactRecord:
    size = len(payload)
    sha = hashlib.sha256(payload).hexdigest()
    b64 = base64.b64encode(payload).decode("ascii")
    return PhysicalArtifactRecord(
        artifact_id=artifact_id,
        original_filename=f"{artifact_id}.{fmt}",
        format=fmt,
        original_size_bytes=size,
        original_sha256=sha,
        original_bytes_b64=b64,
        header_evidence_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=0,
                evidence_length=size,
                original_offset=0,
            )
        ],
        damage_intervals=[],
        is_unrecoverable=False,
    )


def test_status_match_gate_rejects_status_mismatch():
    """Verify that when observed_status does not match expected_status, report.passed is False."""
    art = _make_sample_artifact()
    gt = BenchmarkGroundTruthManifest(
        scenario_id="scen-status-mismatch",
        evidence_buffer_id="buf-1",
        evidence_size_bytes=art.original_size_bytes,
        evidence_sha256=art.original_sha256,
        seed=42,
        artifacts=[art],
    )
    cand = ObservedCandidateResult(
        candidate_id="cand-1",
        evidence_buffer_id="buf-1",
        format="txt",
        offset=0,
        detected_header_length=5,
        estimated_end_offset=art.original_size_bytes,
    )
    # Ground truth expectation is FULLY_RECOVERED, but engine reports CORRUPTED
    rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-1",
        detected_format="txt",
        observed_status="CORRUPTED",
        confidence_score=50,
        total_input_bytes=art.original_size_bytes,
        total_verified_bytes=0,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=b"",
    )
    obs = BenchmarkObservedManifest(
        scenario_id="scen-status-mismatch",
        evidence_buffer_id="buf-1",
        candidates=[cand],
        recoveries=[rec],
    )

    report = evaluate_scenario(gt, obs)
    assert len(report.artifact_evaluations) == 1
    ae = report.artifact_evaluations[0]
    assert ae.expected_status == "FULLY_RECOVERED"
    assert ae.observed_status == "CORRUPTED"
    assert ae.status_match is False
    # CRITICAL: report.passed MUST be False when status does not match
    assert report.passed is False


def test_status_match_gate_rejects_empty_or_unknown_status():
    """Verify that empty, malformed, or unsupported status values do not pass status_match."""
    art = _make_sample_artifact()
    exp = derive_expected_recovery(art)
    assert exp.expected_status == "FULLY_RECOVERED"

    for invalid_status in ["", "UNKNOWN", "PARTIAL", "RECOVERED", "INVALID_STATUS"]:
        rec = ObservedArtifactRecoveryResult(
            detected_format="txt",
            observed_status=invalid_status,
            confidence_score=50,
            total_input_bytes=art.original_size_bytes,
            total_verified_bytes=0,
            total_reconstructed_bytes=0,
            total_missing_bytes=0,
        )
        metrics = compute_evaluation_metrics(art, exp, rec)
        assert metrics.status_match is False


def test_status_match_rejects_identical_invalid_status():
    """Verify that identical invalid statuses do not pass status_match."""
    art = _make_sample_artifact()
    for invalid_status in ["", "UNKNOWN", "INVALID"]:
        exp = DerivedExpectation(
            artifact_id=art.artifact_id,
            expected_status=invalid_status,  # type: ignore[arg-type]
            expected_verified_bytes=art.original_size_bytes,
            expected_reconstructed_bytes=0,
            expected_missing_bytes=0,
        )
        rec = ObservedArtifactRecoveryResult(
            detected_format="txt",
            observed_status=invalid_status,
            confidence_score=50,
            total_input_bytes=art.original_size_bytes,
            total_verified_bytes=art.original_size_bytes,
            total_reconstructed_bytes=0,
            total_missing_bytes=0,
        )
        metrics = compute_evaluation_metrics(art, exp, rec)
        assert metrics.status_match is False


def test_evaluation_report_fails_when_expected_artifacts_not_recovered():
    """Verify that an observed run producing zero recoveries for ground-truth artifacts fails report.passed."""
    art = _make_sample_artifact()
    gt = BenchmarkGroundTruthManifest(
        scenario_id="scen-zero-rec",
        evidence_buffer_id="buf-1",
        evidence_size_bytes=art.original_size_bytes,
        evidence_sha256=art.original_sha256,
        seed=42,
        artifacts=[art],
    )
    obs = BenchmarkObservedManifest(
        scenario_id="scen-zero-rec",
        evidence_buffer_id="buf-1",
        candidates=[],
        recoveries=[],
    )

    report = evaluate_scenario(gt, obs)
    assert len(report.artifact_evaluations) == 0
    # CRITICAL: An evaluation with 0 recoveries when artifacts were expected MUST NOT pass
    assert report.passed is False


def test_evaluation_report_fails_when_partial_artifact_set_recovered():
    """Verify that recovering only 1 of 2 ground-truth artifacts fails report.passed."""
    art1 = _make_sample_artifact(artifact_id="art-01")
    art2 = _make_sample_artifact(artifact_id="art-02")
    gt = BenchmarkGroundTruthManifest(
        scenario_id="scen-partial-set",
        evidence_buffer_id="buf-1",
        evidence_size_bytes=art1.original_size_bytes + art2.original_size_bytes,
        evidence_sha256="0" * 64,
        seed=42,
        artifacts=[art1, art2],
    )
    cand1 = ObservedCandidateResult(
        candidate_id="cand-1",
        evidence_buffer_id="buf-1",
        format="txt",
        offset=0,
        detected_header_length=5,
        estimated_end_offset=art1.original_size_bytes,
    )
    seg1 = ObservedRecoverySegment(
        segment_id="s1",
        category="VERIFIED",
        evidence_start=0,
        evidence_end=art1.original_size_bytes,
        original_start=0,
        original_end=art1.original_size_bytes,
        recovered_start=0,
        recovered_end=art1.original_size_bytes,
    )
    rec1 = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-1",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=art1.original_size_bytes,
        total_verified_bytes=art1.original_size_bytes,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=art1.original_bytes,
        verified_segments=[seg1],
    )
    # Only cand-1 / rec1 recovered, art2 completely missed
    obs = BenchmarkObservedManifest(
        scenario_id="scen-partial-set",
        evidence_buffer_id="buf-1",
        candidates=[cand1],
        recoveries=[rec1],
    )

    report = evaluate_scenario(gt, obs)
    assert len(report.artifact_evaluations) == 1
    assert report.artifact_evaluations[0].status_match is True
    # CRITICAL: Even though rec1 matched status, art2 was missed! report.passed MUST be False
    assert report.passed is False


def test_evaluation_report_fails_when_artifact_evaluated_twice_and_other_omitted():
    """Verify that evaluating the same artifact twice does not mask a missing ground-truth artifact."""
    art1 = _make_sample_artifact(artifact_id="art-01")
    art2 = _make_sample_artifact(artifact_id="art-02")
    gt = BenchmarkGroundTruthManifest(
        scenario_id="scen-dup-eval",
        evidence_buffer_id="buf-1",
        evidence_size_bytes=art1.original_size_bytes + art2.original_size_bytes,
        evidence_sha256="0" * 64,
        seed=42,
        artifacts=[art1, art2],
    )
    cand1 = ObservedCandidateResult(
        candidate_id="cand-1",
        evidence_buffer_id="buf-1",
        format="txt",
        offset=0,
        detected_header_length=5,
        estimated_end_offset=art1.original_size_bytes,
    )
    seg1 = ObservedRecoverySegment(
        segment_id="s1",
        category="VERIFIED",
        evidence_start=0,
        evidence_end=art1.original_size_bytes,
        original_start=0,
        original_end=art1.original_size_bytes,
        recovered_start=0,
        recovered_end=art1.original_size_bytes,
    )
    # Two recoveries both claiming cand-1 (art1). art2 is completely omitted.
    rec1a = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-1",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=art1.original_size_bytes,
        total_verified_bytes=art1.original_size_bytes,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=art1.original_bytes,
        verified_segments=[seg1],
    )
    rec1b = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-1",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=art1.original_size_bytes,
        total_verified_bytes=art1.original_size_bytes,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=art1.original_bytes,
        verified_segments=[seg1],
    )
    obs = BenchmarkObservedManifest(
        scenario_id="scen-dup-eval",
        evidence_buffer_id="buf-1",
        candidates=[cand1],
        recoveries=[rec1a, rec1b],
    )

    report = evaluate_scenario(gt, obs)
    assert len(report.artifact_evaluations) == 2
    # Even though count is 2 (matching expected count of 2), art2 was omitted and art1 was duplicated
    assert report.passed is False


def test_evaluation_report_passes_when_all_status_match_and_zero_violations():
    """Verify that a legitimate full recovery with matching status and zero violations passes."""
    art = _make_sample_artifact()
    gt = BenchmarkGroundTruthManifest(
        scenario_id="scen-pass-clean",
        evidence_buffer_id="buf-1",
        evidence_size_bytes=art.original_size_bytes,
        evidence_sha256=art.original_sha256,
        seed=42,
        artifacts=[art],
    )
    cand = ObservedCandidateResult(
        candidate_id="cand-1",
        evidence_buffer_id="buf-1",
        format="txt",
        offset=0,
        detected_header_length=5,
        estimated_end_offset=art.original_size_bytes,
    )
    seg = ObservedRecoverySegment(
        segment_id="s1",
        category="VERIFIED",
        evidence_start=0,
        evidence_end=art.original_size_bytes,
        original_start=0,
        original_end=art.original_size_bytes,
        recovered_start=0,
        recovered_end=art.original_size_bytes,
    )
    rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-1",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=art.original_size_bytes,
        total_verified_bytes=art.original_size_bytes,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=art.original_bytes,
        verified_segments=[seg],
    )
    obs = BenchmarkObservedManifest(
        scenario_id="scen-pass-clean",
        evidence_buffer_id="buf-1",
        candidates=[cand],
        recoveries=[rec],
    )

    report = evaluate_scenario(gt, obs)
    assert len(report.artifact_evaluations) == 1
    assert report.artifact_evaluations[0].status_match is True
    assert len(report.forensic_violations) == 0
    assert report.passed is True


def test_baseline_summary_overall_passed_fails_when_scenario_fails():
    """Verify that run_baseline_benchmark summary['overall_passed'] is False if any scenario fails."""
    from benchmark.run_baseline import execute_traced_recoveries as real_exec

    def fake_exec(*args, **kwargs):
        runs = real_exec(*args, **kwargs)
        for r in runs:
            # Force status mismatch on cand-2 (art-fragmented-01 expects FULLY_RECOVERED)
            if r.candidate_id == "cand-2":
                r.status = "PARTIALLY_RECOVERED"
        return runs

    with patch("benchmark.run_baseline.execute_traced_recoveries", side_effect=fake_exec):
        rep = run_baseline_benchmark(seed=42, verbose=False)
        summary = rep["summary"]
        assert summary["scenarios_passed"] == 5
        assert summary["scenarios_failed"] == 1
        # CRITICAL: overall_passed MUST be False when a scenario failed
        assert summary["overall_passed"] is False


def test_empty_ground_truth_manifest_behaving_intentionally():
    """Verify that an empty ground truth manifest evaluates cleanly and passes when zero violations exist."""
    empty_gt = BenchmarkGroundTruthManifest(
        scenario_id="scen-empty-gt",
        evidence_buffer_id="buf-1",
        evidence_size_bytes=1024,
        evidence_sha256="0" * 64,
        seed=42,
        artifacts=[],
        spatial_relationships=[],
    )
    empty_obs = BenchmarkObservedManifest(
        scenario_id="scen-empty-gt",
        evidence_buffer_id="buf-1",
        candidates=[],
        recoveries=[],
    )

    report = evaluate_scenario(empty_gt, empty_obs)
    assert report.expected_artifact_count == 0
    assert len(report.artifact_evaluations) == 0
    assert len(report.forensic_violations) == 0
    assert report.candidate_metrics.true_positives == 0
    assert report.candidate_metrics.false_positives == 0
    assert report.candidate_metrics.false_negatives == 0
    assert report.passed is True
