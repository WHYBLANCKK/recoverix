"""tests/test_benchmark_integrity_m316.py — Regression tests for benchmark integrity and edge cases (Milestone 3.16.0).

Verifies:
1. CLI main() exit code agreement: exits 0 on success, exits 1 on failure.
2. Candidate matching failure rejection: unmapped candidate does not bind to ground truth in 1-artifact run.
3. Zero-expected artifacts reject unexpected evaluations.
4. Baseline benchmark overall_passed requires non-empty ground truth scenarios.
5. Case sensitivity and strict identity in artifact correspondence.
6. Manifest validation rejects duplicate artifact IDs.
7. Repeated deterministic scenario evaluation.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import sys
from unittest.mock import patch
import pytest

from benchmark.evaluator import evaluate_scenario, EvaluationReport
from benchmark.metrics import EvaluationMetrics, CandidateDetectionMetrics
from benchmark.models import (
    BenchmarkGroundTruthManifest,
    BenchmarkObservedManifest,
    ObservedArtifactRecoveryResult,
    ObservedCandidateResult,
    ObservedRecoverySegment,
    PhysicalArtifactRecord,
    PhysicalPlacement,
)
from benchmark.run_baseline import main, run_baseline_benchmark


def _make_sample_artifact(
    artifact_id: str = "art-01",
    payload: bytes = b"Deterministic Integrity Payload 1234567890",
    fmt: str = "txt",
    offset: int = 0,
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
        header_evidence_offset=offset,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=offset,
                evidence_length=size,
                original_offset=0,
            )
        ],
        damage_intervals=[],
        is_unrecoverable=False,
    )


def test_cli_exit_code_zero_on_benchmark_success():
    """Verify that CLI main() exits with code 0 (normal termination) on clean benchmark pass."""
    with patch("sys.argv", ["run_baseline", "--quiet", "--seed", "42"]):
        # A successful run should either return normally or exit with code 0
        try:
            main()
        except SystemExit as exc:
            assert exc.code in (0, None)


def test_cli_exit_code_one_on_benchmark_failure():
    """Verify that CLI main() exits with code 1 if overall_passed is False."""
    from benchmark.run_baseline import execute_traced_recoveries as real_exec

    def fake_exec(*args, **kwargs):
        runs = real_exec(*args, **kwargs)
        for r in runs:
            # Force scenario failure on cand-2 (art-fragmented-01)
            if r.candidate_id == "cand-2":
                r.status = "PARTIALLY_RECOVERED"
        return runs

    with patch("benchmark.run_baseline.execute_traced_recoveries", side_effect=fake_exec):
        with patch("sys.argv", ["run_baseline", "--quiet", "--seed", "42"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1


def test_evaluate_scenario_rejects_unmapped_candidate_in_single_artifact_run():
    """Verify that a candidate failing matching does not silently bind to ground truth."""
    art = _make_sample_artifact(offset=0)
    gt = BenchmarkGroundTruthManifest(
        scenario_id="scen-unmapped-cand",
        evidence_buffer_id="buf-1",
        evidence_size_bytes=art.original_size_bytes + 1000,
        evidence_sha256="0" * 64,
        seed=42,
        artifacts=[art],
    )
    # Candidate offset is 500, but artifact is at 0 -> candidate matching fails (TP=0)
    cand_wrong = ObservedCandidateResult(
        candidate_id="cand-wrong",
        evidence_buffer_id="buf-1",
        format="txt",
        offset=500,
        detected_header_length=5,
        estimated_end_offset=600,
    )
    seg = ObservedRecoverySegment(
        segment_id="s1",
        category="VERIFIED",
        evidence_start=500,
        evidence_end=500 + art.original_size_bytes,
        original_start=0,
        original_end=art.original_size_bytes,
        recovered_start=0,
        recovered_end=art.original_size_bytes,
    )
    rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-wrong",
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
        scenario_id="scen-unmapped-cand",
        evidence_buffer_id="buf-1",
        candidates=[cand_wrong],
        recoveries=[rec],
    )

    report = evaluate_scenario(gt, obs)
    assert report.candidate_metrics.true_positives == 0
    # Because candidate did not match artifact, art was not bound
    assert len(report.artifact_evaluations) == 0
    assert report.passed is False


def test_zero_expected_artifacts_rejects_unexpected_evaluations():
    """Verify that a scenario expecting 0 artifacts fails report.passed if unexpected evaluations exist."""
    cand_metrics = CandidateDetectionMetrics(
        true_positives=0,
        false_positives=1,
        false_negatives=0,
        duplicate_count=0,
        precision=0.0,
        recall=0.0,
    )
    ae_unexpected = EvaluationMetrics(
        artifact_id="art-unexpected",
        format="txt",
        v_volume_accuracy=1.0,
        r_volume_accuracy=1.0,
        m_volume_accuracy=1.0,
        v_interval_iou=1.0,
        m_interval_iou=1.0,
        r_interval_iou=1.0,
        v_byte_correctness=1.0,
        r_byte_correctness=1.0,
        expected_status="FULLY_RECOVERED",
        observed_status="FULLY_RECOVERED",
        status_match=True,
        false_fully_recovered=False,
    )
    report = EvaluationReport(
        scenario_id="scen-zero-expected",
        evidence_buffer_id="buf-1",
        candidate_metrics=cand_metrics,
        relationship_accuracy=1.0,
        artifact_evaluations=[ae_unexpected],
        forensic_violations=[],
        expected_artifact_ids=[],
        expected_artifact_count=0,
    )
    assert report.passed is False


def test_baseline_summary_fails_when_zero_ground_truth_scenarios():
    """Verify that run_baseline_benchmark summary['overall_passed'] is False if GT has 0 scenarios."""
    from unittest.mock import patch
    import benchmark.run_baseline as rb

    def fake_build_gt(seed, *args, **kwargs):
        empty_gt = BenchmarkGroundTruthManifest(
            scenario_id="empty-gt",
            evidence_buffer_id="damaged.img",
            evidence_size_bytes=1024,
            evidence_sha256="0" * 64,
            seed=seed,
            artifacts=[],
            spatial_relationships=[],
        )
        return empty_gt, b"\x00" * 1024

    with patch("benchmark.run_baseline.build_ground_truth_manifest", side_effect=fake_build_gt):
        rep = run_baseline_benchmark(seed=42, verbose=False)
        assert rep["summary"]["scenarios_total"] == 0
        assert rep["summary"]["overall_passed"] is False


def test_case_sensitivity_of_artifact_ids():
    """Verify that artifact ID correspondence is case-sensitive and does not coerce case."""
    cand_metrics = CandidateDetectionMetrics(
        true_positives=1,
        false_positives=0,
        false_negatives=0,
        duplicate_count=0,
        precision=1.0,
        recall=1.0,
    )
    ae_upper = EvaluationMetrics(
        artifact_id="ART-01",  # uppercase
        format="txt",
        v_volume_accuracy=1.0,
        r_volume_accuracy=1.0,
        m_volume_accuracy=1.0,
        v_interval_iou=1.0,
        m_interval_iou=1.0,
        r_interval_iou=1.0,
        v_byte_correctness=1.0,
        r_byte_correctness=1.0,
        expected_status="FULLY_RECOVERED",
        observed_status="FULLY_RECOVERED",
        status_match=True,
        false_fully_recovered=False,
    )
    report = EvaluationReport(
        scenario_id="scen-case",
        evidence_buffer_id="buf-1",
        candidate_metrics=cand_metrics,
        relationship_accuracy=1.0,
        artifact_evaluations=[ae_upper],
        forensic_violations=[],
        expected_artifact_ids=["art-01"],  # lowercase
        expected_artifact_count=1,
    )
    assert report.passed is False


def test_ground_truth_manifest_rejects_duplicate_artifact_ids():
    """Verify that BenchmarkGroundTruthManifest raises ValueError on duplicate artifact IDs."""
    art1a = _make_sample_artifact(artifact_id="art-dup", offset=0)
    art1b = _make_sample_artifact(artifact_id="art-dup", offset=100)
    with pytest.raises(ValueError, match="Duplicate artifact_id"):
        BenchmarkGroundTruthManifest(
            scenario_id="scen-dup-gt",
            evidence_buffer_id="buf-1",
            evidence_size_bytes=2000,
            evidence_sha256="0" * 64,
            seed=42,
            artifacts=[art1a, art1b],
        )


def test_evaluate_scenario_deterministic_repeated_execution():
    """Verify repeated evaluate_scenario calls produce identical EvaluationReport data."""
    art = _make_sample_artifact(offset=0)
    gt = BenchmarkGroundTruthManifest(
        scenario_id="scen-det",
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
        scenario_id="scen-det",
        evidence_buffer_id="buf-1",
        candidates=[cand],
        recoveries=[rec],
    )

    r1 = evaluate_scenario(gt, obs)
    r2 = evaluate_scenario(gt, obs)

    assert r1.passed is True
    assert r2.passed is True
    assert r1.candidate_metrics == r2.candidate_metrics
    assert r1.relationship_accuracy == r2.relationship_accuracy
    assert r1.artifact_evaluations == r2.artifact_evaluations
    assert r1.forensic_violations == r2.forensic_violations
    assert r1.expected_artifact_ids == r2.expected_artifact_ids
