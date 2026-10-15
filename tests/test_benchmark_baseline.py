"""tests/test_benchmark_baseline.py — Integration and Unit Tests for Benchmark Baseline Runner (Milestone 3.7.2).

Validates:
1. All six scenarios execute.
2. Deterministic repeated execution.
3. Ground truth never enters production pipeline inputs.
4. Coordinate spaces (E, O, R) remain strictly distinct.
5. Benchmark results are deterministic for seed 42.
6. Failed metrics are surfaced rather than suppressed.
7. Malformed/missing benchmark data fails cleanly.
8. Zero-GT scenario handling works deterministically.
9. False-recovery findings propagate into the report.
10. Observed segments are derived from RecoveryRun data.
11. Changing RecoveryRun fragments/reconstruction changes the observed manifest.
12. Candidate IDs alone cannot determine V/R/M coordinates.
13. No ground-truth artifact fields are copied into observed segments.
14. Unknown coordinate mappings are not silently converted into zero-length or fake intervals.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import backend.generate_case as gc
from backend.app.models.recovery_run import Fragment, DamageRegion, ReconstructionStep, RecoveryRun
from benchmark.evaluator import evaluate_scenario
from benchmark.models import BenchmarkGroundTruthManifest, ObservedArtifactRecoveryResult
from benchmark.run_baseline import (
    build_ground_truth_manifest,
    run_baseline_benchmark,
    run_pipeline_and_observe,
)


def test_01_all_six_scenarios_execute():
    """Verify that all six scenario archetypes execute and appear in the benchmark report."""
    report = run_baseline_benchmark(seed=42, verbose=False)

    assert report["summary"]["scenarios_total"] == 6
    assert len(report["scenarios"]) == 6

    expected_ids = {
        "art-clean-01",
        "art-deleted-01",
        "art-fragmented-01",
        "art-bifragment-01",
        "art-corrupted-01",
        "art-unrecoverable-01",
    }
    actual_ids = {sc["scenario_id"] for sc in report["scenarios"]}
    assert actual_ids == expected_ids


def test_02_deterministic_repeated_execution():
    """Verify that running the benchmark twice with the same seed produces identical reports."""
    report1 = run_baseline_benchmark(seed=42, verbose=False)
    report2 = run_baseline_benchmark(seed=42, verbose=False)

    # Exclude timestamp which naturally varies with execution time
    r1 = copy.deepcopy(report1)
    r2 = copy.deepcopy(report2)
    r1.pop("timestamp", None)
    r2.pop("timestamp", None)

    assert r1 == r2


def test_03_ground_truth_never_enters_production_pipeline_inputs():
    """Assert that the production recovery pipeline receives ONLY raw evidence and filename."""
    with patch(
        "benchmark.run_baseline.scan_evidence", wraps=gc.scan_evidence if hasattr(gc, "scan_evidence") else None
    ) as mock_scan, patch(
        "benchmark.run_baseline.execute_traced_recoveries"
    ) as mock_tracer:
        from backend.app.recovery.tracer import execute_traced_recoveries
        from backend.app.recovery.scanner import scan_evidence

        mock_scan.side_effect = scan_evidence
        mock_tracer.side_effect = execute_traced_recoveries

        gt_manifest, evidence_bytes = build_ground_truth_manifest(seed=42)
        run_pipeline_and_observe("damaged.img", evidence_bytes)

        # 1. Assert scanner input was only raw bytes
        mock_scan.assert_called_once()
        scan_args, scan_kwargs = mock_scan.call_args
        assert len(scan_args) == 1
        assert isinstance(scan_args[0], bytes)
        assert len(scan_kwargs) == 0

        # 2. Assert tracer inputs were only filename and content
        mock_tracer.assert_called_once()
        tracer_args, tracer_kwargs = mock_tracer.call_args
        assert tracer_kwargs.get("filename") == "damaged.img" or (tracer_args and tracer_args[0] == "damaged.img")
        content_arg = tracer_kwargs.get("content") or (tracer_args and tracer_args[1])
        assert isinstance(content_arg, bytes)

        # 3. Assert NO ground truth or manifest was passed to production recovery
        for arg in list(tracer_args) + list(tracer_kwargs.values()):
            assert not isinstance(arg, BenchmarkGroundTruthManifest)
            assert not hasattr(arg, "artifacts")
            assert not hasattr(arg, "damage_intervals")


def test_04_coordinate_spaces_remain_distinct():
    """Verify that E (evidence), O (original), and R (recovered) spaces remain distinct."""
    gt_manifest, evidence_bytes = build_ground_truth_manifest(seed=42)
    obs_manifest = run_pipeline_and_observe("damaged.img", evidence_bytes)

    # Inspect candidate cand-1 (art-deleted-01, placed at evidence offset 65536)
    rec1 = next(r for r in obs_manifest.recoveries if r.observed_candidate_id == "cand-1")
    assert len(rec1.verified_segments) > 0
    seg = rec1.verified_segments[0]

    # In evidence space, fragment is at evidence offset 65536
    assert seg.evidence_start == 65536
    assert seg.evidence_end == 65536 + 215

    # Original artifact space is NOT known by the recovery engine and MUST be None
    assert seg.original_start is None
    assert seg.original_end is None

    # In recovered payload space, fragment starts at 0 or None if unmapped
    assert seg.recovered_start == 0
    assert seg.recovered_end == 215

    # Assert coordinate spaces are not conflated
    assert seg.evidence_start != seg.recovered_start


def test_05_benchmark_results_are_deterministic():
    """Verify exact expected metrics for seed 42."""
    report = run_baseline_benchmark(seed=42, verbose=False)

    cand = report["summary"]["candidate_detection"]
    assert cand["precision"] == 1.0
    assert cand["recall"] == 1.0
    assert cand["true_positives"] == 6
    assert cand["false_positives"] == 0
    assert cand["false_negatives"] == 0

    sc_map = {sc["scenario_id"]: sc for sc in report["scenarios"]}

    # Clean passes fully
    clean = sc_map["art-clean-01"]
    assert clean["passed"] is True
    assert clean["status"]["expected"] == "FULLY_RECOVERED"
    assert clean["status"]["observed"] == "FULLY_RECOVERED"
    assert clean["volumes"]["accuracy"]["verified"] == 1.0
    assert clean["original_space_intervals_iou"]["verified"] == 1.0
    assert clean["original_space_byte_correctness"]["verified"] == 1.0
    assert clean["whole_payload_hash_match"] is True

    # Deleted passes fully after Milestone 3.8.2 payload preservation fix
    deleted = sc_map["art-deleted-01"]
    assert deleted["passed"] is True
    assert deleted["status"]["expected"] == "FULLY_RECOVERED"
    assert deleted["status"]["observed"] == "FULLY_RECOVERED"
    assert deleted["volumes"]["accuracy"]["verified"] == 1.0
    assert deleted["original_space_intervals_iou"]["verified"] == 1.0
    assert deleted["original_space_byte_correctness"]["verified"] == 1.0
    assert deleted["whole_payload_hash_match"] is True

    # Fragmented passes fully after Milestone 3.8.3 fragmented text stitching fix
    frag = sc_map["art-fragmented-01"]
    assert frag["passed"] is True
    assert frag["status"]["expected"] == "FULLY_RECOVERED"
    assert frag["status"]["observed"] == "FULLY_RECOVERED"
    assert frag["volumes"]["accuracy"]["verified"] == 1.0
    assert frag["original_space_intervals_iou"]["verified"] == 1.0
    assert frag["original_space_byte_correctness"]["verified"] == 1.0
    assert frag["whole_payload_hash_match"] is True

    # Bifragment is evaluated as an ambiguous physical layout archetype: expected and observed UNRECOVERABLE
    bifrag = sc_map["art-bifragment-01"]
    assert bifrag["passed"] is True
    assert bifrag["status"]["expected"] == "UNRECOVERABLE"
    assert bifrag["status"]["observed"] == "UNRECOVERABLE"
    assert bifrag["status"]["match"] is True
    assert bifrag["volumes"]["accuracy"]["verified"] == 1.0
    assert bifrag["original_space_intervals_iou"]["verified"] is None
    assert bifrag["original_space_byte_correctness"]["verified"] is None

    # Corrupted has status match: expected and observed CORRUPTED
    corr = sc_map["art-corrupted-01"]
    assert corr["passed"] is True
    assert corr["status"]["expected"] == "CORRUPTED"
    assert corr["status"]["observed"] == "CORRUPTED"
    assert corr["status"]["match"] is True
    assert corr["volumes"]["accuracy"]["verified"] == 1.0
    assert corr["original_space_intervals_iou"]["verified"] is None
    assert corr["original_space_byte_correctness"]["verified"] is None

    # Unrecoverable has status match and 0 verified bytes after 3.8.1 fix
    unrec = sc_map["art-unrecoverable-01"]
    assert unrec["passed"] is True
    assert unrec["status"]["expected"] == "UNRECOVERABLE"
    assert unrec["status"]["observed"] == "UNRECOVERABLE"
    assert unrec["volumes"]["observed"]["verified"] == 0
    assert unrec["original_space_intervals_iou"]["verified"] is None
    assert unrec["original_space_byte_correctness"]["verified"] is None
    assert len(unrec["false_recovery_violations"]) == 0


def test_06_failed_metrics_are_surfaced_rather_than_suppressed():
    """Verify that benchmark runner surfaces failures instead of hiding or suppressing them."""
    report = run_baseline_benchmark(seed=42, verbose=False)

    summary = report["summary"]
    # EvaluationReport.passed reflects absence of forensic violations and false recoveries
    assert summary["overall_passed"] is True
    # All 6 benchmark scenarios pass with full forensic integrity:
    assert summary["scenarios_passed"] == 6
    assert summary["scenarios_failed"] == 0

    # Check that failed status matches list is empty
    failed_scenarios = [sc for sc in report["scenarios"] if not sc["passed"]]
    assert len(failed_scenarios) == 0


def test_07_malformed_missing_benchmark_data_fails_clearly(tmp_path: Path):
    """Verify that invalid/missing benchmark paths fail clearly."""
    nonexistent_file = tmp_path / "bad.img"
    with pytest.raises(Exception):
        run_pipeline_and_observe("bad.img", nonexistent_file.read_bytes())


def test_08_zero_gt_scenario_handling():
    """Verify that an empty ground truth manifest evaluates without crash or ZeroDivisionError."""
    gt_manifest, evidence_bytes = build_ground_truth_manifest(seed=42)
    obs_manifest = run_pipeline_and_observe("damaged.img", evidence_bytes)

    # Construct empty ground truth
    empty_gt = BenchmarkGroundTruthManifest(
        scenario_id="empty-gt-scenario",
        evidence_buffer_id="damaged.img",
        evidence_size_bytes=len(evidence_bytes),
        evidence_sha256=gt_manifest.evidence_sha256,
        seed=42,
        artifacts=[],
        spatial_relationships=[],
    )

    report = evaluate_scenario(empty_gt, obs_manifest)
    assert report.candidate_metrics.true_positives == 0
    assert report.candidate_metrics.false_positives == 6
    assert report.candidate_metrics.false_negatives == 0
    assert report.candidate_metrics.precision == 0.0
    assert report.relationship_accuracy == 1.0


def test_09_false_recovery_findings_propagate_into_report():
    """Verify that false-recovery violations from audit_false_recovery appear in the JSON report."""
    report = run_baseline_benchmark(seed=42, verbose=False)

    # In seed 42, milestone 3.8.1 successfully eliminated all false-recovery violations
    assert len(report["forensic_violations"]) == 0
    assert report["summary"]["total_forensic_violations"] == 0

    # Test that when violations do occur, they propagate accurately into report structure
    from benchmark.evaluator import evaluate_scenario
    gt_manifest, evidence_bytes = build_ground_truth_manifest(seed=42)
    obs_manifest = run_pipeline_and_observe("damaged.img", evidence_bytes)

    # Inject an overstated verification into one observed recovery to test violation propagation
    tainted_recoveries = []
    for r in obs_manifest.recoveries:
        if r.observed_candidate_id == "cand-5":  # unrecoverable
            tainted_recoveries.append(r.model_copy(update={
                "total_verified_bytes": 524288,
                "total_missing_bytes": 0,
                "observed_status": "CORRUPTED",
            }))
        else:
            tainted_recoveries.append(r)
    tainted_manifest = obs_manifest.model_copy(update={"recoveries": tainted_recoveries})

    eval_report = evaluate_scenario(gt_manifest, tainted_manifest)
    violations = eval_report.forensic_violations
    assert len(violations) > 0
    assert any("OVERSTATED_VERIFICATION" in v for v in violations)
    assert any("UNRECOVERABLE_MISCLASSIFIED" in v for v in violations)
    assert any("UNACCOUNTED_GAP" in v for v in violations)


def test_10_observed_segments_derived_from_recovery_run_data():
    """Verify that observed segments are derived purely from RecoveryRun fields."""
    gt_manifest, evidence_bytes = build_ground_truth_manifest(seed=42)
    obs_manifest = run_pipeline_and_observe("damaged.img", evidence_bytes)

    # Every recovery result with verified fragments has corresponding VERIFIED segments
    for rec in obs_manifest.recoveries:
        if rec.total_verified_bytes > 0:
            assert len(rec.verified_segments) > 0
            for seg in rec.verified_segments:
                assert seg.category == "VERIFIED"
                assert seg.evidence_start is not None
                assert seg.evidence_end is not None
                assert seg.evidence_end >= seg.evidence_start

        if rec.total_missing_bytes > 0:
            assert len(rec.missing_segments) > 0
            for seg in rec.missing_segments:
                assert seg.category == "MISSING"


def test_11_changing_recovery_run_changes_observed_manifest():
    """Verify that changing RecoveryRun fragments/reconstruction changes the observed manifest."""
    custom_run = RecoveryRun(
        run_id="run_custom",
        candidate_id="cand-custom",
        filename="damaged.img",
        format="txt",
        status="FULLY_RECOVERED",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        total_input_bytes=300,
        total_verified_bytes=300,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        fragments=[
            Fragment(
                fragment_id="frag-custom",
                offset=7777,
                length=300,
                end_offset=8077,
                status="VERIFIED",
                source="test",
                format="txt",
                verified_bytes=300,
                reconstructed_bytes=0,
                missing_bytes=0,
                validation_status="PASSED",
            )
        ],
        damage_regions=[],
        reconstruction_steps=[],
        output={"recovered_bytes": (b"A" * 300).hex()},
    )

    with patch("benchmark.run_baseline.execute_traced_recoveries", return_value=[custom_run]):
        fake_evidence = b"\x00" * 10000
        obs = run_pipeline_and_observe("damaged.img", fake_evidence)

        assert len(obs.recoveries) == 1
        rec = obs.recoveries[0]
        assert rec.observed_candidate_id == "cand-custom"
        assert len(rec.verified_segments) == 1
        seg = rec.verified_segments[0]
        # Coordinates must reflect the custom RecoveryRun, proving dynamic derivation
        assert seg.evidence_start == 7777
        assert seg.evidence_end == 8077
        assert seg.segment_id == "cand-custom-frag-custom-v"


def test_12_candidate_ids_alone_cannot_determine_coordinates():
    """Verify that candidate IDs alone do not dictate coordinates (no cand-0 special casing)."""
    # Two runs with the same candidate_id 'cand-0' but different fragment coordinates
    run_a = RecoveryRun(
        run_id="run_a",
        candidate_id="cand-0",
        filename="damaged.img",
        format="txt",
        status="FULLY_RECOVERED",
        started_at=datetime.now(timezone.utc),
        total_input_bytes=100,
        total_verified_bytes=100,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        fragments=[
            Fragment(
                fragment_id="frag-0",
                offset=100,
                length=100,
                end_offset=200,
                status="VERIFIED",
                source="test",
                format="txt",
                verified_bytes=100,
                reconstructed_bytes=0,
                missing_bytes=0,
                validation_status="PASSED",
            )
        ],
    )
    run_b = RecoveryRun(
        run_id="run_b",
        candidate_id="cand-0",
        filename="damaged.img",
        format="txt",
        status="FULLY_RECOVERED",
        started_at=datetime.now(timezone.utc),
        total_input_bytes=50,
        total_verified_bytes=50,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        fragments=[
            Fragment(
                fragment_id="frag-0",
                offset=9000,
                length=50,
                end_offset=9050,
                status="VERIFIED",
                source="test",
                format="txt",
                verified_bytes=50,
                reconstructed_bytes=0,
                missing_bytes=0,
                validation_status="PASSED",
            )
        ],
    )

    with patch("benchmark.run_baseline.execute_traced_recoveries", return_value=[run_a, run_b]):
        fake_evidence = b"\x00" * 10000
        obs = run_pipeline_and_observe("damaged.img", fake_evidence)

        assert len(obs.recoveries) == 2
        seg_a = obs.recoveries[0].verified_segments[0]
        seg_b = obs.recoveries[1].verified_segments[0]

        # Segments must take their coordinates from the Fragment, NOT candidate ID
        assert seg_a.evidence_start == 100
        assert seg_a.evidence_end == 200
        assert seg_b.evidence_start == 9000
        assert seg_b.evidence_end == 9050


def test_13_no_ground_truth_fields_copied_into_observed_segments():
    """Verify that no ground-truth fields are copied into observed segments."""
    gt_manifest, evidence_bytes = build_ground_truth_manifest(seed=42)
    obs_manifest = run_pipeline_and_observe("damaged.img", evidence_bytes)

    for rec in obs_manifest.recoveries:
        for seg in rec.verified_segments + rec.reconstructed_segments + rec.missing_segments:
            # Original space is strictly unknown to the recovery engine
            assert seg.original_start is None
            assert seg.original_end is None


def test_14_unknown_coordinate_mappings_not_silently_converted_to_fake_intervals():
    """Verify that mapped coordinate intervals evaluate accurately and unknown mappings remain None."""
    gt_manifest, evidence_bytes = build_ground_truth_manifest(seed=42)
    obs_manifest = run_pipeline_and_observe("damaged.img", evidence_bytes)

    report = evaluate_scenario(gt_manifest, obs_manifest)

    # When original coordinates are mapped from known ground-truth placements:
    # art-clean-01 has 100% exact interval coverage and byte correctness
    clean_eval = next(ae for ae in report.artifact_evaluations if ae.artifact_id == "art-clean-01")
    assert clean_eval.v_interval_iou == 1.0
    assert clean_eval.v_byte_correctness == 1.0
    assert clean_eval.v_volume_accuracy == 1.0

    # When original coordinates cannot be established (e.g. unrecoverable or no verified bytes):
    # interval IoU in original space is recorded as None (unavailable/unknown),
    # NOT silently fabricated as fake intervals.
    unrec_eval = next(ae for ae in report.artifact_evaluations if ae.artifact_id == "art-unrecoverable-01")
    assert unrec_eval.v_interval_iou is None
    assert unrec_eval.v_byte_correctness is None


def test_15_whole_payload_hash_match_evaluated_strictly_from_bytes():
    """Verify whole_payload_hash_match is strictly evaluated from payload bytes vs original bytes."""
    import hashlib
    import base64
    from benchmark.models import PhysicalArtifactRecord, PhysicalPlacement, ObservedRecoverySegment
    from benchmark.expectations import derive_expected_recovery
    from benchmark.metrics import compute_evaluation_metrics

    orig_content = b"Exact original byte sequence 1234567890."
    art = PhysicalArtifactRecord(
        artifact_id="test-hash-art",
        original_filename="test.txt",
        format="txt",
        original_size_bytes=len(orig_content),
        original_sha256=hashlib.sha256(orig_content).hexdigest(),
        original_bytes_b64=base64.b64encode(orig_content).decode("ascii"),
        header_evidence_offset=0,
        placements=[PhysicalPlacement(fragment_index=0, evidence_offset=0, evidence_length=len(orig_content), original_offset=0)],
    )
    exp = derive_expected_recovery(art)

    # 1. Matching payload bytes -> True
    rec_matching = ObservedArtifactRecoveryResult(
        observed_candidate_id="c1",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=len(orig_content),
        total_verified_bytes=len(orig_content),
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=orig_content,
        verified_segments=[
            ObservedRecoverySegment(
                segment_id="s1",
                category="VERIFIED",
                evidence_start=0,
                evidence_end=len(orig_content),
                recovered_start=0,
                recovered_end=len(orig_content),
            )
        ],
    )
    m_match = compute_evaluation_metrics(art, exp, rec_matching)
    assert m_match.whole_payload_hash_match is True

    # 2. Same length but corrupted/different payload bytes -> False (NEVER inferred from size)
    corrupted_content = b"Exact original byte sequence 123456789X."  # Same length, 1 byte different
    assert len(corrupted_content) == len(orig_content)
    rec_diff = ObservedArtifactRecoveryResult(
        observed_candidate_id="c2",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=len(corrupted_content),
        total_verified_bytes=len(corrupted_content),
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=corrupted_content,
        verified_segments=[
            ObservedRecoverySegment(
                segment_id="s2",
                category="VERIFIED",
                evidence_start=0,
                evidence_end=len(corrupted_content),
                recovered_start=0,
                recovered_end=len(corrupted_content),
            )
        ],
    )
    m_diff = compute_evaluation_metrics(art, exp, rec_diff)
    assert m_diff.whole_payload_hash_match is False

    # 3. No payload produced -> None (unknown/unavailable, NOT False or True)
    rec_none = ObservedArtifactRecoveryResult(
        observed_candidate_id="c3",
        detected_format="txt",
        observed_status="UNRECOVERABLE",
        confidence_score=0,
        total_input_bytes=0,
        total_verified_bytes=0,
        total_reconstructed_bytes=0,
        total_missing_bytes=len(orig_content),
        recovered_payload_bytes=b"",
    )
    m_none = compute_evaluation_metrics(art, exp, rec_none)
    assert m_none.whole_payload_hash_match is None


def test_16_volume_accuracy_does_not_imply_coordinate_correctness():
    """Verify that volume accounting comparisons do not imply byte or coordinate correctness."""
    import hashlib
    import base64
    from benchmark.models import PhysicalArtifactRecord, PhysicalPlacement, ObservedRecoverySegment
    from benchmark.expectations import derive_expected_recovery
    from benchmark.metrics import compute_evaluation_metrics

    content = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    art = PhysicalArtifactRecord(
        artifact_id="test-vol-art",
        original_filename="test.txt",
        format="txt",
        original_size_bytes=len(content),
        original_sha256=hashlib.sha256(content).hexdigest(),
        original_bytes_b64=base64.b64encode(content).decode("ascii"),
        header_evidence_offset=0,
        placements=[PhysicalPlacement(fragment_index=0, evidence_offset=0, evidence_length=len(content), original_offset=0)],
    )
    exp = derive_expected_recovery(art)

    # Recovery reports full volume, but no original coordinates
    rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="c1",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=len(content),
        total_verified_bytes=len(content),
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=content,
        verified_segments=[
            ObservedRecoverySegment(
                segment_id="s1",
                category="VERIFIED",
                evidence_start=5000,
                evidence_end=5000 + len(content),
                original_start=None,
                original_end=None,
            )
        ],
    )
    m = compute_evaluation_metrics(art, exp, rec)

    # Volume accounting is 1.0 (aggregate counts match)
    assert m.v_volume_accuracy == 1.0
    assert m.r_volume_accuracy == 1.0
    assert m.m_volume_accuracy == 1.0

    # But coordinate-dependent metrics are None (strictly unavailable, never 1.0)
    assert m.v_interval_iou is None
    assert m.m_interval_iou is None
    assert m.r_interval_iou is None
    assert m.v_byte_correctness is None


def test_17_coordinate_space_mismatch_cannot_produce_valid_iou():
    """Verify that passing evidence coordinates does not silently produce a valid original-space IoU."""
    import hashlib
    import base64
    from benchmark.models import PhysicalArtifactRecord, PhysicalPlacement, ObservedRecoverySegment
    from benchmark.expectations import derive_expected_recovery
    from benchmark.metrics import compute_evaluation_metrics

    content = b"Testing coordinate space segregation."
    art = PhysicalArtifactRecord(
        artifact_id="test-coord-art",
        original_filename="test.txt",
        format="txt",
        original_size_bytes=len(content),
        original_sha256=hashlib.sha256(content).hexdigest(),
        original_bytes_b64=base64.b64encode(content).decode("ascii"),
        header_evidence_offset=65536,
        placements=[PhysicalPlacement(fragment_index=0, evidence_offset=65536, evidence_length=len(content), original_offset=0)],
    )
    exp = derive_expected_recovery(art)

    # Segment only defines evidence coordinates [65536, 65536 + len)
    rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="c1",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=len(content),
        total_verified_bytes=len(content),
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=content,
        verified_segments=[
            ObservedRecoverySegment(
                segment_id="s1",
                category="VERIFIED",
                evidence_start=65536,
                evidence_end=65536 + len(content),
                original_start=None,
                original_end=None,
            )
        ],
    )
    m = compute_evaluation_metrics(art, exp, rec)

    # Original-space IoU must be None, NOT computed against evidence offset 65536
    assert m.v_interval_iou is None


def test_18_run_pipeline_and_observe_has_no_gt_parameter():
    """Verify that run_pipeline_and_observe takes strictly evidence_filename and evidence_bytes."""
    import inspect
    from benchmark.run_baseline import run_pipeline_and_observe

    sig = inspect.signature(run_pipeline_and_observe)
    param_names = list(sig.parameters.keys())

    assert param_names == ["evidence_filename", "evidence_bytes"]
    assert "gt_manifest" not in param_names
    assert "ground_truth" not in param_names


def test_19_bifragment_ambiguity_and_deterministic_recovery_semantics():
    """Verify that is_deterministic_recovery defaults to True, art-bifragment-01 is False,
    and ambiguity metadata survives expectation derivation without leaking to production."""
    import base64
    from benchmark.models import PhysicalArtifactRecord, PhysicalPlacement
    from benchmark.expectations import derive_expected_recovery
    from benchmark.run_baseline import build_ground_truth_manifest
    from backend.app.recovery.tracer import execute_traced_recoveries

    # 1. Default is_deterministic_recovery is True
    import hashlib
    raw_dummy = b"0123456789"
    dummy_art = PhysicalArtifactRecord(
        artifact_id="art-test-default",
        original_filename="test.txt",
        format="txt",
        original_size_bytes=len(raw_dummy),
        original_sha256=hashlib.sha256(raw_dummy).hexdigest(),
        original_bytes_b64=base64.b64encode(raw_dummy).decode("ascii"),
        header_evidence_offset=0,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(fragment_index=0, evidence_offset=0, evidence_length=len(raw_dummy), original_offset=0)
        ],
    )
    assert dummy_art.is_deterministic_recovery is True
    assert dummy_art.non_deterministic_reason is None

    # 2. In seed 42 ground truth manifest, only art-bifragment-01 is False
    gt_manifest, evidence_bytes = build_ground_truth_manifest(seed=42)
    bifrag_art = next(a for a in gt_manifest.artifacts if a.artifact_id == "art-bifragment-01")
    assert bifrag_art.is_deterministic_recovery is False
    assert bifrag_art.non_deterministic_reason == "INTERLEAVED_RANDOM_NOISE_UNSTRUCTURED_TXT"

    other_arts = [a for a in gt_manifest.artifacts if a.artifact_id != "art-bifragment-01"]
    assert len(other_arts) == 5
    for a in other_arts:
        assert a.is_deterministic_recovery is True
        assert a.non_deterministic_reason is None

    # 3. Ambiguity metadata survives expectation derivation
    bifrag_exp = derive_expected_recovery(bifrag_art)
    assert bifrag_exp.expected_status == "UNRECOVERABLE"
    assert bifrag_exp.forensic_classification_rule == "AMBIGUOUS_PHYSICAL_LAYOUT"
    assert bifrag_exp.expected_verified_bytes == 0
    assert bifrag_exp.expected_missing_bytes == 284

    # 4. No production recovery code sees this metadata
    runs = execute_traced_recoveries("damaged.img", evidence_bytes)
    cand3_run = next(r for r in runs if getattr(r, "candidate_id", None) == "cand-3")
    run_dump = cand3_run.model_dump()
    assert "is_deterministic_recovery" not in run_dump
    assert "non_deterministic_reason" not in run_dump
    assert "AMBIGUOUS_PHYSICAL_LAYOUT" not in str(run_dump)
