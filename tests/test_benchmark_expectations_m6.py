"""tests/test_benchmark_expectations_m6.py — Milestone 6 Unit & Regression Tests.

Validates:
1. subtract_damage_intervals:
   - Boundary-touching damage (left, right, abutting)
   - Partial overlap (prefix, infix, suffix)
   - Complete coverage (damage engulfing placement)
   - Nested damage intervals (inner damage inside larger damage)
   - Adjacent damage intervals (touching endpoints that merge)
   - Multiple surviving fragments from a single placement
   - Multiple placements with disjoint damage
   - Zero-length, inverted, and out-of-bounds damage intervals
   - Regression case: json-truncated-incomplete scenario coordinates
2. Volume metrics vs byte/coordinate correctness (Phase 4):
   - 0/0 zero-agreement: ratio is 1.0 but v_is_zero_agreement is True, no payload proof
   - Matching volume count with wrong bytes: v_volume_accuracy == 1.0, but v_byte_correctness == 0.0
   - Matching volume count with shifted coordinates: v_volume_accuracy == 1.0, but v_interval_iou == 0.0
   - One-sided zero volume: ratio is 0.0
"""

from __future__ import annotations

import base64
import hashlib
import pytest

from benchmark.expectations import (
    DerivedExpectation,
    derive_expected_recovery,
    subtract_damage_intervals,
)
from benchmark.metrics import (
    EvaluationMetrics,
    compute_evaluation_metrics,
    compute_volume_ratio,
)
from benchmark.models import (
    ObservedArtifactRecoveryResult,
    ObservedRecoverySegment,
    PhysicalArtifactRecord,
    PhysicalDamageInterval,
    PhysicalPlacement,
)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 3: subtract_damage_intervals Unit Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_subtract_empty_inputs():
    """Empty placements or max_bound <= 0 yield empty list."""
    assert subtract_damage_intervals([], [(10, 20)], max_bound=100) == []
    assert subtract_damage_intervals([(0, 50)], [], max_bound=0) == []
    assert subtract_damage_intervals([(0, 50)], [], max_bound=-5) == []


def test_subtract_no_damage():
    """No damage spans preserves valid placements within max_bound."""
    placements = [(0, 50), (60, 100)]
    assert subtract_damage_intervals(placements, [], max_bound=100) == [(0, 50), (60, 100)]


def test_subtract_partial_overlap_infix():
    """Damage in the middle of a placement splits it into two surviving fragments."""
    # Placement [0, 100) with damage [40, 60) -> [(0, 40), (60, 100)]
    placements = [(0, 100)]
    damage = [(40, 60)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(0, 40), (60, 100)]


def test_subtract_boundary_touching_left():
    """Damage touching placement left boundary [0, 50) and placement [50, 100) does not subtract from placement."""
    placements = [(50, 100)]
    damage = [(0, 50)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(50, 100)]


def test_subtract_boundary_touching_right():
    """Damage touching placement right boundary [50, 100) and placement [0, 50) does not subtract from placement."""
    placements = [(0, 50)]
    damage = [(50, 100)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(0, 50)]


def test_subtract_partial_overlap_prefix():
    """Damage overlapping the start of a placement preserves the suffix."""
    # Placement [20, 100), damage [10, 40) -> surviving [40, 100)
    placements = [(20, 100)]
    damage = [(10, 40)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(40, 100)]


def test_subtract_partial_overlap_suffix():
    """Damage overlapping the end of a placement preserves the prefix."""
    # Placement [0, 80), damage [60, 100) -> surviving [0, 60)
    placements = [(0, 80)]
    damage = [(60, 100)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(0, 60)]


def test_subtract_complete_coverage():
    """Damage completely covering a placement leaves zero surviving intervals."""
    placements = [(20, 80)]
    damage = [(10, 90)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == []


def test_subtract_nested_damage_intervals():
    """Nested/redundant damage intervals are normalized without double-counting."""
    # Placement [0, 100), damage [20, 80) and inner [30, 50) -> surviving [(0, 20), (80, 100)]
    placements = [(0, 100)]
    damage = [(20, 80), (30, 50)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(0, 20), (80, 100)]


def test_subtract_adjacent_and_overlapping_damage_intervals():
    """Adjacent damage spans [20, 40) and [40, 60) merge into [20, 60)."""
    placements = [(0, 100)]
    damage = [(20, 40), (40, 60)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(0, 20), (60, 100)]

    # Overlapping damage spans [20, 50) and [40, 70) merge into [20, 70)
    damage_overlap = [(20, 50), (40, 70)]
    surviving_overlap = subtract_damage_intervals(placements, damage_overlap, max_bound=100)
    assert surviving_overlap == [(0, 20), (70, 100)]


def test_subtract_multiple_damage_inside_one_placement():
    """Multiple damage spans inside one placement yield multiple fragments."""
    # Placement [0, 100), damage [20, 30), [50, 60), [80, 90) -> 4 fragments
    placements = [(0, 100)]
    damage = [(20, 30), (50, 60), (80, 90)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(0, 20), (30, 50), (60, 80), (90, 100)]


def test_subtract_zero_length_and_inverted_damage_ignored():
    """Zero-length (start == end) or inverted (start > end) intervals are safely filtered out."""
    placements = [(0, 100)]
    damage = [(50, 50), (80, 40), (20, 30)]  # only (20, 30) is valid
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(0, 20), (30, 100)]


def test_subtract_out_of_bounds_and_clamping():
    """Intervals extending beyond max_bound or below 0 are clamped appropriately."""
    placements = [(0, 150)]
    damage = [(-20, 20), (80, 200)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    # max_bound clamps placements to [0, 100)
    # damage clamped to [0, 20) and [80, 100)
    # surviving is [(20, 80)]
    assert surviving == [(20, 80)]


def test_regression_json_truncated_incomplete_coordinates():
    """Regression test: json-truncated-incomplete placement [0, 49) minus damage [42, 64) -> [(0, 42)]."""
    # From json-truncated-incomplete scenario:
    # orig_payload = 64 bytes
    # placement = evidence_length 49, original_offset 0 -> [0, 49)
    # damage = intact_prefix_len 42 to 64 -> [42, 64)
    placements = [(0, 49)]
    damage = [(42, 64)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=64)
    assert surviving == [(0, 42)]
    total_verified = sum(e - s for s, e in surviving)
    assert total_verified == 42


def test_subtract_damage_completely_beyond_max_bound():
    """Damage spans starting at or after max_bound do not affect surviving intervals."""
    placements = [(0, 50)]
    damage = [(100, 150), (200, 250)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(0, 50)]


def test_subtract_damage_empty_after_clamping():
    """Damage spans like [-50, 0) or [100, 150) that clamp to empty intervals are ignored."""
    placements = [(20, 80)]
    damage = [(-50, 0), (100, 150)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(20, 80)]


def test_subtract_placements_completely_beyond_max_bound():
    """Placements starting at or after max_bound or with end <= 0 are ignored."""
    placements = [(-50, 0), (100, 150), (0, 30)]
    damage = [(10, 20)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(0, 10), (20, 30)]


def test_subtract_duplicate_and_overlapping_placements():
    """Duplicate and overlapping placements are merged into canonical disjoint subintervals."""
    # Placements [0, 50) and [30, 80) overlap -> union [0, 80)
    # Damage [40, 60) -> surviving [(0, 40), (60, 80)]
    placements = [(0, 50), (30, 80)]
    damage = [(40, 60)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(0, 40), (60, 80)]

    # Duplicate placements
    placements_dup = [(0, 50), (0, 50)]
    surviving_dup = subtract_damage_intervals(placements_dup, [(20, 30)], max_bound=100)
    assert surviving_dup == [(0, 20), (30, 50)]


def test_subtract_negative_endpoints_handled_safely():
    """Negative endpoints in damage and placements are clamped to 0 without corrupting intervals."""
    # Placement [-20, 50) clamps to [0, 50)
    # Damage [-10, 20) clamps to [0, 20)
    # Surviving should be [(20, 50)]
    placements = [(-20, 50)]
    damage = [(-10, 20)]
    surviving = subtract_damage_intervals(placements, damage, max_bound=100)
    assert surviving == [(20, 50)]


# ══════════════════════════════════════════════════════════════════════════════
# Phase 4: Volume Metrics vs Correctness Distinction Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_volume_metrics_zero_zero_agreement():
    """0/0 volume ratio is 1.0 (convention), but v_is_zero_agreement is True and no payload proof is claimed."""
    zero_bytes = b"A" * 100
    art = PhysicalArtifactRecord(
        artifact_id="art-zero-01",
        original_filename="zero.txt",
        format="txt",
        original_size_bytes=100,
        original_sha256=hashlib.sha256(zero_bytes).hexdigest(),
        original_bytes_b64=base64.b64encode(zero_bytes).decode("ascii"),
        header_evidence_offset=0,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(fragment_index=0, evidence_offset=0, evidence_length=100, original_offset=0)
        ],
        damage_intervals=[
            PhysicalDamageInterval(original_start=0, original_end=100, length=100, damage_type="PHYSICAL_GAP")
        ],
        is_unrecoverable=True,
    )
    exp = DerivedExpectation(
        artifact_id="art-zero-01",
        expected_status="UNRECOVERABLE",
        expected_verified_bytes=0,
        expected_reconstructed_bytes=0,
        expected_missing_bytes=100,
    )
    rec = ObservedArtifactRecoveryResult(
        observed_candidate_id=None,
        detected_format="unknown",
        observed_status="UNRECOVERABLE",
        confidence_score=0,
        total_input_bytes=100,
        total_verified_bytes=0,
        total_reconstructed_bytes=0,
        total_missing_bytes=100,
        recovered_payload_bytes=b"",
    )

    metrics = compute_evaluation_metrics(art, exp, rec)

    # Ratio is 1.0 because both are 0
    assert metrics.v_volume_accuracy == 1.0
    # But zero agreement property flags it explicitly
    assert metrics.v_is_zero_agreement is True
    # And original space IoU and byte correctness are None (no spatial claims)
    assert metrics.v_interval_iou is None
    assert metrics.v_byte_correctness is None
    assert metrics.whole_payload_hash_match is None


def test_volume_metrics_matching_count_wrong_bytes():
    """Matching volume count (80 vs 80) gives volume_accuracy=1.0, but byte_correctness=0.0 and hash mismatch."""
    orig_payload = b"A" * 80
    wrong_payload = b"B" * 80
    assert len(orig_payload) == len(wrong_payload) == 80

    art = PhysicalArtifactRecord(
        artifact_id="art-wrong-bytes-01",
        original_filename="wrong.txt",
        format="txt",
        original_size_bytes=len(orig_payload),
        original_sha256=hashlib.sha256(orig_payload).hexdigest(),
        original_bytes_b64=base64.b64encode(orig_payload).decode("ascii"),
        header_evidence_offset=0,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(fragment_index=0, evidence_offset=0, evidence_length=len(orig_payload), original_offset=0)
        ],
        damage_intervals=[],
    )
    exp = derive_expected_recovery(art)
    assert exp.expected_verified_bytes == len(orig_payload)

    rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-0",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=90,
        total_input_bytes=len(orig_payload),
        total_verified_bytes=len(wrong_payload),
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=wrong_payload,
        verified_segments=[
            ObservedRecoverySegment(
                segment_id="cand-0-frag-0-v",
                category="VERIFIED",
                evidence_start=0,
                evidence_end=len(wrong_payload),
                recovered_start=0,
                recovered_end=len(wrong_payload),
                original_start=0,
                original_end=len(wrong_payload),
            )
        ],
    )

    metrics = compute_evaluation_metrics(art, exp, rec)

    # Volume accuracy is 1.0 (both are 96 bytes)
    assert metrics.v_volume_accuracy == 1.0
    assert metrics.v_is_zero_agreement is False
    # But byte correctness exposes the mismatch
    assert metrics.v_byte_correctness < 1.0
    # And whole payload hash match is False
    assert metrics.whole_payload_hash_match is False


def test_volume_metrics_matching_count_shifted_coordinates():
    """Matching volume count but disjoint coordinates gives interval IoU of 0.0."""
    placements = [(0, 50)]
    orig_payload = b"A" * 100
    art = PhysicalArtifactRecord(
        artifact_id="art-shifted-01",
        original_filename="shift.txt",
        format="txt",
        original_size_bytes=100,
        original_sha256=hashlib.sha256(orig_payload).hexdigest(),
        original_bytes_b64=base64.b64encode(orig_payload).decode("ascii"),
        header_evidence_offset=0,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(fragment_index=0, evidence_offset=0, evidence_length=50, original_offset=0)
        ],
        damage_intervals=[
            PhysicalDamageInterval(original_start=50, original_end=100, length=50, damage_type="PHYSICAL_GAP")
        ],
    )
    exp = DerivedExpectation(
        artifact_id="art-shifted-01",
        expected_status="PARTIALLY_RECOVERED",
        expected_verified_bytes=50,
        expected_reconstructed_bytes=0,
        expected_missing_bytes=50,
        expected_surviving_intervals=[(0, 50)],
    )

    # Observed recovered segment claimed at original coordinates [50, 100) instead of [0, 50)
    rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-0",
        detected_format="txt",
        observed_status="PARTIALLY_RECOVERED",
        confidence_score=50,
        total_input_bytes=50,
        total_verified_bytes=50,
        total_reconstructed_bytes=0,
        total_missing_bytes=50,
        recovered_payload_bytes=b"A" * 50,
        verified_segments=[
            ObservedRecoverySegment(
                segment_id="cand-0-frag-0-v",
                category="VERIFIED",
                recovered_start=0,
                recovered_end=50,
                original_start=50,
                original_end=100,  # shifted!
            )
        ],
    )

    metrics = compute_evaluation_metrics(art, exp, rec)

    # Volume accuracy is 1.0 (both 50)
    assert metrics.v_volume_accuracy == 1.0
    # But interval IoU between [0, 50) and [50, 100) is 0.0!
    assert metrics.v_interval_iou == 0.0


def test_volume_ratio_one_sided_zero():
    """One-sided zero volume ratio returns 0.0."""
    assert compute_volume_ratio(0, 50) == 0.0
    assert compute_volume_ratio(50, 0) == 0.0
