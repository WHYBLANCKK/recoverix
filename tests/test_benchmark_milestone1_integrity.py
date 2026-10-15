"""tests/test_benchmark_milestone1_integrity.py — Milestone 1 Benchmark Integrity Tests.

Verifies:
1. Ground truth independence: expected payload is retained independently.
2. Coordinate mapping contract:
   - Maps evidence space to original space via physical placements.
   - Non-matching or out-of-bounds evidence intervals remain None.
   - Recovered length mismatch prevents invalid coordinate assignment.
3. Byte-correctness checks:
   - Correctly recovered bytes pass with v_byte_correctness=1.0 and v_interval_iou=1.0.
   - Divergent bytes in verified segments fail and trigger FALSE_VERIFIED_BYTES.
   - Missing coordinates produce None (N/A), never silently counting as verified.
4. Hash mismatch prevention:
   - Status match cannot conceal a payload hash divergence when FULLY_RECOVERED is expected.
   - Triggers FALSE_FULLY_RECOVERED_HASH_MISMATCH and EvaluationReport.passed is False.
5. Reconstructed artifact discrimination:
   - Reconstructed bytes (R > 0) cannot be declared FULLY_RECOVERED.
   - Divergent deterministic repair triggers FALSE_RECONSTRUCTED_BYTES.
"""

from __future__ import annotations

import base64
import hashlib
import pytest

from benchmark.evaluator import (
    audit_false_recovery,
    evaluate_scenario,
    map_recovery_to_ground_truth,
    EvaluationReport,
)
from benchmark.expectations import derive_expected_recovery
from benchmark.metrics import compute_evaluation_metrics
from benchmark.models import (
    BenchmarkGroundTruthManifest,
    BenchmarkObservedManifest,
    ObservedArtifactRecoveryResult,
    ObservedCandidateResult,
    ObservedRecoverySegment,
    PhysicalArtifactRecord,
    PhysicalDamageInterval,
    PhysicalPlacement,
)


def _create_test_artifact(
    artifact_id: str = "art-test-01",
    payload: bytes = b"1234567890" * 10,  # 100 bytes
    evidence_offset: int = 50000,
    damage: list[PhysicalDamageInterval] | None = None,
) -> PhysicalArtifactRecord:
    size = len(payload)
    sha = hashlib.sha256(payload).hexdigest()
    b64 = base64.b64encode(payload).decode("ascii")
    return PhysicalArtifactRecord(
        artifact_id=artifact_id,
        original_filename=f"{artifact_id}.txt",
        format="txt",
        original_size_bytes=size,
        original_sha256=sha,
        original_bytes_b64=b64,
        header_evidence_offset=evidence_offset,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=evidence_offset,
                evidence_length=size,
                original_offset=0,
            )
        ],
        damage_intervals=damage or [],
    )


def test_01_correctly_recovered_bytes_pass_and_compute_numeric_iou_and_correctness():
    """Requirement 1: Correctly recovered bytes yield numeric v_interval_iou=1.0 and v_byte_correctness=1.0."""
    payload = b"Exact byte test sequence for milestone 1 verification."
    art = _create_test_artifact(payload=payload, evidence_offset=10000)

    # Observed recovery with raw evidence coordinates only (original_start/end=None)
    raw_seg = ObservedRecoverySegment(
        segment_id="seg-1",
        category="VERIFIED",
        evidence_start=10000,
        evidence_end=10000 + len(payload),
        recovered_start=0,
        recovered_end=len(payload),
        original_start=None,
        original_end=None,
    )
    raw_rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-1",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=len(payload),
        total_verified_bytes=len(payload),
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=payload,
        verified_segments=[raw_seg],
    )

    # Map recovery to ground truth
    mapped_rec = map_recovery_to_ground_truth(raw_rec, art)
    mapped_seg = mapped_rec.verified_segments[0]

    assert mapped_seg.original_start == 0
    assert mapped_seg.original_end == len(payload)

    exp = derive_expected_recovery(art)
    metrics = compute_evaluation_metrics(art, exp, mapped_rec)
    violations = audit_false_recovery(art, mapped_rec, exp)

    assert metrics.v_interval_iou == 1.0
    assert metrics.v_byte_correctness == 1.0
    assert metrics.whole_payload_hash_match is True
    assert len(violations) == 0


def test_02_incorrect_bytes_cannot_be_classified_as_correctly_verified():
    """Requirement 2: Divergent bytes in verified segments fail and trigger FALSE_VERIFIED_BYTES."""
    orig_payload = b"Original pristine byte content that was placed in evidence."
    art = _create_test_artifact(payload=orig_payload, evidence_offset=20000)

    # Corrupt one byte in the recovered payload
    corrupted_payload = bytearray(orig_payload)
    corrupted_payload[15] ^= 0xFF
    corrupted_payload = bytes(corrupted_payload)

    raw_seg = ObservedRecoverySegment(
        segment_id="seg-corrupt",
        category="VERIFIED",
        evidence_start=20000,
        evidence_end=20000 + len(orig_payload),
        recovered_start=0,
        recovered_end=len(orig_payload),
        original_start=None,
        original_end=None,
    )
    raw_rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-corrupt",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=len(orig_payload),
        total_verified_bytes=len(orig_payload),
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=corrupted_payload,
        verified_segments=[raw_seg],
    )

    mapped_rec = map_recovery_to_ground_truth(raw_rec, art)
    exp = derive_expected_recovery(art)
    metrics = compute_evaluation_metrics(art, exp, mapped_rec)
    violations = audit_false_recovery(art, mapped_rec, exp)

    assert metrics.v_byte_correctness is not None
    assert metrics.v_byte_correctness < 1.0
    assert any("FALSE_VERIFIED_BYTES" in v for v in violations)
    assert any("FALSE_FULLY_RECOVERED_HASH_MISMATCH" in v for v in violations)

    # Evaluator report must fail
    rep = EvaluationReport(
        scenario_id="scen-test",
        evidence_buffer_id="buf-1",
        candidate_metrics=compute_evaluation_metrics.__globals__["CandidateDetectionMetrics"](
            1, 0, 0, 0, 1.0, 1.0
        ),
        relationship_accuracy=1.0,
        artifact_evaluations=[metrics],
        forensic_violations=violations,
        expected_artifact_ids=[art.artifact_id],
        expected_artifact_count=1,
    )
    assert rep.passed is False


def test_03_missing_coordinate_evidence_cannot_silently_count_as_verified():
    """Requirement 3: Missing coordinate evidence outputs None (N/A), never 1.0."""
    payload = b"Coordinate segregation test payload."
    art = _create_test_artifact(payload=payload, evidence_offset=30000)

    # Segment with evidence coords outside any placement of this artifact
    unmapped_seg = ObservedRecoverySegment(
        segment_id="seg-unmapped",
        category="VERIFIED",
        evidence_start=999999,
        evidence_end=999999 + len(payload),
        recovered_start=0,
        recovered_end=len(payload),
        original_start=None,
        original_end=None,
    )
    raw_rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-unmapped",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=len(payload),
        total_verified_bytes=len(payload),
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=payload,
        verified_segments=[unmapped_seg],
    )

    mapped_rec = map_recovery_to_ground_truth(raw_rec, art)
    mapped_seg = mapped_rec.verified_segments[0]

    # Cannot be mapped because [999999, ...) does not exist in artifact.placements
    assert mapped_seg.original_start is None
    assert mapped_seg.original_end is None

    exp = derive_expected_recovery(art)
    metrics = compute_evaluation_metrics(art, exp, mapped_rec)

    # When coordinates are unavailable, metrics MUST be None, not 1.0
    assert metrics.v_interval_iou is None
    assert metrics.v_byte_correctness is None


def test_04_hash_mismatch_cannot_be_hidden_by_status_matching_when_full_recovery_expected():
    """Requirement 4: Status match cannot conceal a payload hash divergence when FULLY_RECOVERED expected."""
    orig_payload = b"Target payload expecting exact byte identity."
    art = _create_test_artifact(payload=orig_payload, evidence_offset=40000)
    exp = derive_expected_recovery(art)
    assert exp.expected_status == "FULLY_RECOVERED"

    # Engine produces different payload of identical length, claiming FULLY_RECOVERED
    fake_payload = b"Completely different bytes of the exact size."
    assert len(fake_payload) == len(orig_payload)

    raw_rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-fake",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=len(fake_payload),
        total_verified_bytes=len(fake_payload),
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=fake_payload,
        verified_segments=[
            ObservedRecoverySegment(
                segment_id="seg-fake",
                category="VERIFIED",
                evidence_start=40000,
                evidence_end=40000 + len(fake_payload),
                original_start=0,
                original_end=len(fake_payload),
                recovered_start=0,
                recovered_end=len(fake_payload),
            )
        ],
    )

    metrics = compute_evaluation_metrics(art, exp, raw_rec)
    violations = audit_false_recovery(art, raw_rec, exp)

    # Status matches ("FULLY_RECOVERED" == "FULLY_RECOVERED")
    assert metrics.status_match is True
    # But whole payload hash fails
    assert metrics.whole_payload_hash_match is False
    # Violation emitted
    assert any("FALSE_FULLY_RECOVERED_HASH_MISMATCH" in v for v in violations)

    # Evaluator pass condition must reject this scenario
    rep = EvaluationReport(
        scenario_id="scen-test",
        evidence_buffer_id="buf-1",
        candidate_metrics=compute_evaluation_metrics.__globals__["CandidateDetectionMetrics"](
            1, 0, 0, 0, 1.0, 1.0
        ),
        relationship_accuracy=1.0,
        artifact_evaluations=[metrics],
        forensic_violations=violations,
        expected_artifact_ids=[art.artifact_id],
        expected_artifact_count=1,
    )
    assert rep.passed is False


def test_05_reconstructed_artifact_not_automatically_identical_merely_for_parsing():
    """Requirement 5: Reconstructed artifact with R > 0 cannot be considered FULLY_RECOVERED."""
    full_payload = b"A" * 50 + b"B" * 50
    damage = [
        PhysicalDamageInterval(
            original_start=50,
            original_end=100,
            length=50,
            damage_type="PHYSICAL_GAP",
            reconstruction_mode="RECONSTRUCTION_DETERMINISTIC",
            expected_reconstructed_bytes_b64=base64.b64encode(b"B" * 50).decode("ascii"),
        )
    ]
    art = _create_test_artifact(payload=full_payload, evidence_offset=50000, damage=damage)
    exp = derive_expected_recovery(art)
    assert exp.expected_status == "PARTIALLY_RECOVERED"

    # If engine incorrectly claims FULLY_RECOVERED despite reconstruction:
    bad_rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-r",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=90,
        total_input_bytes=100,
        total_verified_bytes=50,
        total_reconstructed_bytes=50,
        total_missing_bytes=0,
        recovered_payload_bytes=full_payload,
        verified_segments=[
            ObservedRecoverySegment(
                segment_id="v1",
                category="VERIFIED",
                evidence_start=50000,
                evidence_end=50050,
                original_start=0,
                original_end=50,
                recovered_start=0,
                recovered_end=50,
            )
        ],
        reconstructed_segments=[
            ObservedRecoverySegment(
                segment_id="r1",
                category="RECONSTRUCTED",
                evidence_start=50050,
                evidence_end=50100,
                original_start=50,
                original_end=100,
                recovered_start=50,
                recovered_end=100,
            )
        ],
    )

    violations = audit_false_recovery(art, bad_rec, exp)
    assert any("FALSE_FULLY_RECOVERED" in v or "INVALID_STATUS_INVARIANT" in v for v in violations)


def test_06_map_recovery_to_ground_truth_contract():
    """Requirement 6: Verify mapping mechanics across contiguous, fragmented, and damaged placements."""
    payload_a = b"First fragment of text. "
    payload_b = b"Second fragment of text."
    full_payload = payload_a + payload_b

    art = PhysicalArtifactRecord(
        artifact_id="art-two-frags",
        original_filename="two_frags.txt",
        format="txt",
        original_size_bytes=len(full_payload),
        original_sha256=hashlib.sha256(full_payload).hexdigest(),
        original_bytes_b64=base64.b64encode(full_payload).decode("ascii"),
        header_evidence_offset=1000,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=1000,
                evidence_length=len(payload_a),
                original_offset=0,
            ),
            PhysicalPlacement(
                fragment_index=1,
                evidence_offset=5000,
                evidence_length=len(payload_b),
                original_offset=len(payload_a),
            ),
        ],
    )

    rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="c-two",
        detected_format="txt",
        observed_status="FULLY_RECOVERED",
        confidence_score=100,
        total_input_bytes=len(full_payload),
        total_verified_bytes=len(full_payload),
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        recovered_payload_bytes=full_payload,
        verified_segments=[
            ObservedRecoverySegment(
                segment_id="s0",
                category="VERIFIED",
                evidence_start=1000,
                evidence_end=1000 + len(payload_a),
                recovered_start=0,
                recovered_end=len(payload_a),
            ),
            ObservedRecoverySegment(
                segment_id="s1",
                category="VERIFIED",
                evidence_start=5000,
                evidence_end=5000 + len(payload_b),
                recovered_start=len(payload_a),
                recovered_end=len(full_payload),
            ),
        ],
    )

    mapped = map_recovery_to_ground_truth(rec, art)
    assert mapped.verified_segments[0].original_start == 0
    assert mapped.verified_segments[0].original_end == len(payload_a)
    assert mapped.verified_segments[1].original_start == len(payload_a)
    assert mapped.verified_segments[1].original_end == len(full_payload)


def test_07_bifragment_oracle_separation_and_honest_reporting():
    """Requirement 7: Separate what fixture makes recoverable vs what engine recovers vs what oracle expects.

    1. When treated as deterministic ground truth (is_deterministic_recovery=True):
       - Fixture is 100% recoverable in principle (284 bytes present across 2 fragments).
       - Ground truth expects FULLY_RECOVERED.
       - Current engine returns UNRECOVERABLE.
       - Benchmark honestly reports status_match=False and report.passed=False (never softened).
    2. When treated as ambiguous layout (is_deterministic_recovery=False):
       - Uncertainty is documented via AMBIGUOUS_PHYSICAL_LAYOUT.
       - Engine returning UNRECOVERABLE confirms the engine does NOT hallucinate across noise.
    """
    raw_payload = b"Fragment A of memo content. " + b"Fragment B of memo content."
    split = len(b"Fragment A of memo content. ")
    frag_a = raw_payload[:split]
    frag_b = raw_payload[split:]

    # 1. Deterministic Ground Truth: Honest failure reporting
    art_det = PhysicalArtifactRecord(
        artifact_id="art-bifrag-det",
        original_filename="memo.txt",
        format="txt",
        original_size_bytes=len(raw_payload),
        original_sha256=hashlib.sha256(raw_payload).hexdigest(),
        original_bytes_b64=base64.b64encode(raw_payload).decode("ascii"),
        header_evidence_offset=1000,
        placements=[
            PhysicalPlacement(fragment_index=0, evidence_offset=1000, evidence_length=len(frag_a), original_offset=0),
            PhysicalPlacement(fragment_index=1, evidence_offset=5000, evidence_length=len(frag_b), original_offset=split),
        ],
        is_deterministic_recovery=True,
    )
    exp_det = derive_expected_recovery(art_det)
    assert exp_det.expected_status == "FULLY_RECOVERED"
    assert exp_det.expected_verified_bytes == len(raw_payload)

    # Engine fails to bridge 3900-byte noise gap and returns UNRECOVERABLE
    rec_engine_failed = ObservedArtifactRecoveryResult(
        observed_candidate_id="cand-bifrag",
        detected_format="txt",
        observed_status="UNRECOVERABLE",
        confidence_score=0,
        total_input_bytes=0,
        total_verified_bytes=0,
        total_reconstructed_bytes=0,
        total_missing_bytes=len(raw_payload),
        recovered_payload_bytes=b"",
    )

    metrics_det = compute_evaluation_metrics(art_det, exp_det, rec_engine_failed)
    # The benchmark must report status mismatch honestly
    assert metrics_det.expected_status == "FULLY_RECOVERED"
    assert metrics_det.observed_status == "UNRECOVERABLE"
    assert metrics_det.status_match is False

    # 2. Non-deterministic Ground Truth: Documented uncertainty
    art_ambig = art_det.model_copy(update={
        "is_deterministic_recovery": False,
        "non_deterministic_reason": "INTERLEAVED_RANDOM_NOISE_UNSTRUCTURED_TXT",
    })
    exp_ambig = derive_expected_recovery(art_ambig)
    assert exp_ambig.forensic_classification_rule == "AMBIGUOUS_PHYSICAL_LAYOUT"
    assert exp_ambig.expected_status == "UNRECOVERABLE"


def test_08_malformed_and_inverted_coordinate_bounds_rejected_by_model():
    """Requirement 8: ObservedRecoverySegment model validator rejects malformed, inverted, or empty bounds."""
    # 1. Inverted evidence bounds
    with pytest.raises(ValueError, match="evidence_end \\(50\\) must be >= evidence_start \\(100\\)"):
        ObservedRecoverySegment(
            segment_id="s-inv-e",
            category="VERIFIED",
            evidence_start=100,
            evidence_end=50,
        )

    # 2. Inverted recovered bounds
    with pytest.raises(ValueError, match="recovered_end \\(10\\) must be >= recovered_start \\(20\\)"):
        ObservedRecoverySegment(
            segment_id="s-inv-r",
            category="VERIFIED",
            recovered_start=20,
            recovered_end=10,
        )

    # 3. Negative coordinates
    with pytest.raises(ValueError, match="evidence_start must be non-negative, got -5"):
        ObservedRecoverySegment(
            segment_id="s-neg",
            category="VERIFIED",
            evidence_start=-5,
            evidence_end=10,
        )

    # 4. Empty intervals (start == end)
    with pytest.raises(ValueError, match="empty interval"):
        ObservedRecoverySegment(
            segment_id="s-empty",
            category="VERIFIED",
            evidence_start=100,
            evidence_end=100,
        )


def test_09_evaluator_defense_against_malformed_intervals_without_crashing():
    """Requirement 9: Evaluator defends against malformed intervals that bypass model validation."""
    art = _create_test_artifact(payload=b"A" * 100, evidence_offset=1000)

    # Construct segments directly using model_construct to simulate unvalidated/bypassed objects
    s_inverted = ObservedRecoverySegment.model_construct(
        segment_id="s-inv",
        category="VERIFIED",
        evidence_start=1050,
        evidence_end=1020,  # Inverted!
        recovered_start=0,
        recovered_end=30,
        original_start=None,
        original_end=None,
    )
    s_negative = ObservedRecoverySegment.model_construct(
        segment_id="s-neg",
        category="VERIFIED",
        evidence_start=-10,
        evidence_end=20,
        recovered_start=0,
        recovered_end=30,
        original_start=None,
        original_end=None,
    )
    s_empty = ObservedRecoverySegment.model_construct(
        segment_id="s-emp",
        category="VERIFIED",
        evidence_start=1020,
        evidence_end=1020,  # Empty!
        recovered_start=0,
        recovered_end=0,
        original_start=None,
        original_end=None,
    )
    s_payload_overflow = ObservedRecoverySegment.model_construct(
        segment_id="s-overflow",
        category="VERIFIED",
        evidence_start=1000,
        evidence_end=1050,
        recovered_start=0,
        recovered_end=999999,  # Extends far beyond recovered payload length!
        original_start=None,
        original_end=None,
    )
    s_preexisting_bad_orig = ObservedRecoverySegment.model_construct(
        segment_id="s-bad-orig",
        category="VERIFIED",
        evidence_start=999999,
        evidence_end=1000049,
        recovered_start=0,
        recovered_end=50,
        original_start=50,
        original_end=10,  # Inverted pre-existing original coordinates and out-of-bounds evidence!
    )
    s_repaired_from_evidence = ObservedRecoverySegment.model_construct(
        segment_id="s-repaired",
        category="VERIFIED",
        evidence_start=1000,
        evidence_end=1050,
        recovered_start=0,
        recovered_end=50,
        original_start=50,
        original_end=10,  # Inverted pre-existing original coordinates, but valid evidence coordinates!
    )

    rec = ObservedArtifactRecoveryResult.model_construct(
        observed_candidate_id="c-def",
        detected_format="txt",
        observed_status="PARTIALLY_RECOVERED",
        confidence_score=50,
        total_input_bytes=100,
        total_verified_bytes=50,
        total_reconstructed_bytes=0,
        total_missing_bytes=50,
        recovered_payload_bytes=b"A" * 50,
        verified_segments=[s_inverted, s_negative, s_empty, s_payload_overflow, s_preexisting_bad_orig, s_repaired_from_evidence],
    )

    # 1. map_recovery_to_ground_truth must not assign or trust invalid original coordinates
    mapped = map_recovery_to_ground_truth(rec, art)
    for seg in mapped.verified_segments[:5]:
        assert seg.original_start is None, f"Segment {seg.segment_id} should have original_start=None"
        assert seg.original_end is None, f"Segment {seg.segment_id} should have original_end=None"

    # The 6th segment had valid evidence bounds, so it was safely remapped from ground truth
    # rather than trusting the inverted [50, 10) fake coordinates
    assert mapped.verified_segments[5].original_start == 0
    assert mapped.verified_segments[5].original_end == 50

    # 2. audit_false_recovery must catch the malformed bounds
    exp = derive_expected_recovery(art)
    violations = audit_false_recovery(art, rec, exp)
    assert any("MALFORMED_COORDINATE_INTERVAL" in v for v in violations)

    # 3. EvaluationReport must fail
    rep = EvaluationReport(
        scenario_id="scen-def",
        evidence_buffer_id="buf-1",
        candidate_metrics=compute_evaluation_metrics.__globals__["CandidateDetectionMetrics"](
            1, 0, 0, 0, 1.0, 1.0
        ),
        relationship_accuracy=1.0,
        artifact_evaluations=[],
        forensic_violations=violations,
        expected_artifact_ids=[art.artifact_id],
        expected_artifact_count=1,
    )
    assert rep.passed is False


def test_10_partial_gap_reconstruction_unambiguous_mapping():
    """Requirement 10: Partial gap reconstruction inside an isometric inter-placement gap maps unambiguously."""
    full_payload = b"PART_A_" + (b"0123456789ABCDEFGHIJ") + b"_PART_B"
    gap_bytes = b"0123456789ABCDEFGHIJ"  # 20 bytes
    part_a = b"PART_A_"  # 7 bytes
    part_b = b"_PART_B"  # 7 bytes
    total_len = len(full_payload)  # 34 bytes

    art = PhysicalArtifactRecord(
        artifact_id="art-gap-partial",
        original_filename="gap_partial.txt",
        format="txt",
        original_size_bytes=total_len,
        original_sha256=hashlib.sha256(full_payload).hexdigest(),
        original_bytes_b64=base64.b64encode(full_payload).decode("ascii"),
        header_evidence_offset=1000,
        placements=[
            PhysicalPlacement(fragment_index=0, evidence_offset=1000, evidence_length=len(part_a), original_offset=0),
            PhysicalPlacement(fragment_index=1, evidence_offset=1027, evidence_length=len(part_b), original_offset=27),
        ],
        damage_intervals=[
            PhysicalDamageInterval(
                original_start=7,
                original_end=27,
                length=20,
                damage_type="PHYSICAL_GAP",
                reconstruction_mode="RECONSTRUCTION_DETERMINISTIC",
                expected_reconstructed_bytes_b64=base64.b64encode(gap_bytes).decode("ascii"),
            )
        ],
    )

    # Check that evidence gap is isometric: 1027 - (1000 + 7) = 20, matches original_gap 27 - 7 = 20
    exp = derive_expected_recovery(art)
    assert exp.expected_status == "PARTIALLY_RECOVERED"

    # Suppose engine reconstructs a sub-slice of 10 bytes: from evidence offset 1012 to 1022
    # In the gap [1007, 1027), offset 1012 has delta = 1012 - 1007 = 5.
    # Therefore original span is [7 + 5, 7 + 5 + 10) = [12, 22)
    # Expected sub-slice is gap_bytes[5:15] = b"56789ABCDE"
    sub_reconstructed_bytes = gap_bytes[5:15]

    rec = ObservedArtifactRecoveryResult(
        observed_candidate_id="c-gap",
        detected_format="txt",
        observed_status="PARTIALLY_RECOVERED",
        confidence_score=75,
        total_input_bytes=len(part_a) + len(part_b),
        total_verified_bytes=len(part_a) + len(part_b),
        total_reconstructed_bytes=10,
        total_missing_bytes=10,
        recovered_payload_bytes=part_a + sub_reconstructed_bytes + part_b,
        verified_segments=[
            ObservedRecoverySegment(
                segment_id="v0",
                category="VERIFIED",
                evidence_start=1000,
                evidence_end=1007,
                recovered_start=0,
                recovered_end=7,
            ),
            ObservedRecoverySegment(
                segment_id="v1",
                category="VERIFIED",
                evidence_start=1027,
                evidence_end=1034,
                recovered_start=17,
                recovered_end=24,
            ),
        ],
        reconstructed_segments=[
            ObservedRecoverySegment(
                segment_id="r0",
                category="RECONSTRUCTED",
                evidence_start=1012,
                evidence_end=1022,
                recovered_start=7,
                recovered_end=17,
            )
        ],
    )

    mapped = map_recovery_to_ground_truth(rec, art)
    r_seg = mapped.reconstructed_segments[0]
    # Verify exact unambiguous original coordinates
    assert r_seg.original_start == 12
    assert r_seg.original_end == 22

    # Verify metrics evaluate correctly
    metrics = compute_evaluation_metrics(art, exp, mapped)
    violations = audit_false_recovery(art, mapped, exp)

    assert metrics.r_byte_correctness == 1.0
    assert len(violations) == 0


def test_11_partial_gap_reconstruction_ambiguous_or_invalid_boundaries_remain_unknown():
    """Requirement 11: Non-isometric gaps or boundary-crossing segments remain unknown and do not map."""
    full_payload = b"PART_A_" + (b"0123456789ABCDEFGHIJ") + b"_PART_B"
    gap_bytes = b"0123456789ABCDEFGHIJ"
    part_a = b"PART_A_"
    part_b = b"_PART_B"

    # Non-isometric gap: evidence distance is 500 bytes (e.g. noise filler), while original gap is 20 bytes
    art_non_isometric = PhysicalArtifactRecord(
        artifact_id="art-non-iso",
        original_filename="non_iso.txt",
        format="txt",
        original_size_bytes=len(full_payload),
        original_sha256=hashlib.sha256(full_payload).hexdigest(),
        original_bytes_b64=base64.b64encode(full_payload).decode("ascii"),
        header_evidence_offset=1000,
        placements=[
            PhysicalPlacement(fragment_index=0, evidence_offset=1000, evidence_length=len(part_a), original_offset=0),
            PhysicalPlacement(fragment_index=1, evidence_offset=1507, evidence_length=len(part_b), original_offset=27),
        ],
        damage_intervals=[
            PhysicalDamageInterval(
                original_start=7,
                original_end=27,
                length=20,
                damage_type="PHYSICAL_GAP",
                reconstruction_mode="RECONSTRUCTION_DETERMINISTIC",
                expected_reconstructed_bytes_b64=base64.b64encode(gap_bytes).decode("ascii"),
            )
        ],
    )

    rec_ambiguous = ObservedArtifactRecoveryResult(
        observed_candidate_id="c-ambig",
        detected_format="txt",
        observed_status="PARTIALLY_RECOVERED",
        confidence_score=70,
        total_input_bytes=14,
        total_verified_bytes=14,
        total_reconstructed_bytes=10,
        total_missing_bytes=10,
        recovered_payload_bytes=part_a + gap_bytes[:10] + part_b,
        reconstructed_segments=[
            # Segment positioned somewhere in the 500-byte noise gap
            ObservedRecoverySegment(
                segment_id="r-ambig",
                category="RECONSTRUCTED",
                evidence_start=1200,
                evidence_end=1210,
                recovered_start=7,
                recovered_end=17,
            )
        ],
    )

    mapped_ambig = map_recovery_to_ground_truth(rec_ambiguous, art_non_isometric)
    # Because evidence gap (500) != original gap (20), mapping is ambiguous and coordinates MUST remain None
    assert mapped_ambig.reconstructed_segments[0].original_start is None
    assert mapped_ambig.reconstructed_segments[0].original_end is None

    # Boundary-crossing segment: starts in placement 0 and extends into gap
    art_isometric = PhysicalArtifactRecord(
        artifact_id="art-iso",
        original_filename="iso.txt",
        format="txt",
        original_size_bytes=len(full_payload),
        original_sha256=hashlib.sha256(full_payload).hexdigest(),
        original_bytes_b64=base64.b64encode(full_payload).decode("ascii"),
        header_evidence_offset=1000,
        placements=[
            PhysicalPlacement(fragment_index=0, evidence_offset=1000, evidence_length=len(part_a), original_offset=0),
            PhysicalPlacement(fragment_index=1, evidence_offset=1027, evidence_length=len(part_b), original_offset=27),
        ],
        damage_intervals=[
            PhysicalDamageInterval(
                original_start=7,
                original_end=27,
                length=20,
                damage_type="PHYSICAL_GAP",
                reconstruction_mode="RECONSTRUCTION_DETERMINISTIC",
                expected_reconstructed_bytes_b64=base64.b64encode(gap_bytes).decode("ascii"),
            )
        ],
    )

    rec_boundary_cross = ObservedArtifactRecoveryResult(
        observed_candidate_id="c-cross",
        detected_format="txt",
        observed_status="PARTIALLY_RECOVERED",
        confidence_score=70,
        total_input_bytes=14,
        total_verified_bytes=14,
        total_reconstructed_bytes=10,
        total_missing_bytes=10,
        recovered_payload_bytes=part_a + gap_bytes[:10] + part_b,
        reconstructed_segments=[
            # Segment crosses from 1005 (inside placement 0) to 1015 (inside gap)
            ObservedRecoverySegment(
                segment_id="r-cross",
                category="RECONSTRUCTED",
                evidence_start=1005,
                evidence_end=1015,
                recovered_start=7,
                recovered_end=17,
            )
        ],
    )

    mapped_cross = map_recovery_to_ground_truth(rec_boundary_cross, art_isometric)
    # Crossing placement boundary cannot be mapped
    assert mapped_cross.reconstructed_segments[0].original_start is None
    assert mapped_cross.reconstructed_segments[0].original_end is None

    # Divergent deterministic repair in sub-interval:
    wrong_sub_bytes = b"XXXXXXXXXX"
    rec_wrong_repair = ObservedArtifactRecoveryResult(
        observed_candidate_id="c-wrong",
        detected_format="txt",
        observed_status="PARTIALLY_RECOVERED",
        confidence_score=70,
        total_input_bytes=14,
        total_verified_bytes=14,
        total_reconstructed_bytes=10,
        total_missing_bytes=10,
        recovered_payload_bytes=part_a + wrong_sub_bytes + part_b,
        reconstructed_segments=[
            ObservedRecoverySegment(
                segment_id="r-wrong",
                category="RECONSTRUCTED",
                evidence_start=1012,
                evidence_end=1022,
                recovered_start=7,
                recovered_end=17,
            )
        ],
    )
    mapped_wrong = map_recovery_to_ground_truth(rec_wrong_repair, art_isometric)
    exp = derive_expected_recovery(art_isometric)
    violations = audit_false_recovery(art_isometric, mapped_wrong, exp)
    assert any("FALSE_RECONSTRUCTED_BYTES" in v for v in violations)


