"""benchmark/metrics.py — Foundational Forensic Metrics Calculator.

Calculates:
- Candidate detection metrics (Precision, Recall, TP, FP, FN, Duplicates)
- Volume accuracy (V, R, M counts)
- Interval IoU (V, R, M spatial coverage in original coordinates)
- Byte-level correctness (verified and reconstructed payload matching)
- Status accuracy and false FULLY_RECOVERED flags
- Zero-safe spatial relationship accuracy
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple
from benchmark.matcher import MatchingResult
from benchmark.models import (
    ObservedArtifactRecoveryResult,
    ObservedRecoverySegment,
    ObservedRelationshipRecord,
    PhysicalArtifactRecord,
    PhysicalRelationshipRecord,
)
from benchmark.expectations import DerivedExpectation

VALID_STATUSES = frozenset({
    "FULLY_RECOVERED",
    "PARTIALLY_RECOVERED",
    "CORRUPTED",
    "UNRECOVERABLE",
})


def compute_volume_ratio(observed_vol: int, expected_vol: int) -> float:
    """Compute volume accuracy ratio min(obs, exp) / max(obs, exp).

    Returns:
      1.0 if both are 0
      0.0 if one is 0 and the other > 0
      min / max ratio otherwise
    """
    if observed_vol < 0 or expected_vol < 0:
        raise ValueError("Volumes must be non-negative")
    if observed_vol == 0 and expected_vol == 0:
        return 1.0
    if observed_vol == 0 or expected_vol == 0:
        return 0.0
    return min(observed_vol, expected_vol) / max(observed_vol, expected_vol)


def is_valid_half_open_interval(
    start: Optional[int],
    end: Optional[int],
    max_bound: Optional[int] = None,
) -> bool:
    """Validate that [start, end) is a non-empty, non-inverted, non-negative half-open interval."""
    if start is None or end is None:
        return False
    if not isinstance(start, int) or not isinstance(end, int):
        return False
    if start < 0 or end <= start:
        return False
    if max_bound is not None and end > max_bound:
        return False
    return True


def _interval_union_length(intervals: Sequence[Tuple[int, int]]) -> int:
    """Compute the total covered byte count of a union of half-open intervals [s, e)."""
    if not intervals:
        return 0
    # Sort and merge
    sorted_ivs = sorted(intervals)
    merged: List[Tuple[int, int]] = []
    for s, e in sorted_ivs:
        if s >= e:
            continue
        if not merged or s > merged[-1][1]:
            merged.append((s, e))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
    return sum(e - s for s, e in merged)


def compute_interval_iou(
    intervals_a: Sequence[Tuple[int, int]],
    intervals_b: Sequence[Tuple[int, int]],
) -> float:
    """Compute Jaccard IoU between two sets of half-open intervals [s, e).

    Returns:
      1.0 if both interval sets are empty
      0.0 if one is empty and the other is non-empty
      |A ∩ B| / |A ∪ B| otherwise
    """
    len_a = _interval_union_length(intervals_a)
    len_b = _interval_union_length(intervals_b)

    if len_a == 0 and len_b == 0:
        return 1.0
    if len_a == 0 or len_b == 0:
        return 0.0

    # Compute intersection length
    inter_len = 0
    for s_a, e_a in intervals_a:
        for s_b, e_b in intervals_b:
            lo = max(s_a, s_b)
            hi = min(e_a, e_b)
            if hi > lo:
                inter_len += (hi - lo)

    union_len = len_a + len_b - inter_len
    if union_len <= 0:
        return 0.0
    return inter_len / union_len


@dataclass(frozen=True)
class CandidateDetectionMetrics:
    true_positives: int
    false_positives: int
    false_negatives: int
    duplicate_count: int
    precision: float
    recall: float


def compute_candidate_metrics(matching: MatchingResult) -> CandidateDetectionMetrics:
    """Extract candidate detection precision and recall from matching results."""
    return CandidateDetectionMetrics(
        true_positives=matching.true_positives,
        false_positives=matching.false_positives,
        false_negatives=matching.false_negatives,
        duplicate_count=len(matching.duplicate_candidates),
        precision=matching.precision,
        recall=matching.recall,
    )


@dataclass(frozen=True)
class EvaluationMetrics:
    """Comprehensive metric assessment for one evaluated artifact."""

    artifact_id: str
    format: str

    # Volume accuracy
    # Aggregate Volume Accounting (aggregate byte counts only; does not imply byte or coordinate correctness)
    v_volume_accuracy: float
    r_volume_accuracy: float
    m_volume_accuracy: float

    # Original-Space Interval IoU (Jaccard similarity in original coordinates; None if original coordinates are unavailable)
    v_interval_iou: Optional[float]
    m_interval_iou: Optional[float]
    r_interval_iou: Optional[float]

    # Original-Space Byte Correctness (payload[R_s:R_e] == original[O_s:O_e]; None if coordinates unavailable)
    v_byte_correctness: Optional[float]
    r_byte_correctness: Optional[float]  # None if no deterministic repair expected or coords not established

    # Status
    expected_status: str
    observed_status: str
    status_match: bool

    # Forensic False Recovery
    false_fully_recovered: bool

    # Whole-Payload SHA-256 Match (actual payload bytes == original ground truth bytes; None if no payload produced)
    whole_payload_hash_match: Optional[bool] = None


def compute_evaluation_metrics(
    artifact: PhysicalArtifactRecord,
    expectation: DerivedExpectation,
    recovery: ObservedArtifactRecoveryResult,
) -> EvaluationMetrics:
    """Calculate foundational metrics for one artifact recovery result."""
    # 1. Aggregate Volume Accounting (aggregate byte count comparisons only)
    v_vol_acc = compute_volume_ratio(recovery.total_verified_bytes, expectation.expected_verified_bytes)
    r_vol_acc = compute_volume_ratio(recovery.total_reconstructed_bytes, expectation.expected_reconstructed_bytes)
    m_vol_acc = compute_volume_ratio(recovery.total_missing_bytes, expectation.expected_missing_bytes)

    # 2. Original-Space Coordinate Availability
    # Original coordinates are ONLY valid if established by the recovery run.
    # If no segment defines original coordinates, original-space interval IoU and byte correctness MUST be None.
    has_any_orig = any(
        is_valid_half_open_interval(s.original_start, s.original_end, max_bound=artifact.original_size_bytes)
        for s in (recovery.verified_segments + recovery.reconstructed_segments + recovery.missing_segments)
    )

    obs_v_intervals = [
        (s.original_start, s.original_end)
        for s in recovery.verified_segments
        if is_valid_half_open_interval(s.original_start, s.original_end, max_bound=artifact.original_size_bytes)
    ]
    obs_m_intervals = [
        (s.original_start, s.original_end)
        for s in recovery.missing_segments
        if is_valid_half_open_interval(s.original_start, s.original_end, max_bound=artifact.original_size_bytes)
    ]
    obs_r_intervals = [
        (s.original_start, s.original_end)
        for s in recovery.reconstructed_segments
        if is_valid_half_open_interval(s.original_start, s.original_end, max_bound=artifact.original_size_bytes)
    ]

    if has_any_orig:
        v_iou: Optional[float] = compute_interval_iou(obs_v_intervals, expectation.expected_surviving_intervals)
        m_iou: Optional[float] = compute_interval_iou(obs_m_intervals, expectation.expected_missing_intervals)
        r_iou: Optional[float] = compute_interval_iou(obs_r_intervals, expectation.expected_reconstructed_intervals)
    else:
        v_iou = None
        m_iou = None
        r_iou = None

    # 3. Byte-level verified correctness: payload[R_s:R_e] == original[O_s:O_e]
    orig_bytes = artifact.original_bytes
    payload_bytes = recovery.recovered_payload_bytes

    total_v_bytes = 0
    correct_v_bytes = 0

    for seg in recovery.verified_segments:
        if (
            is_valid_half_open_interval(seg.recovered_start, seg.recovered_end, max_bound=len(payload_bytes))
            and is_valid_half_open_interval(seg.original_start, seg.original_end, max_bound=len(orig_bytes))
            and (seg.recovered_end - seg.recovered_start) == (seg.original_end - seg.original_start)
        ):
            seg_len = seg.recovered_end - seg.recovered_start
            total_v_bytes += seg_len

            payload_slice = payload_bytes[seg.recovered_start : seg.recovered_end]
            orig_slice = orig_bytes[seg.original_start : seg.original_end]

            correct_v_bytes += sum(1 for p_b, o_b in zip(payload_slice, orig_slice) if p_b == o_b)

    if has_any_orig:
        if total_v_bytes == 0:
            v_byte_corr: Optional[float] = 1.0 if expectation.expected_verified_bytes == 0 else 0.0
        else:
            v_byte_corr = correct_v_bytes / total_v_bytes
    else:
        v_byte_corr = None

    # 4. Byte-level reconstructed correctness
    r_byte_corr: Optional[float] = None
    expected_r_bytes_map: Dict[Tuple[int, int], bytes] = {}
    for d in artifact.damage_intervals:
        if d.reconstruction_mode == "RECONSTRUCTION_DETERMINISTIC" and d.expected_reconstructed_bytes_b64:
            import base64
            expected_r_bytes_map[(d.original_start, d.original_end)] = base64.b64decode(
                d.expected_reconstructed_bytes_b64
            )

    if expected_r_bytes_map:
        if has_any_orig:
            total_r_eval_bytes = 0
            correct_r_eval_bytes = 0
            for seg in recovery.reconstructed_segments:
                if (
                    is_valid_half_open_interval(seg.original_start, seg.original_end, max_bound=artifact.original_size_bytes)
                    and is_valid_half_open_interval(seg.recovered_start, seg.recovered_end, max_bound=len(payload_bytes))
                ):
                    for (d_s, d_e), exp_b in expected_r_bytes_map.items():
                        if d_s <= seg.original_start < seg.original_end <= d_e:
                            sub_s = seg.original_start - d_s
                            sub_e = seg.original_end - d_s
                            expected_b = exp_b[sub_s:sub_e]
                            actual_b = payload_bytes[seg.recovered_start : seg.recovered_end]
                            total_r_eval_bytes += max(len(expected_b), len(actual_b))
                            correct_r_eval_bytes += sum(1 for a, b in zip(actual_b, expected_b) if a == b)
                            break
            r_byte_corr = (correct_r_eval_bytes / total_r_eval_bytes) if total_r_eval_bytes > 0 else 0.0
        else:
            r_byte_corr = None

    # 5. Status match
    status_match = bool(
        recovery.observed_status in VALID_STATUSES
        and expectation.expected_status in VALID_STATUSES
        and recovery.observed_status == expectation.expected_status
    )

    # 6. False FULLY_RECOVERED detection
    is_damaged = (
        len(artifact.damage_intervals) > 0
        or artifact.is_unrecoverable
        or expectation.expected_missing_bytes > 0
        or expectation.expected_reconstructed_bytes > 0
    )
    false_full = (
        (is_damaged and recovery.observed_status == "FULLY_RECOVERED")
        or ((recovery.total_reconstructed_bytes > 0 or recovery.total_missing_bytes > 0) and recovery.observed_status == "FULLY_RECOVERED")
    )

    # 7. Whole-payload SHA-256 hash match against ground-truth original bytes
    # Computed strictly from actual recovered payload bytes vs original ground-truth bytes.
    # Never inferred from V/R/M byte counts, candidate ID, or recovery status.
    whole_payload_hash_match: Optional[bool]
    if recovery.recovered_payload_bytes:
        import hashlib
        computed_sha = hashlib.sha256(recovery.recovered_payload_bytes).hexdigest().lower()
        whole_payload_hash_match = (computed_sha == artifact.original_sha256.lower())
    elif artifact.original_size_bytes == 0 and recovery.recovered_payload_bytes == b"":
        whole_payload_hash_match = True
    else:
        whole_payload_hash_match = None

    return EvaluationMetrics(
        artifact_id=artifact.artifact_id,
        format=artifact.format,
        v_volume_accuracy=v_vol_acc,
        r_volume_accuracy=r_vol_acc,
        m_volume_accuracy=m_vol_acc,
        v_interval_iou=v_iou,
        m_interval_iou=m_iou,
        r_interval_iou=r_iou,
        v_byte_correctness=v_byte_corr,
        r_byte_correctness=r_byte_corr,
        expected_status=expectation.expected_status,
        observed_status=recovery.observed_status,
        status_match=status_match,
        false_fully_recovered=false_full,
        whole_payload_hash_match=whole_payload_hash_match,
    )


def compute_relationship_accuracy(
    gt_relationships: Sequence[PhysicalRelationshipRecord],
    observed_relationships: Sequence[ObservedRelationshipRecord],
) -> float:
    """Compute directional relationship accuracy handling the zero-case deterministically.

    Rules:
      - 0 GT relationships and 0 observed -> 1.0 (perfect true negative)
      - 0 GT relationships and >0 observed -> 0.0 (false positives)
      - >0 GT relationships -> TP / (Total GT + FP)
    """
    n_gt = len(gt_relationships)
    n_obs = len(observed_relationships)

    if n_gt == 0:
        return 1.0 if n_obs == 0 else 0.0

    # Match directional edges: (evidence_buffer_id, source, target, type)
    gt_set = {
        (r.evidence_buffer_id, r.source_artifact_id, r.target_artifact_id, r.relationship_type)
        for r in gt_relationships
    }
    obs_set = {
        (r.evidence_buffer_id, r.source_candidate_id, r.target_candidate_id, r.relationship_type)
        for r in observed_relationships
    }

    tp = len(gt_set.intersection(obs_set))
    fp = n_obs - tp
    denom = n_gt + fp
    return (tp / denom) if denom > 0 else 0.0
