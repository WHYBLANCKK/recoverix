"""benchmark/evaluator.py — Coordinate-Aware Benchmark Evaluator & False-Recovery Auditor.

Evaluates observed recovery runs against physical ground truth manifests:
- Enforces strict original-space coordinate evaluation
- Audits zero-tolerance false-recovery forensic invariants
- Emits structured EvaluationReport
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from benchmark.expectations import DerivedExpectation, derive_expected_recovery
from benchmark.matcher import (
    CandidateMatch,
    MatchingResult,
    match_candidates_one_to_one,
)
from benchmark.metrics import (
    CandidateDetectionMetrics,
    EvaluationMetrics,
    compute_candidate_metrics,
    compute_evaluation_metrics,
    compute_relationship_accuracy,
    is_valid_half_open_interval,
)
from benchmark.models import (
    BenchmarkGroundTruthManifest,
    BenchmarkObservedManifest,
    ObservedArtifactRecoveryResult,
    PhysicalArtifactRecord,
)


def audit_false_recovery(
    artifact: PhysicalArtifactRecord,
    recovery: ObservedArtifactRecoveryResult,
    expectation: DerivedExpectation,
) -> List[str]:
    """Audit strict forensic rules for false-recovery violations.

    Rules:
      1. Damaged or incomplete artifact cannot be FULLY_RECOVERED.
      2. Reconstructed (R > 0) or Missing (M > 0) cannot be FULLY_RECOVERED.
      3. Physical gaps in ground truth cannot disappear from missing accounting.
      4. Total verified bytes cannot exceed physically surviving evidence bytes.
      5. Bytes claimed in verified segments must match original bytes at original coordinates.
      6. Unrecoverable scenario archetype must be declared UNRECOVERABLE.
    """
    violations: List[str] = []

    is_damaged = (
        len(artifact.damage_intervals) > 0
        or artifact.is_unrecoverable
        or expectation.expected_missing_bytes > 0
        or expectation.expected_reconstructed_bytes > 0
    )
    has_unrepaired_gap = any(
        d.damage_type == "PHYSICAL_GAP" and d.reconstruction_mode != "RECONSTRUCTION_DETERMINISTIC"
        for d in artifact.damage_intervals
    ) or (expectation.expected_missing_bytes > 0)

    # Rule 0: Malformed coordinate intervals cannot be treated as valid segments
    orig_bytes = artifact.original_bytes
    payload_bytes = recovery.recovered_payload_bytes

    for seg in recovery.verified_segments:
        if seg.evidence_start is not None or seg.evidence_end is not None:
            if not is_valid_half_open_interval(seg.evidence_start, seg.evidence_end):
                violations.append(
                    f"Benchmark finding: MALFORMED_COORDINATE_INTERVAL — Verified segment {seg.segment_id} "
                    f"has invalid evidence bounds [{seg.evidence_start}, {seg.evidence_end})"
                )
                break
        if seg.recovered_start is not None or seg.recovered_end is not None:
            if not is_valid_half_open_interval(seg.recovered_start, seg.recovered_end, max_bound=len(payload_bytes)):
                violations.append(
                    f"Benchmark finding: MALFORMED_COORDINATE_INTERVAL — Verified segment {seg.segment_id} "
                    f"has invalid recovered bounds [{seg.recovered_start}, {seg.recovered_end}) "
                    f"for payload length {len(payload_bytes)}"
                )
                break
        if seg.original_start is not None or seg.original_end is not None:
            if not is_valid_half_open_interval(seg.original_start, seg.original_end, max_bound=artifact.original_size_bytes):
                violations.append(
                    f"Benchmark finding: MALFORMED_COORDINATE_INTERVAL — Verified segment {seg.segment_id} "
                    f"has invalid original bounds [{seg.original_start}, {seg.original_end}) "
                    f"for original size {artifact.original_size_bytes}"
                )
                break
            if seg.recovered_start is not None and seg.recovered_end is not None:
                r_len = seg.recovered_end - seg.recovered_start
                o_len = seg.original_end - seg.original_start
                if r_len != o_len:
                    violations.append(
                        f"Benchmark finding: MALFORMED_COORDINATE_INTERVAL — Verified segment {seg.segment_id} "
                        f"length mismatch: recovered {r_len} != original {o_len}"
                    )
                    break

    # Rule 1: Damaged artifact cannot be FULLY_RECOVERED
    if is_damaged and recovery.observed_status == "FULLY_RECOVERED":
        violations.append("Benchmark finding: FALSE_FULLY_RECOVERED — Ground-truth damaged artifact reported as FULLY_RECOVERED")

    # Rule 2: R > 0 or M > 0 cannot be FULLY_RECOVERED
    if (recovery.total_reconstructed_bytes > 0 or recovery.total_missing_bytes > 0) and recovery.observed_status == "FULLY_RECOVERED":
        violations.append("Benchmark finding: INVALID_STATUS_INVARIANT — FULLY_RECOVERED claimed with R > 0 or M > 0")

    # Rule 3: Physical gaps cannot disappear from missing accounting
    if has_unrepaired_gap and recovery.total_missing_bytes == 0:
        violations.append(
            f"Benchmark finding: UNACCOUNTED_GAP — Physical gap present in ground truth "
            f"({expectation.expected_missing_bytes} bytes), but observed missing_bytes == 0"
        )

    # Rule 4: Total verified bytes cannot exceed physically surviving evidence bytes
    surviving_evidence_bytes = sum(p.evidence_length for p in artifact.placements)
    if recovery.total_verified_bytes > surviving_evidence_bytes:
        violations.append(
            f"Benchmark finding: OVERSTATED_VERIFICATION — Observed verified bytes ({recovery.total_verified_bytes}) "
            f"> surviving evidence bytes ({surviving_evidence_bytes})"
        )

    # Rule 5: Byte divergence in verified segments using original coordinates
    for seg in recovery.verified_segments:
        if (
            is_valid_half_open_interval(seg.recovered_start, seg.recovered_end, max_bound=len(payload_bytes))
            and is_valid_half_open_interval(seg.original_start, seg.original_end, max_bound=len(orig_bytes))
            and (seg.recovered_end - seg.recovered_start) == (seg.original_end - seg.original_start)
        ):
            payload_slice = payload_bytes[seg.recovered_start : seg.recovered_end]
            orig_slice = orig_bytes[seg.original_start : seg.original_end]
            if payload_slice != orig_slice:
                violations.append(
                    f"Benchmark finding: FALSE_VERIFIED_BYTES — Divergence in segment {seg.segment_id}: "
                    f"payload[{seg.recovered_start}:{seg.recovered_end}] != "
                    f"original[{seg.original_start}:{seg.original_end}]"
                )
                break

    # Rule 6: Unrecoverable scenario archetype must be declared UNRECOVERABLE
    if artifact.is_unrecoverable and recovery.observed_status != "UNRECOVERABLE":
        violations.append(
            f"Benchmark finding: UNRECOVERABLE_MISCLASSIFIED — Ground-truth unrecoverable scenario reported as {recovery.observed_status}"
        )

    # Rule 7: Reconstructed byte divergence when deterministic repair is expected
    import base64
    for d in artifact.damage_intervals:
        if d.reconstruction_mode == "RECONSTRUCTION_DETERMINISTIC" and d.expected_reconstructed_bytes_b64:
            expected_r_b = base64.b64decode(d.expected_reconstructed_bytes_b64)
            for seg in recovery.reconstructed_segments:
                if (
                    is_valid_half_open_interval(seg.original_start, seg.original_end, max_bound=artifact.original_size_bytes)
                    and is_valid_half_open_interval(seg.recovered_start, seg.recovered_end, max_bound=len(payload_bytes))
                ):
                    if d.original_start <= seg.original_start < seg.original_end <= d.original_end:
                        sub_s = seg.original_start - d.original_start
                        sub_e = seg.original_end - d.original_start
                        exp_slice = expected_r_b[sub_s:sub_e]
                        actual_r_b = payload_bytes[seg.recovered_start : seg.recovered_end]
                        if actual_r_b != exp_slice:
                            violations.append(
                                f"Benchmark finding: FALSE_RECONSTRUCTED_BYTES — Reconstructed bytes in segment {seg.segment_id} "
                                f"diverge from expected deterministic repair: {actual_r_b!r} != {exp_slice!r}"
                            )
                            break

    # Rule 8: Exact payload match required when observed status is FULLY_RECOVERED
    if recovery.observed_status == "FULLY_RECOVERED":
        if recovery.recovered_payload_bytes:
            import hashlib
            computed_sha = hashlib.sha256(recovery.recovered_payload_bytes).hexdigest().lower()
            if computed_sha != artifact.original_sha256.lower():
                violations.append(
                    f"Benchmark finding: FALSE_FULLY_RECOVERED_HASH_MISMATCH — Observed status FULLY_RECOVERED "
                    f"but recovered payload SHA-256 does not match original ground truth ({computed_sha[:16]}... != {artifact.original_sha256[:16]}...)"
                )
        elif artifact.original_size_bytes > 0:
            violations.append(
                "Benchmark finding: FALSE_FULLY_RECOVERED_EMPTY_PAYLOAD — Observed status FULLY_RECOVERED "
                "but no recovered payload bytes produced"
            )

    return violations


def map_recovery_to_ground_truth(
    recovery: ObservedArtifactRecoveryResult,
    artifact: PhysicalArtifactRecord,
) -> ObservedArtifactRecoveryResult:
    """Map observed recovery segments to ground-truth original coordinates using physical placements.

    Derives original coordinates strictly from known physical placements and damage intervals.
    Never infers original coordinates from recovery output or candidate IDs.
    Unknown coordinates remain None.
    """
    payload_len = len(recovery.recovered_payload_bytes)

    # 1. Map verified segments
    mapped_v_segs: List[ObservedRecoverySegment] = []
    for seg in recovery.verified_segments:
        # Check pre-existing original coordinates defensively
        if seg.original_start is not None and seg.original_end is not None:
            if (
                is_valid_half_open_interval(seg.original_start, seg.original_end, max_bound=artifact.original_size_bytes)
                and (
                    seg.recovered_start is None
                    or (
                        is_valid_half_open_interval(seg.recovered_start, seg.recovered_end, max_bound=payload_len)
                        and (seg.recovered_end - seg.recovered_start == seg.original_end - seg.original_start)
                    )
                )
            ):
                mapped_v_segs.append(seg)
                continue
            # Strip invalid pre-existing original coordinates
            seg = seg.model_copy(update={"original_start": None, "original_end": None})

        orig_s: Optional[int] = None
        orig_e: Optional[int] = None

        if is_valid_half_open_interval(seg.evidence_start, seg.evidence_end):
            e_s = seg.evidence_start
            e_e = seg.evidence_end
            e_len = e_e - e_s

            r_ok = True
            if seg.recovered_start is not None or seg.recovered_end is not None:
                if (
                    not is_valid_half_open_interval(seg.recovered_start, seg.recovered_end, max_bound=payload_len)
                    or (seg.recovered_end - seg.recovered_start) != e_len
                ):
                    r_ok = False

            if r_ok:
                candidate_mappings = []
                for p in artifact.placements:
                    if p.evidence_offset <= e_s and e_e <= (p.evidence_offset + p.evidence_length):
                        delta = e_s - p.evidence_offset
                        cand_s = p.original_offset + delta
                        cand_e = cand_s + e_len
                        if is_valid_half_open_interval(cand_s, cand_e, max_bound=artifact.original_size_bytes):
                            candidate_mappings.append((cand_s, cand_e))

                if len(candidate_mappings) == 1:
                    orig_s, orig_e = candidate_mappings[0]

        if orig_s is not None and orig_e is not None:
            mapped_v_segs.append(
                seg.model_copy(update={"original_start": orig_s, "original_end": orig_e})
            )
        else:
            mapped_v_segs.append(seg)

    # 2. Map reconstructed segments
    mapped_r_segs: List[ObservedRecoverySegment] = []
    for seg in recovery.reconstructed_segments:
        # Check pre-existing original coordinates defensively
        if seg.original_start is not None and seg.original_end is not None:
            if (
                is_valid_half_open_interval(seg.original_start, seg.original_end, max_bound=artifact.original_size_bytes)
                and (
                    seg.recovered_start is None
                    or (
                        is_valid_half_open_interval(seg.recovered_start, seg.recovered_end, max_bound=payload_len)
                        and (seg.recovered_end - seg.recovered_start == seg.original_end - seg.original_start)
                    )
                )
            ):
                mapped_r_segs.append(seg)
                continue
            seg = seg.model_copy(update={"original_start": None, "original_end": None})

        orig_s = None
        orig_e = None

        if is_valid_half_open_interval(seg.evidence_start, seg.evidence_end):
            e_s = seg.evidence_start
            e_e = seg.evidence_end
            e_len = e_e - e_s

            r_ok = True
            if seg.recovered_start is not None or seg.recovered_end is not None:
                if (
                    not is_valid_half_open_interval(seg.recovered_start, seg.recovered_end, max_bound=payload_len)
                    or (seg.recovered_end - seg.recovered_start) != e_len
                ):
                    r_ok = False

            if r_ok:
                candidate_mappings = []

                # A. Within-placement damage
                for d in artifact.damage_intervals:
                    for p in artifact.placements:
                        if p.original_offset <= d.original_start and d.original_end <= (p.original_offset + p.evidence_length):
                            d_ev_s = p.evidence_offset + (d.original_start - p.original_offset)
                            d_ev_e = d_ev_s + d.length
                            if d_ev_s <= e_s and e_e <= d_ev_e:
                                delta = e_s - d_ev_s
                                cand_s = d.original_start + delta
                                cand_e = cand_s + e_len
                                if is_valid_half_open_interval(cand_s, cand_e, max_bound=artifact.original_size_bytes):
                                    candidate_mappings.append((cand_s, cand_e))

                # B. Inter-placement gap
                for d in artifact.damage_intervals:
                    for i in range(len(artifact.placements) - 1):
                        p_curr = artifact.placements[i]
                        p_next = artifact.placements[i + 1]
                        if (
                            d.original_start == (p_curr.original_offset + p_curr.evidence_length)
                            and d.original_end == p_next.original_offset
                        ):
                            gap_ev_s = p_curr.evidence_offset + p_curr.evidence_length
                            gap_ev_e = p_next.evidence_offset
                            ev_gap_len = gap_ev_e - gap_ev_s
                            orig_gap_len = d.original_end - d.original_start
                            # Strict isometric constraint: evidence distance between placements
                            # must be 1-to-1 with the original damage gap. If non-isometric (e.g.
                            # arbitrary noise filler), mapping is ambiguous and coordinates cannot be inferred.
                            if ev_gap_len == orig_gap_len:
                                if gap_ev_s <= e_s and e_e <= gap_ev_e:
                                    delta = e_s - gap_ev_s
                                    cand_s = d.original_start + delta
                                    cand_e = cand_s + e_len
                                    if is_valid_half_open_interval(cand_s, cand_e, max_bound=artifact.original_size_bytes):
                                        candidate_mappings.append((cand_s, cand_e))

                if len(candidate_mappings) == 1:
                    orig_s, orig_e = candidate_mappings[0]

        if orig_s is not None and orig_e is not None:
            mapped_r_segs.append(
                seg.model_copy(update={"original_start": orig_s, "original_end": orig_e})
            )
        else:
            mapped_r_segs.append(seg)

    # 3. Map missing segments
    mapped_m_segs: List[ObservedRecoverySegment] = []
    for seg in recovery.missing_segments:
        if seg.original_start is not None and seg.original_end is not None:
            if is_valid_half_open_interval(seg.original_start, seg.original_end, max_bound=artifact.original_size_bytes):
                mapped_m_segs.append(seg)
                continue
            seg = seg.model_copy(update={"original_start": None, "original_end": None})

        orig_s = None
        orig_e = None

        if is_valid_half_open_interval(seg.evidence_start, seg.evidence_end):
            e_s = seg.evidence_start
            e_e = seg.evidence_end
            e_len = e_e - e_s

            candidate_mappings = []

            for d in artifact.damage_intervals:
                for p in artifact.placements:
                    if p.original_offset <= d.original_start and d.original_end <= (p.original_offset + p.evidence_length):
                        d_ev_s = p.evidence_offset + (d.original_start - p.original_offset)
                        d_ev_e = d_ev_s + d.length
                        if d_ev_s <= e_s and e_e <= d_ev_e:
                            delta = e_s - d_ev_s
                            cand_s = d.original_start + delta
                            cand_e = cand_s + e_len
                            if is_valid_half_open_interval(cand_s, cand_e, max_bound=artifact.original_size_bytes):
                                candidate_mappings.append((cand_s, cand_e))

            for d in artifact.damage_intervals:
                for i in range(len(artifact.placements) - 1):
                    p_curr = artifact.placements[i]
                    p_next = artifact.placements[i + 1]
                    if (
                        d.original_start == (p_curr.original_offset + p_curr.evidence_length)
                        and d.original_end == p_next.original_offset
                    ):
                        gap_ev_s = p_curr.evidence_offset + p_curr.evidence_length
                        gap_ev_e = p_next.evidence_offset
                        ev_gap_len = gap_ev_e - gap_ev_s
                        orig_gap_len = d.original_end - d.original_start
                        if ev_gap_len == orig_gap_len:
                            if gap_ev_s <= e_s and e_e <= gap_ev_e:
                                delta = e_s - gap_ev_s
                                cand_s = d.original_start + delta
                                cand_e = cand_s + e_len
                                if is_valid_half_open_interval(cand_s, cand_e, max_bound=artifact.original_size_bytes):
                                    candidate_mappings.append((cand_s, cand_e))

            if len(candidate_mappings) == 1:
                orig_s, orig_e = candidate_mappings[0]

        if orig_s is not None and orig_e is not None:
            mapped_m_segs.append(
                seg.model_copy(update={"original_start": orig_s, "original_end": orig_e})
            )
        else:
            mapped_m_segs.append(seg)

    return recovery.model_copy(
        update={
            "verified_segments": mapped_v_segs,
            "reconstructed_segments": mapped_r_segs,
            "missing_segments": mapped_m_segs,
        }
    )


@dataclass(frozen=True)
class EvaluationReport:
    """Complete evaluation report for one benchmark scenario."""

    scenario_id: str
    evidence_buffer_id: str

    candidate_metrics: CandidateDetectionMetrics
    relationship_accuracy: float

    artifact_evaluations: List[EvaluationMetrics] = field(default_factory=list)
    forensic_violations: List[str] = field(default_factory=list)
    expected_artifact_ids: List[str] = field(default_factory=list)
    expected_artifact_count: int = 0

    @property
    def has_false_fully_recovered(self) -> bool:
        return any(ae.false_fully_recovered for ae in self.artifact_evaluations)

    @property
    def passed(self) -> bool:
        evaluated_ids = [ae.artifact_id for ae in self.artifact_evaluations]
        if self.expected_artifact_ids or self.expected_artifact_count == 0:
            if set(evaluated_ids) != set(self.expected_artifact_ids):
                return False
            if len(evaluated_ids) != len(self.expected_artifact_ids):
                return False
            if not self.expected_artifact_ids:
                return len(self.forensic_violations) == 0
        elif self.expected_artifact_count > 0:
            if len(set(evaluated_ids)) != self.expected_artifact_count or len(evaluated_ids) != self.expected_artifact_count:
                return False
        elif not self.artifact_evaluations:
            return self.expected_artifact_count == 0 and len(self.forensic_violations) == 0

        # Strict correctness checks for each artifact evaluation
        for ae in self.artifact_evaluations:
            if not ae.status_match:
                return False
            # Contract requires exact payload identity for FULLY_RECOVERED
            if ae.expected_status == "FULLY_RECOVERED" and ae.whole_payload_hash_match is not True:
                return False
            # If byte correctness was evaluated, must be 1.0 (no divergence in verified bytes)
            if ae.v_byte_correctness is not None and ae.v_byte_correctness < 1.0:
                return False

        return (
            len(self.forensic_violations) == 0
            and not self.has_false_fully_recovered
            and len(self.artifact_evaluations) > 0
        )


def evaluate_scenario(
    gt_manifest: BenchmarkGroundTruthManifest,
    observed_manifest: BenchmarkObservedManifest,
) -> EvaluationReport:
    """Evaluate an observed benchmark run against the physical ground-truth manifest."""
    # 1. Match candidates to ground-truth artifacts
    matching = match_candidates_one_to_one(
        gt_manifest.artifacts,
        observed_manifest.candidates,
        gt_manifest.evidence_buffer_id,
    )
    cand_metrics = compute_candidate_metrics(matching)

    # 2. Match recoveries to ground-truth artifacts
    # Build candidate_id -> artifact map from candidate matches
    cand_to_art: Dict[str, PhysicalArtifactRecord] = {
        m.candidate.candidate_id: m.artifact for m in matching.matched_pairs
    }

    artifact_evals: List[EvaluationMetrics] = []
    all_violations: List[str] = []

    for rec in observed_manifest.recoveries:
        art: Optional[PhysicalArtifactRecord] = None
        if rec.observed_candidate_id and rec.observed_candidate_id in cand_to_art:
            art = cand_to_art[rec.observed_candidate_id]
        elif (
            not rec.observed_candidate_id
            and not observed_manifest.candidates
            and len(gt_manifest.artifacts) == 1
            and len(observed_manifest.recoveries) == 1
        ):
            art = gt_manifest.artifacts[0]

        if art is not None:
            mapped_rec = map_recovery_to_ground_truth(rec, art)
            expectation = derive_expected_recovery(art)
            metrics = compute_evaluation_metrics(art, expectation, mapped_rec)
            violations = audit_false_recovery(art, mapped_rec, expectation)

            artifact_evals.append(metrics)
            all_violations.extend(violations)

    # 3. Compute spatial relationship accuracy
    rel_acc = compute_relationship_accuracy(
        gt_manifest.spatial_relationships,
        observed_manifest.observed_relationships,
    )

    return EvaluationReport(
        scenario_id=gt_manifest.scenario_id,
        evidence_buffer_id=gt_manifest.evidence_buffer_id,
        candidate_metrics=cand_metrics,
        relationship_accuracy=rel_acc,
        artifact_evaluations=artifact_evals,
        forensic_violations=all_violations,
        expected_artifact_ids=[art.artifact_id for art in gt_manifest.artifacts],
        expected_artifact_count=len(gt_manifest.artifacts),
    )
