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
    orig_bytes = artifact.original_bytes
    payload_bytes = recovery.recovered_payload_bytes
    for seg in recovery.verified_segments:
        if (
            seg.recovered_start is not None
            and seg.recovered_end is not None
            and seg.original_start is not None
            and seg.original_end is not None
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
                if seg.original_start == d.original_start and seg.original_end == d.original_end:
                    actual_r_b = payload_bytes[seg.recovered_start : seg.recovered_end]
                    if actual_r_b != expected_r_b:
                        violations.append(
                            f"Benchmark finding: FALSE_RECONSTRUCTED_BYTES — Reconstructed bytes in segment {seg.segment_id} "
                            f"diverge from expected deterministic repair: {actual_r_b!r} != {expected_r_b!r}"
                        )
                        break

    return violations


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
        if self.expected_artifact_ids:
            if set(evaluated_ids) != set(self.expected_artifact_ids):
                return False
            if len(evaluated_ids) != len(self.expected_artifact_ids):
                return False
        elif self.expected_artifact_count > 0:
            if len(set(evaluated_ids)) != self.expected_artifact_count or len(evaluated_ids) != self.expected_artifact_count:
                return False
        elif not self.artifact_evaluations:
            return self.expected_artifact_count == 0 and len(self.forensic_violations) == 0

        return (
            len(self.forensic_violations) == 0
            and not self.has_false_fully_recovered
            and len(self.artifact_evaluations) > 0
            and all(ae.status_match for ae in self.artifact_evaluations)
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
        elif len(gt_manifest.artifacts) == 1 and len(observed_manifest.recoveries) == 1:
            art = gt_manifest.artifacts[0]

        if art is not None:
            expectation = derive_expected_recovery(art)
            metrics = compute_evaluation_metrics(art, expectation, rec)
            violations = audit_false_recovery(art, rec, expectation)

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
