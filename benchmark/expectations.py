"""benchmark/expectations.py — Decoupled Forensic Expectation Oracle.

Derives deterministic forensic expectations (V/R/M byte budgets and expected status)
from physical ground-truth manifests without accessing recovery code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal, Sequence, Tuple
from benchmark.models import PhysicalArtifactRecord, PhysicalDamageInterval


ExpectedStatus = Literal[
    "FULLY_RECOVERED",
    "PARTIALLY_RECOVERED",
    "CORRUPTED",
    "UNRECOVERABLE",
]


@dataclass(frozen=True)
class DerivedExpectation:
    """Forensic expectations deterministically derived from physical ground truth."""

    artifact_id: str
    expected_status: ExpectedStatus
    expected_verified_bytes: int
    expected_reconstructed_bytes: int
    expected_missing_bytes: int

    # Expected intervals in original artifact coordinates [start, end)
    expected_surviving_intervals: List[Tuple[int, int]] = field(default_factory=list)
    expected_missing_intervals: List[Tuple[int, int]] = field(default_factory=list)
    expected_reconstructed_intervals: List[Tuple[int, int]] = field(default_factory=list)
    expected_corrupted_intervals: List[Tuple[int, int]] = field(default_factory=list)

    forensic_classification_rule: str = ""


def subtract_damage_intervals(
    placements: Sequence[Tuple[int, int]],
    damage_spans: Sequence[Tuple[int, int]],
    max_bound: int,
) -> List[Tuple[int, int]]:
    """Compute surviving half-open intervals by subtracting damage spans from placements.

    surviving_intervals = placement_intervals minus union(damage_intervals)

    Enforces:
      - Valid half-open interval endpoints: 0 <= start < end <= max_bound
      - Merged/normalized damage intervals (handling overlaps, adjacent spans, and nesting)
      - Explicit handling of zero-length or inverted intervals
      - Canonical sorted, disjoint surviving subintervals
    """
    if max_bound <= 0:
        return []

    # 1. Validate, clamp, and filter damage spans
    valid_dmg: List[Tuple[int, int]] = []
    for s, e in damage_spans:
        if isinstance(s, int) and isinstance(e, int) and s < e and e > 0 and s < max_bound:
            clamped_s = max(0, s)
            clamped_e = min(max_bound, e)
            if clamped_s < clamped_e:
                valid_dmg.append((clamped_s, clamped_e))
    valid_dmg.sort()

    # 2. Merge overlapping or adjacent damage intervals
    merged_dmg: List[Tuple[int, int]] = []
    for s, e in valid_dmg:
        if not merged_dmg:
            merged_dmg.append((s, e))
        elif s <= merged_dmg[-1][1]:
            merged_dmg[-1] = (merged_dmg[-1][0], max(merged_dmg[-1][1], e))
        else:
            merged_dmg.append((s, e))

    # 3. For each placement interval, subtract merged damage spans
    surviving: List[Tuple[int, int]] = []
    for p_s, p_e in placements:
        if not (isinstance(p_s, int) and isinstance(p_e, int) and p_s < p_e and p_e > 0 and p_s < max_bound):
            continue
        clamped_p_s = max(0, p_s)
        clamped_p_e = min(max_bound, p_e)
        if clamped_p_s >= clamped_p_e:
            continue

        curr = clamped_p_s
        for d_s, d_e in merged_dmg:
            if d_e <= curr:
                continue
            if d_s >= clamped_p_e:
                break
            if d_s > curr:
                surviving.append((curr, min(d_s, clamped_p_e)))
            curr = max(curr, d_e)
            if curr >= clamped_p_e:
                break
        if curr < clamped_p_e:
            surviving.append((curr, clamped_p_e))

    # 4. Sort and merge surviving intervals
    surviving.sort()
    final_surviving: List[Tuple[int, int]] = []
    for s, e in surviving:
        if not final_surviving:
            final_surviving.append((s, e))
        elif s <= final_surviving[-1][1]:
            final_surviving[-1] = (final_surviving[-1][0], max(final_surviving[-1][1], e))
        else:
            final_surviving.append((s, e))

    return final_surviving


def derive_expected_recovery(artifact: PhysicalArtifactRecord) -> DerivedExpectation:
    """Derive deterministic recovery budgets and expected status from physical ground truth.

    Implements the approved deterministic status truth table:
      1. INTACT                  -> FULLY_RECOVERED
      2. PHYSICAL_GAP_UNREPAIRED -> PARTIALLY_RECOVERED
      3. DETERMINISTIC_REPAIR    -> PARTIALLY_RECOVERED
      4. UNREPAIRABLE_CORRUPTION -> CORRUPTED
      5. UNRECOVERABLE           -> UNRECOVERABLE

    Invariant: If R > 0 or M > 0, expected_status CANNOT be FULLY_RECOVERED.
    """
    orig_size = artifact.original_size_bytes

    # 1. Check explicit ground-truth unrecoverable scenario archetype
    if artifact.is_unrecoverable:
        return DerivedExpectation(
            artifact_id=artifact.artifact_id,
            expected_status="UNRECOVERABLE",
            expected_verified_bytes=0,
            expected_reconstructed_bytes=0,
            expected_missing_bytes=orig_size,
            expected_surviving_intervals=[],
            expected_missing_intervals=[(0, orig_size)],
            expected_reconstructed_intervals=[],
            expected_corrupted_intervals=[],
            forensic_classification_rule="UNRECOVERABLE_ARCHETYPE",
        )

    # 2. Partition damage intervals by physical nature and reconstruction mode
    missing_intervals: List[Tuple[int, int]] = []
    reconstructed_intervals: List[Tuple[int, int]] = []
    corrupted_intervals: List[Tuple[int, int]] = []

    has_gap_unrepaired = False
    has_deterministic_repair = False
    has_unrepairable_corruption = False

    for d in artifact.damage_intervals:
        span = (d.original_start, d.original_end)
        if d.reconstruction_mode == "RECONSTRUCTION_DETERMINISTIC":
            reconstructed_intervals.append(span)
            has_deterministic_repair = True
        elif d.damage_type == "PHYSICAL_GAP":
            missing_intervals.append(span)
            has_gap_unrepaired = True
        elif d.damage_type in ("ZERO_FILL", "RANDOM_OVERWRITE", "BIT_FLIP"):
            corrupted_intervals.append(span)
            has_unrepairable_corruption = True
        else:
            missing_intervals.append(span)

    # 3. Calculate surviving (verified) intervals from placements excluding damage spans
    placement_spans = [(p.original_offset, p.original_offset + p.evidence_length) for p in artifact.placements]
    all_damage_spans = missing_intervals + corrupted_intervals + reconstructed_intervals
    surviving_intervals = subtract_damage_intervals(placement_spans, all_damage_spans, max_bound=orig_size)

    total_missing = sum(end - start for start, end in missing_intervals)
    total_reconstructed = sum(end - start for start, end in reconstructed_intervals)
    total_corrupted = sum(end - start for start, end in corrupted_intervals)
    total_verified = sum(end - start for start, end in surviving_intervals)

    # 4. Apply Mutually Exclusive Status Truth Table
    if not artifact.is_deterministic_recovery:
        return DerivedExpectation(
            artifact_id=artifact.artifact_id,
            expected_status="UNRECOVERABLE",
            expected_verified_bytes=0,
            expected_reconstructed_bytes=0,
            expected_missing_bytes=orig_size,
            expected_surviving_intervals=[],
            expected_missing_intervals=[(0, orig_size)],
            expected_reconstructed_intervals=[],
            expected_corrupted_intervals=[],
            forensic_classification_rule="AMBIGUOUS_PHYSICAL_LAYOUT",
        )
    elif not artifact.damage_intervals:
        # Rule 1: INTACT
        status: ExpectedStatus = "FULLY_RECOVERED"
        rule_name = "INTACT"
        total_verified = orig_size
        total_reconstructed = 0
        total_missing = 0
        surviving_intervals = [(0, orig_size)]
    elif has_deterministic_repair:
        # Rule 3: DETERMINISTIC_REPAIR (R > 0 means status is PARTIALLY_RECOVERED, never FULLY)
        status = "PARTIALLY_RECOVERED"
        rule_name = "DETERMINISTIC_REPAIR"
    elif has_gap_unrepaired:
        # Rule 2: PHYSICAL_GAP_UNREPAIRED
        status = "PARTIALLY_RECOVERED"
        rule_name = "PHYSICAL_GAP_UNREPAIRED"
    elif has_unrepairable_corruption:
        # Rule 4: UNREPAIRABLE_CORRUPTION
        status = "CORRUPTED"
        rule_name = "UNREPAIRABLE_CORRUPTION"
        total_verified = 0
        total_reconstructed = 0
        surviving_intervals = []
    else:
        status = "PARTIALLY_RECOVERED"
        rule_name = "DEFAULT_PARTIAL"

    # Enforce invariant: R > 0 or M > 0 => cannot be FULLY_RECOVERED
    if (total_reconstructed > 0 or total_missing > 0) and status == "FULLY_RECOVERED":
        raise AssertionError("Derived expectation invariant violated: FULLY_RECOVERED with R > 0 or M > 0")

    return DerivedExpectation(
        artifact_id=artifact.artifact_id,
        expected_status=status,
        expected_verified_bytes=total_verified,
        expected_reconstructed_bytes=total_reconstructed,
        expected_missing_bytes=total_missing,
        expected_surviving_intervals=surviving_intervals,
        expected_missing_intervals=missing_intervals,
        expected_reconstructed_intervals=reconstructed_intervals,
        expected_corrupted_intervals=corrupted_intervals,
        forensic_classification_rule=rule_name,
    )
