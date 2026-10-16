"""benchmark/run_baseline.py — Recoverix Recovery Benchmark Runner & Baseline Measurement.

Connects the existing benchmark evaluator foundation to the real Recoverix
recovery pipeline and produces deterministic baseline measurements.

Usage:
    python -m benchmark.run_baseline --seed 42
    python benchmark/run_baseline.py --seed 42 --report-path backend/generated/baseline_report.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root is on sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import backend.generate_case as gc
from backend.app.generator.disk import EvidenceDisk
from backend.app.generator.ground_truth import GroundTruthManifest
from backend.app.recovery.scanner import scan_evidence, Candidate
from backend.app.recovery.tracer import execute_traced_recoveries
from backend.app.models.recovery_run import RecoveryRun

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
from benchmark.evaluator import EvaluationReport, evaluate_scenario


# ── GROUND TRUTH BUILDER ───────────────────────────────────────────────────

def build_ground_truth_manifest(
    seed: int = 42,
    output_dir: Optional[Path] = None,
) -> Tuple[BenchmarkGroundTruthManifest, bytes]:
    """Generate or load the deterministic synthetic evidence and ground-truth manifest.

    Ground truth metadata and payloads are constructed deterministically
    using the existing generator specifications in backend.generate_case.

    Args:
        seed: Deterministic random seed (default: 42).
        output_dir: Optional output directory for generated files (default: backend/generated).

    Returns:
        Tuple of (BenchmarkGroundTruthManifest, evidence_bytes).
    """
    out_dir = output_dir or (Path(_PROJECT_ROOT) / "backend" / "generated")
    out_dir.mkdir(parents=True, exist_ok=True)

    img_path = out_dir / gc.EVIDENCE_FILENAME
    gt_path = out_dir / gc.MANIFEST_FILENAME

    # Generate if not existing or if regenerating
    if not img_path.exists() or not gt_path.exists():
        gc.generate_evidence(seed, out_dir)

    evidence_bytes = img_path.read_bytes()
    evidence_sha256 = hashlib.sha256(evidence_bytes).hexdigest()

    # Reconstruct the exact ground-truth original payloads
    # 1. Clean
    p_clean = gc._make_txt(
        "evidence_log.txt",
        [
            "type: access_log",
            "timestamp: 2025-03-15T08:30:00Z",
            "user: admin",
            "action: login",
            "ip: 192.168.1.100",
            "status: success",
        ],
    )
    art_clean = PhysicalArtifactRecord(
        artifact_id="art-clean-01",
        original_filename="evidence_log.txt",
        format="txt",
        original_size_bytes=len(p_clean),
        original_sha256=hashlib.sha256(p_clean).hexdigest(),
        original_bytes_b64=base64.b64encode(p_clean).decode("ascii"),
        header_evidence_offset=0,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=0,
                evidence_length=len(p_clean),
                original_offset=0,
            )
        ],
        damage_intervals=[],
    )

    # 2. Deleted
    p_del = gc._make_csv(
        "deleted_transactions.csv",
        [
            ["txn_id", "date", "amount", "account"],
            ["T1001", "2025-01-10", "5000.00", "ACC-4421"],
            ["T1002", "2025-01-11", "12300.50", "ACC-4421"],
            ["T1003", "2025-01-12", "780.25", "ACC-9983"],
            ["T1004", "2025-01-13", "44100.00", "ACC-4421"],
        ],
    )
    art_del = PhysicalArtifactRecord(
        artifact_id="art-deleted-01",
        original_filename="deleted_transactions.csv",
        format="csv",
        original_size_bytes=len(p_del),
        original_sha256=hashlib.sha256(p_del).hexdigest(),
        original_bytes_b64=base64.b64encode(p_del).decode("ascii"),
        header_evidence_offset=65536,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=65536,
                evidence_length=len(p_del),
                original_offset=0,
            )
        ],
        damage_intervals=[],
    )

    # 3. Fragmented (3 non-contiguous fragments: 131, 131, 131 bytes)
    p_frag = gc._make_txt(
        "fragmented_report.txt",
        [
            "type: incident_report",
            "case: IR-2025-0042",
            "severity: high",
            "summary: Unauthorized access detected on internal file server.",
            "affected_hosts: srv-file-01, srv-file-02",
            "timeline: Initial access at 02:14 UTC, lateral movement at 02:31 UTC.",
            "containment: Network segment isolated at 03:05 UTC.",
            "status: under_investigation",
        ],
    )
    art_frag = PhysicalArtifactRecord(
        artifact_id="art-fragmented-01",
        original_filename="fragmented_report.txt",
        format="txt",
        original_size_bytes=len(p_frag),
        original_sha256=hashlib.sha256(p_frag).hexdigest(),
        original_bytes_b64=base64.b64encode(p_frag).decode("ascii"),
        header_evidence_offset=131072,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(fragment_index=0, evidence_offset=131072, evidence_length=131, original_offset=0),
            PhysicalPlacement(fragment_index=1, evidence_offset=196608, evidence_length=131, original_offset=131),
            PhysicalPlacement(fragment_index=2, evidence_offset=262144, evidence_length=131, original_offset=262),
        ],
        damage_intervals=[],
    )

    # 4. Bifragment (Frag A: 142 bytes, Frag B: 142 bytes, 2747-byte gap in evidence)
    p_bifrag = gc._make_txt(
        "bifragment_memo.txt",
        [
            "type: internal_memo",
            "subject: Credentials rotation schedule",
            "from: security-team@example.com",
            "to: all-staff@example.com",
            "body: All service account credentials must be rotated by EOD Friday.",
            "priority: urgent",
        ],
    )
    art_bifrag = PhysicalArtifactRecord(
        artifact_id="art-bifragment-01",
        original_filename="bifragment_memo.txt",
        format="txt",
        original_size_bytes=len(p_bifrag),
        original_sha256=hashlib.sha256(p_bifrag).hexdigest(),
        original_bytes_b64=base64.b64encode(p_bifrag).decode("ascii"),
        header_evidence_offset=327680,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(fragment_index=0, evidence_offset=327680, evidence_length=142, original_offset=0),
            PhysicalPlacement(fragment_index=1, evidence_offset=330569, evidence_length=142, original_offset=142),
        ],
        damage_intervals=[],
        is_deterministic_recovery=False,
        non_deterministic_reason="INTERLEAVED_RANDOM_NOISE_UNSTRUCTURED_TXT",
    )

    # 5. Corrupted (243 bytes, 32 bytes random overwrite at offset 60)
    p_corr = gc._make_txt(
        "corrupted_config.txt",
        [
            "type: server_config",
            "hostname: db-primary-01",
            "port: 5432",
            "max_connections: 200",
            "ssl_mode: verify-full",
            "data_directory: /var/lib/postgresql/15/main",
            "log_level: warning",
        ],
    )
    art_corr = PhysicalArtifactRecord(
        artifact_id="art-corrupted-01",
        original_filename="corrupted_config.txt",
        format="txt",
        original_size_bytes=len(p_corr),
        original_sha256=hashlib.sha256(p_corr).hexdigest(),
        original_bytes_b64=base64.b64encode(p_corr).decode("ascii"),
        header_evidence_offset=458752,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=458752,
                evidence_length=len(p_corr),
                original_offset=0,
            )
        ],
        damage_intervals=[
            PhysicalDamageInterval(
                original_start=60,
                original_end=92,
                length=32,
                damage_type="RANDOM_OVERWRITE",
                reconstruction_mode="RECONSTRUCTION_NONE",
            )
        ],
    )

    # 6. Unrecoverable (247 bytes original, only first 49 bytes survive, 198 destroyed)
    p_unrec = gc._make_txt(
        "destroyed_evidence.txt",
        [
            "type: key_material",
            "algorithm: AES-256-GCM",
            "key_id: KEY-2025-ALPHA",
            "created: 2025-02-20T14:00:00Z",
            "NOTE: This key material has been destroyed and cannot be recovered.",
        ],
    )
    art_unrec = PhysicalArtifactRecord(
        artifact_id="art-unrecoverable-01",
        original_filename="destroyed_evidence.txt",
        format="txt",
        original_size_bytes=len(p_unrec),
        original_sha256=hashlib.sha256(p_unrec).hexdigest(),
        original_bytes_b64=base64.b64encode(p_unrec).decode("ascii"),
        header_evidence_offset=524288,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=524288,
                evidence_length=49,
                original_offset=0,
            )
        ],
        damage_intervals=[
            PhysicalDamageInterval(
                original_start=49,
                original_end=247,
                length=198,
                damage_type="RANDOM_OVERWRITE",
                reconstruction_mode="RECONSTRUCTION_NONE",
            )
        ],
        is_unrecoverable=True,
        unrecoverable_reason="Only 49 of 247 bytes survive; remaining 198 overwritten with noise",
    )

    artifacts = [art_clean, art_del, art_frag, art_bifrag, art_corr, art_unrec]

    manifest = BenchmarkGroundTruthManifest(
        manifest_version="1.0.0",
        scenario_id=f"benchmark-baseline-seed-{seed}",
        evidence_buffer_id=gc.EVIDENCE_FILENAME,
        evidence_size_bytes=len(evidence_bytes),
        evidence_sha256=evidence_sha256,
        seed=seed,
        artifacts=artifacts,
        spatial_relationships=[],
    )

    return manifest, evidence_bytes


# ── EXECUTION & OBSERVATION ADAPTER ────────────────────────────────────────

def run_pipeline_and_observe(
    evidence_filename: str,
    evidence_bytes: bytes,
) -> BenchmarkObservedManifest:
    """Feed evidence bytes into the canonical Recoverix recovery pipeline and observe results.

    CRITICAL BOUNDARY:
      The recovery pipeline functions (scan_evidence, execute_traced_recoveries)
      receive ONLY the raw evidence bytes and filename. Ground truth is NEVER passed
      to the production pipeline.

    After recovery completes, the observed output is mapped into BenchmarkObservedManifest,
    preserving coordinate segregation:
      E: evidence coordinates
      O: original artifact coordinates
      R: recovered payload coordinates

    Args:
        evidence_filename: Name of the evidence buffer (e.g. damaged.img).
        evidence_bytes: Raw binary evidence bytes.

    Returns:
        BenchmarkObservedManifest containing observed candidates and recovery results.
    """
    # 1. Discover candidates via real production scanner
    scanner_candidates: List[Candidate] = scan_evidence(evidence_bytes)

    obs_candidates: List[ObservedCandidateResult] = [
        ObservedCandidateResult(
            candidate_id=c.candidate_id,
            evidence_buffer_id=evidence_filename,
            format=c.format,
            offset=c.offset,
            detected_header_length=getattr(c, "detected_header_length", 26),
            estimated_end_offset=getattr(c, "estimated_end_offset", None),
            is_unbounded=(getattr(c, "estimated_end_offset", None) is None),
        )
        for c in scanner_candidates
    ]

    # 2. Execute recovery pipeline via canonical tracer
    recovery_runs: List[RecoveryRun] = execute_traced_recoveries(
        filename=evidence_filename,
        content=evidence_bytes,
    )

    # 3. Post-recovery mapping: build ObservedArtifactRecoveryResult
    # Derive segments purely from RecoveryRun fields (fragments, damage_regions,
    # reconstruction_steps, provenance, and output) with zero candidate-ID branching
    # and zero ground truth dependency.
    obs_recoveries: List[ObservedArtifactRecoveryResult] = []

    for r in recovery_runs:
        cid = r.candidate_id or "rec"
        cand_offset = r.provenance.get("evidence_start", 0) if r.provenance else 0

        # Extract recovered payload bytes
        payload = b""
        if r.output and "recovered_bytes" in r.output:
            raw_hex = r.output["recovered_bytes"]
            try:
                payload = bytes.fromhex(raw_hex)
            except Exception:
                payload = raw_hex.encode("utf-8", errors="replace")

        v_segs: List[ObservedRecoverySegment] = []
        r_segs: List[ObservedRecoverySegment] = []
        m_segs: List[ObservedRecoverySegment] = []

        # 1. Derive VERIFIED segments from r.fragments
        for idx, f in enumerate(r.fragments):
            if f.verified_bytes > 0:
                e_start = f.offset
                e_end = f.offset + f.verified_bytes

                r_start: Optional[int] = None
                r_end: Optional[int] = None
                if payload and len(payload) >= f.verified_bytes:
                    ev_slice = evidence_bytes[e_start:e_end] if e_end <= len(evidence_bytes) else b""
                    pos = payload.find(ev_slice) if ev_slice else -1
                    if pos != -1:
                        r_start = pos
                        r_end = pos + f.verified_bytes
                    elif idx == 0 and len(payload) >= f.verified_bytes:
                        r_start = 0
                        r_end = f.verified_bytes

                v_segs.append(
                    ObservedRecoverySegment(
                        segment_id=f"{cid}-{f.fragment_id}-v",
                        category="VERIFIED",
                        evidence_start=e_start,
                        evidence_end=e_end,
                        recovered_start=r_start,
                        recovered_end=r_end,
                        original_start=None,
                        original_end=None,
                    )
                )

        # 2. Derive RECONSTRUCTED or MISSING segments from r.damage_regions
        for idx, d in enumerate(r.damage_regions):
            e_start = d.start_offset
            e_end = d.end_offset
            if cand_offset > 0 and e_end <= (len(evidence_bytes) - cand_offset) and e_start < cand_offset:
                e_start += cand_offset
                e_end += cand_offset

            if d.status == "RECONSTRUCTED" or d.type == "RECONSTRUCTABLE":
                r_s: Optional[int] = None
                r_e: Optional[int] = None
                if payload and len(payload) >= d.end_offset and d.end_offset > d.start_offset:
                    r_s = d.start_offset
                    r_e = d.end_offset

                # Reconstructed structural bytes (e.g. appended closures) were never in evidence
                is_structural_closure = (d.type == "MISSING_STRUCTURAL_CLOSURE")
                ev_s: Optional[int] = None
                ev_e: Optional[int] = None
                if not is_structural_closure and e_end <= len(evidence_bytes) and e_start >= 0 and e_end > e_start:
                    ev_s = e_start
                    ev_e = e_end

                r_segs.append(
                    ObservedRecoverySegment(
                        segment_id=f"{cid}-{d.region_id}-r",
                        category="RECONSTRUCTED",
                        evidence_start=ev_s,
                        evidence_end=ev_e,
                        recovered_start=r_s,
                        recovered_end=r_e,
                        original_start=None,
                        original_end=None,
                    )
                )
            else:
                ev_s = None
                ev_e = None
                if e_end <= len(evidence_bytes) and e_start >= 0 and e_end > e_start:
                    ev_s = e_start
                    ev_e = e_end

                m_segs.append(
                    ObservedRecoverySegment(
                        segment_id=f"{cid}-{d.region_id}-m",
                        category="MISSING",
                        evidence_start=ev_s,
                        evidence_end=ev_e,
                        original_start=None,
                        original_end=None,
                    )
                )

        # 3. Derive RECONSTRUCTED segments from r.reconstruction_steps if not already captured
        for idx, s in enumerate(r.reconstruction_steps):
            if s.reconstructed_bytes > 0 and not r_segs:
                r_start = r.total_verified_bytes if len(payload) >= (r.total_verified_bytes + s.reconstructed_bytes) else 0
                r_end = r_start + s.reconstructed_bytes
                r_segs.append(
                    ObservedRecoverySegment(
                        segment_id=f"{cid}-{s.step_id}-r",
                        category="RECONSTRUCTED",
                        evidence_start=s.gap_start,
                        evidence_end=s.gap_end,
                        recovered_start=r_start if r_end <= len(payload) else None,
                        recovered_end=r_end if r_end <= len(payload) else None,
                        original_start=None,
                        original_end=None,
                    )
                )
            if s.missing_bytes > 0 and not m_segs:
                m_segs.append(
                    ObservedRecoverySegment(
                        segment_id=f"{cid}-{s.step_id}-m",
                        category="MISSING",
                        evidence_start=s.gap_start,
                        evidence_end=s.gap_end,
                        original_start=None,
                        original_end=None,
                    )
                )

        # 4. Fallback for unrepresented reconstructed/missing volume
        if r.total_reconstructed_bytes > 0 and not r_segs:
            r_start = r.total_verified_bytes if len(payload) >= (r.total_verified_bytes + r.total_reconstructed_bytes) else 0
            r_end = min(len(payload), r_start + r.total_reconstructed_bytes)
            if r_end > r_start:
                r_segs.append(
                    ObservedRecoverySegment(
                        segment_id=f"{cid}-r-fallback",
                        category="RECONSTRUCTED",
                        recovered_start=r_start,
                        recovered_end=r_end,
                        original_start=None,
                        original_end=None,
                    )
                )

        if r.total_missing_bytes > 0 and not m_segs:
            m_segs.append(
                ObservedRecoverySegment(
                    segment_id=f"{cid}-m-fallback",
                    category="MISSING",
                    original_start=None,
                    original_end=None,
                )
            )

        obs_rec = ObservedArtifactRecoveryResult(
            observed_candidate_id=r.candidate_id,
            detected_format=r.format,
            observed_status=r.status,
            confidence_score=int(r.confidence.get("total", 0) if r.confidence else 0),
            total_input_bytes=r.total_input_bytes,
            total_verified_bytes=r.total_verified_bytes,
            total_reconstructed_bytes=r.total_reconstructed_bytes,
            total_missing_bytes=r.total_missing_bytes,
            recovered_payload_bytes=payload,
            verified_segments=v_segs,
            reconstructed_segments=r_segs,
            missing_segments=m_segs,
        )
        obs_recoveries.append(obs_rec)

    return BenchmarkObservedManifest(
        manifest_version="1.0.0",
        scenario_id="observed-run",
        evidence_buffer_id=evidence_filename,
        candidates=obs_candidates,
        recoveries=obs_recoveries,
        observed_relationships=[],
    )


# ── BENCHMARK RUNNER & REPORTER ────────────────────────────────────────────

def run_baseline_benchmark(
    seed: int = 42,
    output_dir: Optional[Path] = None,
    report_path: Optional[Path] = None,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Execute the complete baseline recovery benchmark and emit reports.

    Args:
        seed: Deterministic random seed (default: 42).
        output_dir: Directory for generated evidence (default: backend/generated).
        report_path: Path to write the JSON baseline report.
        verbose: If True, prints a formatted console summary.

    Returns:
        Structured dictionary representation of the baseline report.
    """
    out_dir = output_dir or (Path(_PROJECT_ROOT) / "backend" / "generated")
    gt_manifest, evidence_bytes = build_ground_truth_manifest(seed=seed, output_dir=out_dir)

    # Run the real recovery pipeline on the evidence bytes
    obs_manifest = run_pipeline_and_observe(
        evidence_filename=gc.EVIDENCE_FILENAME,
        evidence_bytes=evidence_bytes,
    )

    # Evaluate using the benchmark evaluator
    report: EvaluationReport = evaluate_scenario(gt_manifest, obs_manifest)

    # Build scenario-level detail records
    eval_by_art_id = {ae.artifact_id: ae for ae in report.artifact_evaluations}
    rec_by_cand_id = {r.observed_candidate_id: r for r in obs_manifest.recoveries if r.observed_candidate_id}

    scenario_details = []
    scenarios_passed = 0
    scenarios_failed = 0

    # Match each ground-truth artifact
    for art in gt_manifest.artifacts:
        ae = eval_by_art_id.get(art.artifact_id)
        # Map candidate matching to associate violations accurately
        from benchmark.matcher import match_candidates_one_to_one
        matching = match_candidates_one_to_one(
            gt_manifest.artifacts,
            obs_manifest.candidates,
            gt_manifest.evidence_buffer_id,
        )
        art_to_cand = {m.artifact.artifact_id: m.candidate.candidate_id for m in matching.matched_pairs}
        cand_id = art_to_cand.get(art.artifact_id)

        # Find violations specific to this artifact or its candidate
        art_violations = []
        for v in report.forensic_violations:
            if art.artifact_id in v:
                art_violations.append(v)
            elif cand_id and (f"segment {cand_id}" in v or f"{cand_id}-" in v):
                art_violations.append(v)
            elif art.is_unrecoverable and ("UNRECOVERABLE_MISCLASSIFIED" in v or "OVERSTATED_VERIFICATION" in v or "UNACCOUNTED_GAP" in v):
                art_violations.append(v)

        requires_exact_payload = (ae.expected_status == "FULLY_RECOVERED") if ae else False
        payload_ok = (ae.whole_payload_hash_match is True) if (ae and requires_exact_payload) else True
        byte_corr_ok = (ae.v_byte_correctness is None or ae.v_byte_correctness >= 1.0) if ae else True

        passed = (
            ae is not None
            and ae.status_match
            and not ae.false_fully_recovered
            and payload_ok
            and byte_corr_ok
            and len(art_violations) == 0
        )

        if passed:
            scenarios_passed += 1
        else:
            scenarios_failed += 1

        rec = rec_by_cand_id.get(cand_id)
        scenario_details.append({
            "scenario_id": art.artifact_id,
            "artifact_id": art.artifact_id,
            "archetype": art.artifact_id.split("-")[1] if "-" in art.artifact_id else "unknown",
            "filename": art.original_filename,
            "format": art.format,
            "passed": passed,
            "status": {
                "expected": ae.expected_status if ae else "UNKNOWN",
                "observed": ae.observed_status if ae else "UNKNOWN",
                "match": ae.status_match if ae else False,
            },
            "volume_accounting": {
                "description": "Aggregate volume accounting comparison only; does not imply byte or coordinate correctness.",
                "verified_volume_accuracy": ae.v_volume_accuracy if ae else 0.0,
                "reconstructed_volume_accuracy": ae.r_volume_accuracy if ae else 0.0,
                "missing_volume_accuracy": ae.m_volume_accuracy if ae else 0.0,
            },
            "volumes": {
                "expected": {
                    "verified": sum(p.evidence_length for p in art.placements),
                    "reconstructed": sum(d.length for d in art.damage_intervals if d.reconstruction_mode == "RECONSTRUCTION_DETERMINISTIC"),
                    "missing": sum(d.length for d in art.damage_intervals if d.reconstruction_mode != "RECONSTRUCTION_DETERMINISTIC"),
                },
                "observed": {
                    "verified": rec.total_verified_bytes if rec else 0,
                    "reconstructed": rec.total_reconstructed_bytes if rec else 0,
                    "missing": rec.total_missing_bytes if rec else 0,
                },
                "accuracy": {
                    "verified": ae.v_volume_accuracy if ae else 0.0,
                    "reconstructed": ae.r_volume_accuracy if ae else 0.0,
                    "missing": ae.m_volume_accuracy if ae else 0.0,
                },
            },
            "original_space_intervals_iou": {
                "verified": ae.v_interval_iou if ae else None,
                "reconstructed": ae.r_interval_iou if ae else None,
                "missing": ae.m_interval_iou if ae else None,
            },
            "intervals_iou": {
                "verified": ae.v_interval_iou if ae else None,
                "reconstructed": ae.r_interval_iou if ae else None,
                "missing": ae.m_interval_iou if ae else None,
            },
            "original_space_byte_correctness": {
                "verified": ae.v_byte_correctness if ae else None,
                "reconstructed": ae.r_byte_correctness if ae else None,
            },
            "byte_correctness": {
                "verified": ae.v_byte_correctness if ae else None,
                "reconstructed": ae.r_byte_correctness if ae else None,
            },
            "whole_payload_hash_match": ae.whole_payload_hash_match if ae else None,
            "false_recovery_violations": art_violations,
        })

    report_dict: Dict[str, Any] = {
        "benchmark_version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "evidence_file": gc.EVIDENCE_FILENAME,
        "evidence_size_bytes": len(evidence_bytes),
        "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
        "summary": {
            "scenarios_total": len(gt_manifest.artifacts),
            "scenarios_passed": scenarios_passed,
            "scenarios_failed": scenarios_failed,
            "overall_passed": report.passed and (scenarios_failed == 0) and (len(gt_manifest.artifacts) > 0),
            "candidate_detection": {
                "precision": report.candidate_metrics.precision,
                "recall": report.candidate_metrics.recall,
                "true_positives": report.candidate_metrics.true_positives,
                "false_positives": report.candidate_metrics.false_positives,
                "false_negatives": report.candidate_metrics.false_negatives,
                "duplicate_count": report.candidate_metrics.duplicate_count,
            },
            "spatial_relationship_accuracy": report.relationship_accuracy,
            "total_forensic_violations": len(report.forensic_violations),
        },
        "scenarios": scenario_details,
        "forensic_violations": report.forensic_violations,
    }

    # Save JSON baseline report if path specified or default
    save_path = report_path or (out_dir / "baseline_report.json")
    save_path.parent.mkdir(parents=True, exist_ok=True)
    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    if verbose:
        print_console_summary(report_dict)

    return report_dict


def print_console_summary(report: Dict[str, Any]) -> None:
    """Print a clean, concise, human-readable baseline benchmark summary."""
    summary = report["summary"]
    cand = summary["candidate_detection"]

    def _fmt(val: Optional[float]) -> str:
        return f"{val:.3f}" if val is not None else "N/A"

    print()
    print("═" * 72)
    print("  RECOVERIX RECOVERY ENGINE — 3.7.2 BASELINE BENCHMARK REPORT")
    print("═" * 72)
    print(f"  Benchmark Seed        : {report['seed']}")
    print(f"  Evidence File         : {report['evidence_file']} ({report['evidence_size_bytes']:,} bytes)")
    print(f"  Candidate Detection   : Precision {cand['precision']:.3f}, Recall {cand['recall']:.3f} (TP: {cand['true_positives']}, FP: {cand['false_positives']}, FN: {cand['false_negatives']})")
    print(f"  Spatial Relationship  : {summary['spatial_relationship_accuracy']:.3f}")
    print(f"  Scenarios Passed      : {summary['scenarios_passed']} / {summary['scenarios_total']}")
    print(f"  Overall Engine Status : {'PASSED' if summary['overall_passed'] else 'FAILED (Weaknesses Exposed for Milestone 3.8)'}")
    print("═" * 72)
    print("SCENARIO RESULTS:")
    print("─" * 72)

    for sc in report["scenarios"]:
        tag = "[PASS]" if sc["passed"] else "[FAIL]"
        print(f"{tag} {sc['scenario_id']} ({sc['archetype']}, {sc['format']})")
        st = sc["status"]
        print(f"       Status             : Expected {st['expected']} | Observed {st['observed']} (Match: {st['match']})")
        vol = sc["volumes"]["accuracy"]
        v_zero_note = " (0/0 agreement)" if (vol['verified'] == 1.0 and sc['volumes']['expected']['verified'] == 0 and sc['volumes']['observed']['verified'] == 0) else ""
        print(f"       Volume Accounting  : V_vol_acc={vol['verified']:.3f}{v_zero_note}, R_vol_acc={vol['reconstructed']:.3f}, M_vol_acc={vol['missing']:.3f} (aggregate counts only)")
        iou = sc["intervals_iou"]
        print(f"       Original-Space IoU : V_iou={_fmt(iou['verified'])}, R_iou={_fmt(iou['reconstructed'])}, M_iou={_fmt(iou['missing'])}")
        bc = sc["byte_correctness"]
        hash_val = sc.get("whole_payload_hash_match")
        hash_str = "MATCH" if hash_val is True else ("MISMATCH" if hash_val is False else "N/A (No Payload)")
        print(f"       Byte Correctness   : V_byte_corr={_fmt(bc['verified'])}, R_byte_corr={_fmt(bc['reconstructed'])}, Payload_SHA256={hash_str}")

        if sc["false_recovery_violations"]:
            print(f"       Violations ({len(sc['false_recovery_violations'])}):")
            for v in sc["false_recovery_violations"]:
                print(f"         * {v}")
        print()

    print("─" * 72)
    print(f"FORENSIC AUDIT: {summary['total_forensic_violations']} total violations across all scenarios")
    for v in report["forensic_violations"]:
        print(f"  ! {v}")
    print("═" * 72)
    print()


# ── CLI ENTRY POINT ────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recoverix Baseline Recovery Benchmark Runner (Milestone 3.7.2)"
    )
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed (default: 42)")
    parser.add_argument(
        "--output-dir",
        type=str,
        default="backend/generated",
        help="Directory containing or generating damaged.img and ground_truth.json",
    )
    parser.add_argument(
        "--report-path",
        type=str,
        default="backend/generated/baseline_report.json",
        help="Path to save the JSON baseline report",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress human-readable console summary",
    )
    args = parser.parse_args()

    report = run_baseline_benchmark(
        seed=args.seed,
        output_dir=Path(args.output_dir),
        report_path=Path(args.report_path),
        verbose=not args.quiet,
    )
    if not report.get("summary", {}).get("overall_passed", False):
        sys.exit(1)


if __name__ == "__main__":
    main()
