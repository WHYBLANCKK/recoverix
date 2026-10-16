"""benchmark/json_benchmark.py — Marker-Free End-to-End JSON Recovery Benchmark.

Product Principle:
    "Recoverix does not guess what was lost. It proves what can be recovered."

Provides a reproducible, marker-free JSON recovery benchmark measuring
Recoverix's end-to-end recovery capabilities against independently recorded
physical ground truth.

All scenarios in this benchmark are strictly marker-free:
- No [SYNTHETIC_ARTIFACT_START] or [SYNTHETIC_ARTIFACT_END] delimiters.
- No FMT: tags or synthetic headers.
- Candidates are discovered solely through raw byte inspection and syntax boundaries.
- Reconstructions and evaluations enforce coordinate segregation (E, O, R).
- Structural validity is strictly distinguished from original payload identity.

Usage:
    python -m benchmark.json_benchmark --seed 42
    python benchmark/json_benchmark.py --seed 42 --report-path backend/generated/json_benchmark_report.json
"""

from __future__ import annotations

import argparse
import base64
import copy
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

from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)
from benchmark.models import (
    BenchmarkGroundTruthManifest,
    BenchmarkObservedManifest,
    PhysicalArtifactRecord,
    PhysicalDamageInterval,
    PhysicalPlacement,
)
from benchmark.evaluator import EvaluationReport, evaluate_scenario
from benchmark.run_baseline import run_pipeline_and_observe


# ── SCENARIO BUILDERS ──────────────────────────────────────────────────────

def build_clean_json_scenario(
    seed: int = 42,
    offset: int = 512,
) -> Tuple[BenchmarkGroundTruthManifest, bytes]:
    """Scenario A: Marker-Free Clean JSON.

    A valid, pristine JSON document embedded in an evidence buffer with zero-padding.
    No synthetic start or end markers.

    Ground Truth Expectation:
        - Format: json
        - Status: FULLY_RECOVERED
        - Verified bytes: 100% of payload
        - Reconstructed bytes: 0
        - Missing bytes: 0
        - Payload hash: Exact SHA-256 match
    """
    payload = b'{"service": "auth-gateway", "port": 8080, "protocol": "https", "enabled": true}'
    payload_sha256 = hashlib.sha256(payload).hexdigest()

    # Evidence layout: 512 bytes zero padding, payload, 512 bytes zero padding
    evidence = (b"\x00" * offset) + payload + (b"\x00" * 512)
    evidence_sha256 = hashlib.sha256(evidence).hexdigest()

    # Verification: strictly marker-free
    assert SYNTHETIC_START_MARKER not in evidence, "Accidental synthetic start marker in clean JSON evidence"
    assert SYNTHETIC_END_MARKER not in evidence, "Accidental synthetic end marker in clean JSON evidence"

    art = PhysicalArtifactRecord(
        artifact_id="art-json-clean-01",
        original_filename="clean_config.json",
        format="json",
        original_size_bytes=len(payload),
        original_sha256=payload_sha256,
        original_bytes_b64=base64.b64encode(payload).decode("ascii"),
        header_evidence_offset=offset,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=offset,
                evidence_length=len(payload),
                original_offset=0,
            )
        ],
        damage_intervals=[],
    )

    manifest = BenchmarkGroundTruthManifest(
        manifest_version="1.0.0",
        scenario_id="json-clean",
        evidence_buffer_id="json_clean.img",
        evidence_size_bytes=len(evidence),
        evidence_sha256=evidence_sha256,
        seed=seed,
        artifacts=[art],
        spatial_relationships=[],
    )

    return manifest, evidence


def build_truncated_closable_scenario(
    seed: int = 42,
    offset: int = 0,
    content_loss: bool = False,
) -> Tuple[BenchmarkGroundTruthManifest, bytes]:
    """Scenario B: Marker-Free Truncated JSON (Closable Prefix).

    Supports two distinct physical realities:
    1. content_loss=False (Case 2: Purely Structural Closer Repair)
       The original document had only its closing brackets truncated.
       The engine deterministically reconstructs ']}' (R=2, M=0).
       Recovered payload matches the original payload SHA-256.
       Status: PARTIALLY_RECOVERED, 0 violations, passes.

    2. content_loss=True (Case 1: Missing Original Content Preceding Closers)
       The original document had additional content (e.g. an extra array element)
       truncated before the closing point.
       The engine appends ']}' to produce valid JSON, but original content is lost.
       Ground truth records a physical gap (M=14).
       Evaluator identifies UNACCOUNTED_GAP (honest capability gap).
    """
    if not content_loss:
        # Case 2: Pure structural closer repair
        orig_payload = b'{"device": "telemetry-probe-4", "firmware": "v2.1.0", "readings": ["sensor_a", "sensor_b"]}'
        surviving_payload = b'{"device": "telemetry-probe-4", "firmware": "v2.1.0", "readings": ["sensor_a", "sensor_b"'
        closers = b"]}"
        gap_len = len(closers)
        scenario_id = "json-truncated-closable"
        evidence_buffer_id = "json_truncated_closable.img"
        damage_intervals = [
            PhysicalDamageInterval(
                original_start=len(surviving_payload),
                original_end=len(orig_payload),
                length=gap_len,
                damage_type="PHYSICAL_GAP",
                reconstruction_mode="RECONSTRUCTION_DETERMINISTIC",
                expected_reconstructed_bytes_b64=base64.b64encode(closers).decode("ascii"),
            )
        ]
    else:
        # Case 1: Missing original content preceding closers
        orig_payload = b'{"device": "telemetry-probe-4", "firmware": "v2.1.0", "readings": ["sensor_a", "sensor_b", "sensor_c"]}'
        surviving_payload = b'{"device": "telemetry-probe-4", "firmware": "v2.1.0", "readings": ["sensor_a", "sensor_b"'
        gap_len = len(orig_payload) - len(surviving_payload)
        scenario_id = "json-truncated-closable-content-loss"
        evidence_buffer_id = "json_truncated_closable_content_loss.img"
        damage_intervals = [
            PhysicalDamageInterval(
                original_start=len(surviving_payload),
                original_end=len(orig_payload),
                length=gap_len,
                damage_type="PHYSICAL_GAP",
                reconstruction_mode="RECONSTRUCTION_NONE",
            )
        ]

    evidence = (b"\x00" * offset) + surviving_payload
    evidence_sha256 = hashlib.sha256(evidence).hexdigest()

    assert SYNTHETIC_START_MARKER not in evidence, "Accidental synthetic start marker in truncated evidence"
    assert SYNTHETIC_END_MARKER not in evidence, "Accidental synthetic end marker in truncated evidence"

    art = PhysicalArtifactRecord(
        artifact_id=f"art-{scenario_id}-01",
        original_filename=f"{scenario_id.replace('-', '_')}.json",
        format="json",
        original_size_bytes=len(orig_payload),
        original_sha256=hashlib.sha256(orig_payload).hexdigest(),
        original_bytes_b64=base64.b64encode(orig_payload).decode("ascii"),
        header_evidence_offset=offset,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=offset,
                evidence_length=len(surviving_payload),
                original_offset=0,
            )
        ],
        damage_intervals=damage_intervals,
    )

    manifest = BenchmarkGroundTruthManifest(
        manifest_version="1.0.0",
        scenario_id=scenario_id,
        evidence_buffer_id=evidence_buffer_id,
        evidence_size_bytes=len(evidence),
        evidence_sha256=evidence_sha256,
        seed=seed,
        artifacts=[art],
        spatial_relationships=[],
    )

    return manifest, evidence


def build_truncated_closable_pure_scenario(
    seed: int = 42,
    offset: int = 0,
) -> Tuple[BenchmarkGroundTruthManifest, bytes]:
    """Scenario B1: Purely Structural Closer Repair."""
    return build_truncated_closable_scenario(seed=seed, offset=offset, content_loss=False)


def build_truncated_closable_content_loss_scenario(
    seed: int = 42,
    offset: int = 0,
) -> Tuple[BenchmarkGroundTruthManifest, bytes]:
    """Scenario B2: Missing Original Content Preceding Closers."""
    return build_truncated_closable_scenario(seed=seed, offset=offset, content_loss=True)


def build_truncated_incomplete_scenario(
    seed: int = 42,
    offset: int = 0,
) -> Tuple[BenchmarkGroundTruthManifest, bytes]:
    """Scenario C: Marker-Free Truncated JSON (Incomplete Token / Damaged).

    A JSON document truncated mid-string/mid-token (e.g. unterminated string).
    No synthetic markers.

    Original Document:
        {"session_id": "sess-9921", "user_id": 501, "action": "logout"} (64 bytes)

    Surviving Evidence (truncated mid-string at 'act'):
        {"session_id": "sess-9921", "user_id": 501, "act (49 bytes)

    Engine Capability Assessment:
        - The engine refuses to hallucinate: the unclosed string cannot be closed
          without inventing property/value characters.
        - Dropped incomplete token: ', "act' (7 bytes reported missing).
        - Preserved verified prefix: '{"session_id": "sess-9921", "user_id": 501' (42 bytes).
        - Status: PARTIALLY_RECOVERED.
        - Payload hash: Mismatch with original.
        - Verified bytes match original coordinates exactly.
    """
    orig_payload = b'{"session_id": "sess-9921", "user_id": 501, "action": "logout"}'
    surviving_payload = b'{"session_id": "sess-9921", "user_id": 501, "act'

    evidence = (b"\x00" * offset) + surviving_payload
    evidence_sha256 = hashlib.sha256(evidence).hexdigest()

    assert SYNTHETIC_START_MARKER not in evidence, "Accidental synthetic start marker in incomplete evidence"
    assert SYNTHETIC_END_MARKER not in evidence, "Accidental synthetic end marker in incomplete evidence"

    # Known boundary of the intact verified prefix in original coordinates
    intact_prefix_len = len(b'{"session_id": "sess-9921", "user_id": 501')

    art = PhysicalArtifactRecord(
        artifact_id="art-json-trunc-incomplete-01",
        original_filename="incomplete_token.json",
        format="json",
        original_size_bytes=len(orig_payload),
        original_sha256=hashlib.sha256(orig_payload).hexdigest(),
        original_bytes_b64=base64.b64encode(orig_payload).decode("ascii"),
        header_evidence_offset=offset,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=offset,
                evidence_length=len(surviving_payload),
                original_offset=0,
            )
        ],
        damage_intervals=[
            PhysicalDamageInterval(
                original_start=intact_prefix_len,
                original_end=len(orig_payload),
                length=len(orig_payload) - intact_prefix_len,
                damage_type="PHYSICAL_GAP",
                reconstruction_mode="RECONSTRUCTION_NONE",
            )
        ],
    )

    manifest = BenchmarkGroundTruthManifest(
        manifest_version="1.0.0",
        scenario_id="json-truncated-incomplete",
        evidence_buffer_id="json_truncated_incomplete.img",
        evidence_size_bytes=len(evidence),
        evidence_sha256=evidence_sha256,
        seed=seed,
        artifacts=[art],
        spatial_relationships=[],
    )

    return manifest, evidence


def build_unrecoverable_noise_scenario(
    seed: int = 42,
    offset: int = 512,
) -> Tuple[BenchmarkGroundTruthManifest, bytes]:
    """Scenario D: Marker-Free Ambiguous / Non-JSON Noise Negative Control.

    Evidence containing corrupt, non-JSON bytes that begin with '{' but cannot
    form valid JSON syntax or structure.

    Ground Truth Expectation:
        - Archetype: UNRECOVERABLE
        - Status: UNRECOVERABLE
        - Reconstructed bytes: 0
        - Verified bytes: 0
        - Must NOT produce a false FULLY_RECOVERED or PARTIALLY_RECOVERED candidate.
    """
    orig_payload = b'{"secret_token": "9f8e7d6c5b4a3210", "role": "admin", "expires": 1893456000}'
    noise_body = b'{"corrupted_entry": \xff\xfe\xfd\xfc, \x80\x81: bad_syntax}'
    evidence = (b"\x00" * offset) + noise_body + (b"\x00" * 450)
    evidence_sha256 = hashlib.sha256(evidence).hexdigest()

    assert SYNTHETIC_START_MARKER not in evidence, "Accidental synthetic start marker in noise evidence"
    assert SYNTHETIC_END_MARKER not in evidence, "Accidental synthetic end marker in noise evidence"

    art = PhysicalArtifactRecord(
        artifact_id="art-json-unrec-01",
        original_filename="destroyed_auth.json",
        format="json",
        original_size_bytes=len(orig_payload),
        original_sha256=hashlib.sha256(orig_payload).hexdigest(),
        original_bytes_b64=base64.b64encode(orig_payload).decode("ascii"),
        header_evidence_offset=offset,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=offset,
                evidence_length=len(noise_body),
                original_offset=0,
            )
        ],
        damage_intervals=[
            PhysicalDamageInterval(
                original_start=0,
                original_end=len(orig_payload),
                length=len(orig_payload),
                damage_type="RANDOM_OVERWRITE",
                reconstruction_mode="RECONSTRUCTION_NONE",
            )
        ],
        is_unrecoverable=True,
        unrecoverable_reason="Over 90% of artifact destroyed; surviving region is corrupted non-JSON noise",
        is_deterministic_recovery=False,
    )

    manifest = BenchmarkGroundTruthManifest(
        manifest_version="1.0.0",
        scenario_id="json-unrecoverable-noise",
        evidence_buffer_id="json_unrecoverable_noise.img",
        evidence_size_bytes=len(evidence),
        evidence_sha256=evidence_sha256,
        seed=seed,
        artifacts=[art],
        spatial_relationships=[],
    )

    return manifest, evidence


def build_json_with_binary_noise_scenario(
    seed: int = 42,
    offset: int = 128,
) -> Tuple[BenchmarkGroundTruthManifest, bytes]:
    """Scenario E: JSON Followed by High-Entropy Binary Noise.

    A valid JSON document followed immediately by high-entropy binary noise.
    Tests scanner boundary isolation: scanner must terminate candidate at
    the closing delimiter '}', isolating the JSON from the adjacent trailing noise.

    Ground Truth Expectation:
        - Format: json
        - Status: FULLY_RECOVERED
        - Verified bytes: 100% of JSON payload
        - Reconstructed bytes: 0
        - Missing bytes: 0
        - Candidate detection: 1 candidate, noise excluded
        - Payload hash: Exact SHA-256 match
    """
    payload = b'{"session_id": "sess-9941a", "authenticated": true, "timestamp": 1729000000}'
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    # Non-structured high-entropy noise
    noise = bytes([(x * 37 + 13) % 255 + 1 for x in range(128)])
    evidence = (b"\x00" * offset) + payload + noise
    evidence_sha256 = hashlib.sha256(evidence).hexdigest()

    assert SYNTHETIC_START_MARKER not in evidence, "Accidental synthetic start marker in evidence"
    assert SYNTHETIC_END_MARKER not in evidence, "Accidental synthetic end marker in evidence"

    art = PhysicalArtifactRecord(
        artifact_id="art-json-noise-iso-01",
        original_filename="session_auth.json",
        format="json",
        original_size_bytes=len(payload),
        original_sha256=payload_sha256,
        original_bytes_b64=base64.b64encode(payload).decode("ascii"),
        header_evidence_offset=offset,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=offset,
                evidence_length=len(payload),
                original_offset=0,
            )
        ],
        damage_intervals=[],
    )

    manifest = BenchmarkGroundTruthManifest(
        manifest_version="1.0.0",
        scenario_id="json-with-binary-noise",
        evidence_buffer_id="json_with_binary_noise.img",
        evidence_size_bytes=len(evidence),
        evidence_sha256=evidence_sha256,
        seed=seed,
        artifacts=[art],
        spatial_relationships=[],
    )

    return manifest, evidence


def build_two_independent_json_scenario(
    seed: int = 42,
    offset1: int = 64,
    noise_len: int = 64,
    suffix_len: int = 64,
) -> Tuple[BenchmarkGroundTruthManifest, bytes]:
    """Scenario F: Two Independent JSON Documents Separated by Binary Noise.

    Two distinct JSON documents placed in the same evidence buffer, separated
    by high-entropy binary noise and bounded by zero-padding.
    Tests multi-candidate discovery, isolation, and independent evaluation:
    neither document merges into the other, and no false-positive candidates are produced.

    Ground Truth Expectation:
        - Document 1: FULLY_RECOVERED, exact SHA-256 match, V=len(c1), R=0, M=0
        - Document 2: FULLY_RECOVERED, exact SHA-256 match, V=len(c2), R=0, M=0
        - Candidate detection: Exactly 2 true-positive candidates, 0 FP, 0 FN
        - Greedy matcher correctly maps each candidate to its respective artifact
    """
    c1 = b'{"cluster": "us-east-1", "primary": "node-01.internal", "shards": 4}'
    c2 = b'{"service": "metrics-collector", "port": 9090, "retention_days": 30}'
    noise = bytes([(i * 17) % 255 + 1 for i in range(noise_len)])

    off1 = offset1
    off2 = off1 + len(c1) + len(noise)
    evidence = (b"\x00" * off1) + c1 + noise + c2 + (b"\x00" * suffix_len)
    evidence_sha256 = hashlib.sha256(evidence).hexdigest()

    assert SYNTHETIC_START_MARKER not in evidence, "Accidental synthetic start marker in evidence"
    assert SYNTHETIC_END_MARKER not in evidence, "Accidental synthetic end marker in evidence"

    art1 = PhysicalArtifactRecord(
        artifact_id="art-json-multi-01",
        original_filename="cluster_config.json",
        format="json",
        original_size_bytes=len(c1),
        original_sha256=hashlib.sha256(c1).hexdigest(),
        original_bytes_b64=base64.b64encode(c1).decode("ascii"),
        header_evidence_offset=off1,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=off1,
                evidence_length=len(c1),
                original_offset=0,
            )
        ],
        damage_intervals=[],
    )

    art2 = PhysicalArtifactRecord(
        artifact_id="art-json-multi-02",
        original_filename="metrics_service.json",
        format="json",
        original_size_bytes=len(c2),
        original_sha256=hashlib.sha256(c2).hexdigest(),
        original_bytes_b64=base64.b64encode(c2).decode("ascii"),
        header_evidence_offset=off2,
        header_original_offset=0,
        placements=[
            PhysicalPlacement(
                fragment_index=0,
                evidence_offset=off2,
                evidence_length=len(c2),
                original_offset=0,
            )
        ],
        damage_intervals=[],
    )

    manifest = BenchmarkGroundTruthManifest(
        manifest_version="1.0.0",
        scenario_id="json-multi-candidate-independent",
        evidence_buffer_id="json_multi_candidate_independent.img",
        evidence_size_bytes=len(evidence),
        evidence_sha256=evidence_sha256,
        seed=seed,
        artifacts=[art1, art2],
        spatial_relationships=[],
    )

    return manifest, evidence


def build_all_json_scenarios(
    seed: int = 42,
) -> List[Tuple[BenchmarkGroundTruthManifest, bytes]]:
    """Build all marker-free JSON benchmark scenarios deterministically."""
    return [
        build_clean_json_scenario(seed=seed),
        build_truncated_closable_pure_scenario(seed=seed),
        build_truncated_closable_content_loss_scenario(seed=seed),
        build_truncated_incomplete_scenario(seed=seed),
        build_unrecoverable_noise_scenario(seed=seed),
        build_json_with_binary_noise_scenario(seed=seed),
        build_two_independent_json_scenario(seed=seed),
    ]


# ── EVALUATION & BENCHMARK EXECUTION ───────────────────────────────────────

def evaluate_json_scenario(
    gt_manifest: BenchmarkGroundTruthManifest,
    evidence_bytes: bytes,
) -> Dict[str, Any]:
    """Execute recovery pipeline on evidence bytes and evaluate against ground truth.

    CRITICAL FORENSIC BOUNDARY:
      The recovery pipeline receives ONLY the evidence filename and raw evidence bytes.
      Ground truth manifest is withheld until recovery completes.
    """
    # Enforce strictly marker-free evidence
    if SYNTHETIC_START_MARKER in evidence_bytes or SYNTHETIC_END_MARKER in evidence_bytes:
        raise AssertionError(
            f"Scenario {gt_manifest.scenario_id} violates marker-free integrity: synthetic framing detected in evidence"
        )

    # 1. Feed raw evidence bytes into production recovery pipeline
    obs_manifest = run_pipeline_and_observe(
        evidence_filename=gt_manifest.evidence_buffer_id,
        evidence_bytes=evidence_bytes,
    )

    # 2. Evaluate observed results against ground truth
    report: EvaluationReport = evaluate_scenario(gt_manifest, obs_manifest)

    # 3. Associate results with ground truth artifacts
    from benchmark.matcher import match_candidates_one_to_one
    matching = match_candidates_one_to_one(
        gt_manifest.artifacts,
        obs_manifest.candidates,
        gt_manifest.evidence_buffer_id,
    )
    art_to_cand = {m.artifact.artifact_id: m.candidate.candidate_id for m in matching.matched_pairs}
    eval_by_art_id = {ae.artifact_id: ae for ae in report.artifact_evaluations}
    rec_by_cand_id = {r.observed_candidate_id: r for r in obs_manifest.recoveries if r.observed_candidate_id}

    scenario_artifact_results = []
    for art in gt_manifest.artifacts:
        ae = eval_by_art_id.get(art.artifact_id)
        cand_id = art_to_cand.get(art.artifact_id)
        rec = rec_by_cand_id.get(cand_id)

        # Collect violations specific to this artifact
        art_violations = []
        for v in report.forensic_violations:
            if len(gt_manifest.artifacts) == 1:
                art_violations.append(v)
            elif art.artifact_id in v:
                art_violations.append(v)
            elif cand_id and (f"segment {cand_id}" in v or f"{cand_id}-" in v or f"Candidate {cand_id}" in v):
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

        scenario_artifact_results.append({
            "artifact_id": art.artifact_id,
            "filename": art.original_filename,
            "expected_status": ae.expected_status if ae else "UNKNOWN",
            "observed_status": ae.observed_status if ae else "UNRECOVERED",
            "status_match": ae.status_match if ae else False,
            "matched_candidate_id": cand_id,
            "v_volume_accuracy": ae.v_volume_accuracy if ae else 0.0,
            "r_volume_accuracy": ae.r_volume_accuracy if ae else 0.0,
            "m_volume_accuracy": ae.m_volume_accuracy if ae else 0.0,
            "observed_verified_bytes": ae.observed_verified_bytes if ae else 0,
            "expected_verified_bytes": ae.expected_verified_bytes if ae else 0,
            "v_is_zero_agreement": ae.v_is_zero_agreement if ae else False,
            "v_interval_iou": ae.v_interval_iou if ae else None,
            "r_interval_iou": ae.r_interval_iou if ae else None,
            "m_interval_iou": ae.m_interval_iou if ae else None,
            "v_byte_correctness": ae.v_byte_correctness if ae else None,
            "r_byte_correctness": ae.r_byte_correctness if ae else None,
            "whole_payload_hash_match": ae.whole_payload_hash_match if ae else None,
            "false_fully_recovered": ae.false_fully_recovered if ae else False,
            "forensic_violations": art_violations,
            "passed": passed,
        })

    has_matching_violations = any(
        "FALSE_POSITIVE_CANDIDATE" in v or "DUPLICATE_CANDIDATE" in v or "UNRECOVERED_ARTIFACT" in v
        for v in report.forensic_violations
    ) or (matching.false_positives > 0) or (len(matching.duplicate_candidates) > 0)

    all_passed = all(r["passed"] for r in scenario_artifact_results) and not has_matching_violations

    return {
        "scenario_id": gt_manifest.scenario_id,
        "evidence_buffer_id": gt_manifest.evidence_buffer_id,
        "evidence_size_bytes": gt_manifest.evidence_size_bytes,
        "evidence_sha256": gt_manifest.evidence_sha256,
        "candidates_discovered": len(obs_manifest.candidates),
        "recoveries_observed": len(obs_manifest.recoveries),
        "candidate_metrics": {
            "true_positives": report.candidate_metrics.true_positives,
            "false_positives": report.candidate_metrics.false_positives,
            "false_negatives": report.candidate_metrics.false_negatives,
            "duplicate_count": report.candidate_metrics.duplicate_count,
            "precision": report.candidate_metrics.precision,
            "recall": report.candidate_metrics.recall,
        },
        "artifacts": scenario_artifact_results,
        "forensic_violations": report.forensic_violations,
        "passed": all_passed,
    }


def run_json_benchmark(
    seed: int = 42,
    output_dir: Optional[Path] = None,
    report_path: Optional[Path] = None,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Execute complete marker-free JSON benchmark suite across all scenarios.

    Args:
        seed: Deterministic random seed (default: 42).
        output_dir: Optional directory to store generated evidence buffers.
        report_path: Optional path to emit the JSON benchmark report.
        verbose: If True, prints a formatted console summary.

    Returns:
        Structured dictionary representation of the JSON benchmark report.
    """
    out_dir = output_dir or (Path(_PROJECT_ROOT) / "backend" / "generated")
    out_dir.mkdir(parents=True, exist_ok=True)

    scenarios = build_all_json_scenarios(seed=seed)
    scenario_results: List[Dict[str, Any]] = []

    total_scenarios = len(scenarios)
    passed_scenarios = 0
    total_violations = 0

    for gt_manifest, evidence_bytes in scenarios:
        # Optionally write evidence buffer to output_dir
        ev_file = out_dir / gt_manifest.evidence_buffer_id
        ev_file.write_bytes(evidence_bytes)

        res = evaluate_json_scenario(gt_manifest, evidence_bytes)
        scenario_results.append(res)
        if res["passed"]:
            passed_scenarios += 1
        total_violations += len(res["forensic_violations"])

    report_data = {
        "benchmark_name": "Recoverix Marker-Free JSON Recovery Benchmark",
        "benchmark_milestone": "Milestone 2 Phase 1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "summary": {
            "scenarios_total": total_scenarios,
            "scenarios_passed": passed_scenarios,
            "scenarios_failed": total_scenarios - passed_scenarios,
            "total_forensic_violations": total_violations,
            "marker_free_verified": True,
        },
        "scenarios": scenario_results,
    }

    if report_path:
        r_path = Path(report_path)
        r_path.parent.mkdir(parents=True, exist_ok=True)
        r_path.write_text(json.dumps(report_data, indent=2))

    if verbose:
        _print_json_benchmark_summary(report_data)

    return report_data


def _print_json_benchmark_summary(report: Dict[str, Any]) -> None:
    """Print formatted summary of the marker-free JSON benchmark results."""
    print("\n" + "═" * 72)
    print("  RECOVERIX — MARKER-FREE JSON RECOVERY BENCHMARK (MILESTONE 2)")
    print("═" * 72)
    summary = report["summary"]
    print(f"  Benchmark Seed        : {report['seed']}")
    print(f"  Marker-Free Framing   : VERIFIED (zero synthetic delimiters)")
    print(f"  Scenarios Passed      : {summary['scenarios_passed']} / {summary['scenarios_total']}")
    print(f"  Forensic Violations   : {summary['total_forensic_violations']}")
    print("═" * 72)
    print("SCENARIO RESULTS:")
    print("─" * 72)

    for sc in report["scenarios"]:
        passed_tag = "[PASS]" if sc["passed"] else "[GAP / LIMITATION]"
        print(f"{passed_tag} {sc['scenario_id']} ({sc['evidence_buffer_id']}, {sc['evidence_size_bytes']} bytes)")
        for art in sc["artifacts"]:
            status_match_str = f"Match: {art['status_match']}"
            v_zero_note = " (0/0 agreement)" if art.get("v_is_zero_agreement") else ""
            print(f"       Volume Accounting  : V_vol_acc={art['v_volume_accuracy']:.3f}{v_zero_note}, R_vol_acc={art['r_volume_accuracy']:.3f}, M_vol_acc={art['m_volume_accuracy']:.3f} (aggregate counts only)")

            v_iou_str = f"{art['v_interval_iou']:.3f}" if art['v_interval_iou'] is not None else "N/A"
            r_iou_str = f"{art['r_interval_iou']:.3f}" if art['r_interval_iou'] is not None else "N/A"
            m_iou_str = f"{art['m_interval_iou']:.3f}" if art['m_interval_iou'] is not None else "N/A"
            print(f"       Original-Space IoU : V_iou={v_iou_str}, R_iou={r_iou_str}, M_iou={m_iou_str}")

            v_corr_str = f"{art['v_byte_correctness']:.3f}" if art['v_byte_correctness'] is not None else "N/A"
            r_corr_str = f"{art['r_byte_correctness']:.3f}" if art['r_byte_correctness'] is not None else "N/A"
            hash_str = (
                "MATCH" if art["whole_payload_hash_match"] is True
                else ("MISMATCH" if art["whole_payload_hash_match"] is False else "N/A (No Payload)")
            )
            print(f"       Byte Correctness   : V_byte_corr={v_corr_str}, R_byte_corr={r_corr_str}, Payload_SHA256={hash_str}")

            if art["forensic_violations"]:
                print("       Violations Detected:")
                for v in art["forensic_violations"]:
                    print(f"         ! {v}")
        print()

    print("─" * 72)
    print(f"FORENSIC AUDIT: {summary['total_forensic_violations']} total violations across all scenarios")
    print("═" * 72 + "\n")


# ── CLI ENTRY POINT ────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recoverix Marker-Free JSON Recovery Benchmark Runner."
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed (default: 42)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory for generated evidence buffers (default: backend/generated)",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=None,
        help="Path to save the JSON report",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output",
    )

    args = parser.parse_args()

    run_json_benchmark(
        seed=args.seed,
        output_dir=args.output_dir,
        report_path=args.report_path,
        verbose=not args.quiet,
    )


if __name__ == "__main__":
    main()
