"""benchmark/run_realworld.py — Recoverix Empirical Real-World Validation Harness.

Executes the deterministic Recoverix recovery pipeline against external corpus samples
described by a ground-truth manifest, observing and evaluating:
  - Candidate detection & false positives/negatives
  - Format-specific structural validation
  - Volume accounting (V, R, M) & original-identity verification
  - Structural outcome when ground truth is unknown / unmeasurable
  - Strict read-only handling of corpus evidence files (never downloads or mutates)
  - 5 MiB bounded evidence input size limit

Usage:
    python -m benchmark.run_realworld --manifest path/to/manifest.json [--corpus-dir path/to/corpus] [--output-report path/to/report.json] [--quiet]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

from pydantic import BaseModel, Field, model_validator

# Ensure project root is on sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.app.recovery.scanner import scan_evidence, Candidate
from backend.app.recovery.tracer import execute_traced_recoveries
from backend.app.recovery.validators import validate_artifact
from backend.app.models.recovery_run import RecoveryRun

# Maximum evidence input limit (5 MiB)
MAX_EVIDENCE_SIZE = 5 * 1024 * 1024


# ── MANIFEST DATA CONTRACTS ───────────────────────────────────────────────

class RealWorldSample(BaseModel):
    """Manifest entry for a single real-world or external evidence file."""

    sample_id: str
    file_path: str
    format: Optional[str] = None
    corruption_category: str = "unknown"
    detection_mode: Optional[Literal["known_file", "blind", "synthetic_harness"]] = None
    description: Optional[str] = None

    # Expected ground-truth metrics (nullable for blind/wild samples)
    expected_detection: Optional[bool] = None
    expected_status: Optional[str] = None
    expected_verified_bytes: Optional[int] = None
    expected_reconstructed_bytes: Optional[int] = None
    expected_missing_bytes: Optional[int] = None
    original_sha256: Optional[str] = None

    # Provenance and licensing
    license: Optional[str] = None
    provenance_notes: Optional[str] = None

    @model_validator(mode="after")
    def normalize_fields(self) -> "RealWorldSample":
        if self.original_sha256:
            object.__setattr__(self, "original_sha256", self.original_sha256.lower().strip())
        if self.format:
            object.__setattr__(self, "format", self.format.lower().strip("."))
        return self


class RealWorldManifest(BaseModel):
    """Corpus manifest declaring a collection of test files and ground truths."""

    manifest_version: str = "1.0.0"
    corpus_name: str = "realworld-validation"
    description: Optional[str] = None
    samples: List[RealWorldSample] = Field(default_factory=list)


# ── EVALUATION LOGIC ──────────────────────────────────────────────────────

def evaluate_realworld_sample(
    sample: RealWorldSample,
    corpus_dir: Path,
) -> Dict[str, Any]:
    """Execute recovery pipeline on one corpus sample and evaluate observed metrics.

    Enforces strict read-only access and bounded 5 MiB file reading.
    """
    start_time = time.perf_counter()

    # Resolve and confine file path within corpus_dir
    resolved_corpus = corpus_dir.resolve()
    raw_path = Path(sample.file_path)
    if raw_path.is_absolute():
        target_path = raw_path.resolve()
    else:
        target_path = (resolved_corpus / raw_path).resolve()

    sample_result: Dict[str, Any] = {
        "sample_id": sample.sample_id,
        "file_path": str(target_path),
        "corruption_category": sample.corruption_category,
        "format": sample.format,
        "file_size_bytes": 0,
        "file_sha256": None,
        "execution_error": None,
        "candidates_detected": 0,
        "candidate_details": [],
        "recovery_runs_count": 0,
        "recoveries": [],
        "ground_truth_evaluation": {
            "has_ground_truth": False,
            "detection_match": None,
            "status_match": None,
            "payload_hash_match": "NOT_MEASURABLE",
            "volume_accounting_match": None,
            "violations": [],
        },
        "elapsed_seconds": 0.0,
    }

    try:
        target_path.relative_to(resolved_corpus)
    except ValueError:
        sample_result["execution_error"] = (
            f"PATH_TRAVERSAL_PROHIBITED: File path '{sample.file_path}' resolves outside corpus root '{resolved_corpus}'"
        )
        sample_result["elapsed_seconds"] = round(time.perf_counter() - start_time, 4)
        return sample_result

    file_path = target_path

    # 1. Existence check
    if not file_path.exists() or not file_path.is_file():
        sample_result["execution_error"] = f"FILE_NOT_FOUND: Evidence file does not exist: {file_path}"
        sample_result["elapsed_seconds"] = round(time.perf_counter() - start_time, 4)
        return sample_result

    # 2. Size limit check
    file_size = file_path.stat().st_size
    sample_result["file_size_bytes"] = file_size
    if file_size > MAX_EVIDENCE_SIZE:
        sample_result["execution_error"] = (
            f"EXCEEDS_SIZE_LIMIT: File size {file_size} bytes exceeds maximum evidence limit of {MAX_EVIDENCE_SIZE} bytes (5 MiB)"
        )
        sample_result["elapsed_seconds"] = round(time.perf_counter() - start_time, 4)
        return sample_result

    # 3. Read-only byte ingestion
    try:
        with open(file_path, "rb") as f:
            evidence_bytes = f.read()
    except Exception as exc:
        sample_result["execution_error"] = f"READ_ERROR: Failed to read file {file_path}: {exc}"
        sample_result["elapsed_seconds"] = round(time.perf_counter() - start_time, 4)
        return sample_result

    file_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
    sample_result["file_sha256"] = file_sha256

    # 4. Scanner execution (candidate discovery)
    try:
        candidates: List[Candidate] = scan_evidence(evidence_bytes)
    except Exception as exc:
        sample_result["execution_error"] = f"SCANNER_ERROR: scan_evidence failed: {exc}"
        sample_result["elapsed_seconds"] = round(time.perf_counter() - start_time, 4)
        return sample_result

    sample_result["candidates_detected"] = len(candidates)
    sample_result["candidate_details"] = [
        {
            "candidate_id": c.candidate_id,
            "format": c.format,
            "offset": c.offset,
            "length": getattr(c, "detected_header_length", 0),
        }
        for c in candidates
    ]

    # 5. Recovery tracer execution
    detection_mode = sample.detection_mode or ("known_file" if sample.format else "blind")
    try:
        recovery_runs: List[RecoveryRun] = execute_traced_recoveries(
            filename=file_path.name,
            content=evidence_bytes,
            detection_mode=detection_mode,
        )
    except Exception as exc:
        sample_result["execution_error"] = f"RECOVERY_ERROR: execute_traced_recoveries failed: {exc}"
        sample_result["elapsed_seconds"] = round(time.perf_counter() - start_time, 4)
        return sample_result

    sample_result["recovery_runs_count"] = len(recovery_runs)

    recoveries_list: List[Dict[str, Any]] = []
    for r in recovery_runs:
        # Extract recovered payload bytes
        payload_bytes = b""
        if r.output and "recovered_bytes" in r.output:
            raw_hex = r.output["recovered_bytes"]
            try:
                payload_bytes = bytes.fromhex(raw_hex)
            except Exception:
                payload_bytes = raw_hex.encode("utf-8", errors="replace")

        payload_sha256 = hashlib.sha256(payload_bytes).hexdigest() if payload_bytes else ""

        # Validate structural outcome using format validator
        val_res = validate_artifact(r.format, payload_bytes) if payload_bytes else None

        rec_entry: Dict[str, Any] = {
            "candidate_id": r.candidate_id,
            "format": r.format,
            "status": r.status,
            "confidence_score": getattr(r, "confidence_score", 0.0),
            "total_input_bytes": r.total_input_bytes,
            "total_verified_bytes": r.total_verified_bytes,
            "total_reconstructed_bytes": r.total_reconstructed_bytes,
            "total_missing_bytes": r.total_missing_bytes,
            "payload_size_bytes": len(payload_bytes),
            "payload_sha256": payload_sha256,
            "validation_valid": val_res.valid if val_res else False,
            "validation_errors": val_res.errors if val_res else ["Empty payload"],
        }
        recoveries_list.append(rec_entry)

    sample_result["recoveries"] = recoveries_list

    # 6. Ground-truth evaluation (if ground-truth fields are specified)
    has_gt = any([
        sample.expected_detection is not None,
        sample.expected_status is not None,
        sample.expected_verified_bytes is not None,
        sample.expected_reconstructed_bytes is not None,
        sample.expected_missing_bytes is not None,
        sample.original_sha256 is not None,
    ])

    gt_eval: Dict[str, Any] = {
        "has_ground_truth": has_gt,
        "detection_match": None,
        "status_match": None,
        "payload_hash_match": "NOT_MEASURABLE",
        "volume_accounting_match": None,
        "violations": [],
    }

    if has_gt:
        # 6a. Detection match
        if sample.expected_detection is not None:
            detected_bool = len(candidates) > 0
            gt_eval["detection_match"] = (detected_bool == sample.expected_detection)
            if not gt_eval["detection_match"]:
                gt_eval["violations"].append(
                    f"Detection mismatch: expected={sample.expected_detection}, observed={detected_bool} (count={len(candidates)})"
                )

        # 6b. Status match (evaluated against primary recovery run)
        primary_rec = recoveries_list[0] if recoveries_list else None
        obs_status = primary_rec["status"] if primary_rec else "UNRECOVERABLE"

        if sample.expected_status is not None:
            gt_eval["status_match"] = (obs_status == sample.expected_status)
            if not gt_eval["status_match"]:
                gt_eval["violations"].append(
                    f"Status mismatch: expected={sample.expected_status}, observed={obs_status}"
                )

        # 6c. Payload hash match
        if sample.original_sha256:
            if primary_rec and primary_rec["payload_sha256"]:
                if primary_rec["payload_sha256"].lower() == sample.original_sha256.lower():
                    gt_eval["payload_hash_match"] = "MATCH"
                else:
                    gt_eval["payload_hash_match"] = "MISMATCH"
                    gt_eval["violations"].append(
                        f"Payload SHA-256 mismatch: expected={sample.original_sha256}, observed={primary_rec['payload_sha256']}"
                    )
            else:
                gt_eval["payload_hash_match"] = "MISMATCH"
                gt_eval["violations"].append(
                    f"Payload SHA-256 mismatch: expected={sample.original_sha256}, but no payload was recovered"
                )
        else:
            gt_eval["payload_hash_match"] = "NOT_MEASURABLE"

        # 6d. Volume accounting match
        if any([
            sample.expected_verified_bytes is not None,
            sample.expected_reconstructed_bytes is not None,
            sample.expected_missing_bytes is not None,
        ]):
            vol_ok = True
            if primary_rec:
                if sample.expected_verified_bytes is not None:
                    if primary_rec["total_verified_bytes"] != sample.expected_verified_bytes:
                        vol_ok = False
                        gt_eval["violations"].append(
                            f"Verified bytes mismatch: expected={sample.expected_verified_bytes}, observed={primary_rec['total_verified_bytes']}"
                        )
                if sample.expected_reconstructed_bytes is not None:
                    if primary_rec["total_reconstructed_bytes"] != sample.expected_reconstructed_bytes:
                        vol_ok = False
                        gt_eval["violations"].append(
                            f"Reconstructed bytes mismatch: expected={sample.expected_reconstructed_bytes}, observed={primary_rec['total_reconstructed_bytes']}"
                        )
                if sample.expected_missing_bytes is not None:
                    if primary_rec["total_missing_bytes"] != sample.expected_missing_bytes:
                        vol_ok = False
                        gt_eval["violations"].append(
                            f"Missing bytes mismatch: expected={sample.expected_missing_bytes}, observed={primary_rec['total_missing_bytes']}"
                        )
            else:
                vol_ok = False
                gt_eval["violations"].append("Volume accounting cannot be verified: no recovery run produced")
            gt_eval["volume_accounting_match"] = vol_ok

    sample_result["ground_truth_evaluation"] = gt_eval
    sample_result["elapsed_seconds"] = round(time.perf_counter() - start_time, 4)
    return sample_result


# ── SUMMARY METRICS CALCULATOR ─────────────────────────────────────────────

def calculate_corpus_summary(sample_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate aggregate forensic and statistical metrics across all evaluated samples."""
    total_samples = len(sample_results)
    file_not_found = 0
    oversized = 0
    path_traversal = 0
    exec_errors = 0
    processed = 0

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    samples_with_detection_gt = 0

    samples_with_status_gt = 0
    status_matches = 0
    status_mismatches = 0

    samples_with_hash_gt = 0
    hash_matches = 0
    hash_mismatches = 0

    total_candidates = 0
    total_recoveries = 0
    val_passed = 0
    val_failed = 0

    total_time = 0.0

    for s in sample_results:
        total_time += s.get("elapsed_seconds", 0.0)
        err = s.get("execution_error")
        if err:
            if "FILE_NOT_FOUND" in err:
                file_not_found += 1
            elif "EXCEEDS_SIZE_LIMIT" in err:
                oversized += 1
            elif "PATH_TRAVERSAL_PROHIBITED" in err:
                path_traversal += 1
            else:
                exec_errors += 1
            continue

        processed += 1
        cand_count = s.get("candidates_detected", 0)
        total_candidates += cand_count

        # Detection classification
        gt = s.get("ground_truth_evaluation", {})
        det_match = gt.get("detection_match")

        if det_match is not None:
            samples_with_detection_gt += 1
            # If expected_detection was explicitly set in sample:
            if det_match is True:
                if cand_count > 0:
                    tp += 1
                else:
                    tn += 1
            else:
                if cand_count > 0:
                    fp += 1
                else:
                    fn += 1

        # Status classification
        stat_match = gt.get("status_match")
        if stat_match is not None:
            samples_with_status_gt += 1
            if stat_match is True:
                status_matches += 1
            else:
                status_mismatches += 1

        # Hash classification
        hash_match = gt.get("payload_hash_match")
        if hash_match in ("MATCH", "MISMATCH"):
            samples_with_hash_gt += 1
            if hash_match == "MATCH":
                hash_matches += 1
            else:
                hash_mismatches += 1

        # Structural validation across recoveries
        for rec in s.get("recoveries", []):
            total_recoveries += 1
            if rec.get("validation_valid"):
                val_passed += 1
            else:
                val_failed += 1

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else None
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if (precision is not None and recall is not None and (precision + recall) > 0)
        else None
    )

    status_accuracy = (
        round(status_matches / samples_with_status_gt, 4)
        if samples_with_status_gt > 0
        else None
    )

    validation_pass_rate = (
        round(val_passed / total_recoveries, 4)
        if total_recoveries > 0
        else None
    )

    file_detection_metrics = {
        "samples_with_gt": samples_with_detection_gt,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
    }

    return {
        "total_samples": total_samples,
        "processed_samples": processed,
        "file_not_found_count": file_not_found,
        "oversized_file_count": oversized,
        "path_traversal_count": path_traversal,
        "execution_error_count": exec_errors,
        "file_level_detection_metrics": file_detection_metrics,
        "detection_metrics": file_detection_metrics,  # Backwards-compatible alias
        "candidate_level_metrics": {
            "total_candidates_detected": total_candidates,
            "total_recoveries_executed": total_recoveries,
            "candidates_per_processed_sample": round(total_candidates / processed, 2) if processed > 0 else 0.0,
        },
        "recovery_status_metrics": {
            "samples_with_gt": samples_with_status_gt,
            "status_matches": status_matches,
            "status_mismatches": status_mismatches,
            "accuracy": status_accuracy,
        },
        "payload_hash_metrics": {
            "samples_with_gt": samples_with_hash_gt,
            "hash_matches": hash_matches,
            "hash_mismatches": hash_mismatches,
        },
        "structural_validation_metrics": {
            "total_recoveries": total_recoveries,
            "validation_passed": val_passed,
            "validation_failed": val_failed,
            "pass_rate": validation_pass_rate,
        },
        "elapsed_total_seconds": round(total_time, 4),
    }


# ── RUNNER & CLI INTERFACE ────────────────────────────────────────────────

def run_realworld_benchmark(
    manifest_path: Union[str, Path],
    corpus_dir: Optional[Union[str, Path]] = None,
    output_report_path: Optional[Union[str, Path]] = None,
    quiet: bool = False,
) -> Dict[str, Any]:
    """Execute the empirical validation benchmark against a corpus manifest."""
    m_path = Path(manifest_path).resolve()
    if not m_path.exists():
        raise FileNotFoundError(f"Manifest file not found: {m_path}")

    # Load and validate manifest JSON
    try:
        manifest_text = m_path.read_text(encoding="utf-8")
        manifest_data = json.loads(manifest_text)
        manifest = RealWorldManifest.model_validate(manifest_data)
    except Exception as exc:
        raise ValueError(f"Failed to parse corpus manifest {m_path}: {exc}") from exc

    c_dir = Path(corpus_dir).resolve() if corpus_dir else m_path.parent

    if not quiet:
        print("═" * 72)
        print(f"  RECOVERIX EMPIRICAL VALIDATION HARNESS — {manifest.corpus_name}")
        print("═" * 72)
        print(f"  Manifest Path   : {m_path}")
        print(f"  Corpus Directory: {c_dir}")
        print(f"  Total Samples   : {len(manifest.samples)}")
        print("─" * 72)

    sample_results: List[Dict[str, Any]] = []
    for idx, sample in enumerate(manifest.samples, 1):
        res = evaluate_realworld_sample(sample, c_dir)
        sample_results.append(res)

        if not quiet:
            err = res.get("execution_error")
            status_tag = "ERROR" if err else "PROCESSED"
            primary_rec = res["recoveries"][0] if res["recoveries"] else None
            obs_stat = primary_rec["status"] if primary_rec else "N/A"
            gt = res.get("ground_truth_evaluation", {})
            stat_match = gt.get("status_match")
            match_str = ""
            if stat_match is not None:
                match_str = f" [Status Match: {stat_match}]"

            print(
                f"[{idx:03d}/{len(manifest.samples):03d}] {sample.sample_id} "
                f"({sample.corruption_category}) -> {status_tag} | Observed: {obs_stat}{match_str}"
            )
            if err:
                print(f"       ! {err}")
            elif gt.get("violations"):
                for v in gt["violations"]:
                    print(f"       * Ground truth violation: {v}")

    summary = calculate_corpus_summary(sample_results)

    final_report = {
        "report_version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "manifest_path": str(m_path),
        "corpus_directory": str(c_dir),
        "summary": summary,
        "samples": sample_results,
    }

    if not quiet:
        print("═" * 72)
        print("  CORPUS VALIDATION SUMMARY")
        print("═" * 72)
        print(f"  Processed Samples   : {summary['processed_samples']} / {summary['total_samples']}")
        if summary.get("path_traversal_count", 0) > 0:
            print(f"  Path Traversal Block: {summary['path_traversal_count']}")
        if summary["file_not_found_count"] > 0:
            print(f"  Files Not Found     : {summary['file_not_found_count']}")
        if summary["oversized_file_count"] > 0:
            print(f"  Oversized (>5 MiB)  : {summary['oversized_file_count']}")
        if summary["execution_error_count"] > 0:
            print(f"  Execution Errors    : {summary['execution_error_count']}")

        cand = summary.get("candidate_level_metrics", {})
        if cand:
            print(f"  Candidates Detected : {cand.get('total_candidates_detected', 0)} (avg {cand.get('candidates_per_processed_sample', 0.0)}/sample)")

        det = summary["detection_metrics"]
        if det["samples_with_gt"] > 0:
            print("  Detection Metrics (File-Level):")
            print(f"    TP: {det['true_positives']}, FP: {det['false_positives']}, TN: {det['true_negatives']}, FN: {det['false_negatives']}")
            print(f"    Precision: {det['precision']}, Recall: {det['recall']}, F1: {det['f1_score']}")

        rec = summary["recovery_status_metrics"]
        if rec["samples_with_gt"] > 0:
            print(f"  Recovery Status Acc : {rec['accuracy']} ({rec['status_matches']}/{rec['samples_with_gt']} matched)")

        hsh = summary["payload_hash_metrics"]
        if hsh["samples_with_gt"] > 0:
            print(f"  Payload SHA-256 Acc : {hsh['hash_matches']}/{hsh['samples_with_gt']} exact hash matches")

        val = summary["structural_validation_metrics"]
        print(f"  Structural Validity : {val['pass_rate']} ({val['validation_passed']}/{val['total_recoveries']} valid)")
        print(f"  Total Duration      : {summary['elapsed_total_seconds']}s")
        print("═" * 72)

    # Save output report if requested (ensuring evidence files are never overwritten)
    if output_report_path:
        out_p = Path(output_report_path).resolve()
        if out_p == m_path:
            raise ValueError(f"Refusing to write report: output path matches manifest file {out_p}")
        for s in manifest.samples:
            sample_resolved = (c_dir / s.file_path).resolve()
            if out_p == sample_resolved:
                raise ValueError(
                    f"Refusing to write report: output path {out_p} would overwrite evidence file {sample_resolved}"
                )
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(final_report, indent=2), encoding="utf-8")
        if not quiet:
            print(f"Report saved to: {out_p}")

    return final_report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recoverix Empirical Real-World Validation Harness.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--manifest",
        required=True,
        help="Path to the JSON corpus manifest.",
    )
    parser.add_argument(
        "--corpus-dir",
        default=None,
        help="Path to directory containing corpus files (defaults to manifest parent directory).",
    )
    parser.add_argument(
        "--output-report",
        default=None,
        help="Optional path to output the machine-readable JSON evaluation report.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress verbose console summary.",
    )

    args = parser.parse_args(argv)

    try:
        run_realworld_benchmark(
            manifest_path=args.manifest,
            corpus_dir=args.corpus_dir,
            output_report_path=args.output_report,
            quiet=args.quiet,
        )
        return 0
    except Exception as exc:
        print(f"Error running real-world benchmark harness: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
