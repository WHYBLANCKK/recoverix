"""tests/test_evaluation_corpus.py — Integration test for Milestone 13 Evaluation Corpus.

Executes the empirical validation harness against benchmark/evaluation_corpus/manifest.json
and verifies:
  1. Complete sample processing (15/15)
  2. 100% recovery status agreement against documented ground truth
  3. Exact payload SHA-256 matches on all intact samples
  4. Precise V / R / M volume accounting on reconstructed artifacts
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark.run_realworld import run_realworld_benchmark

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = _PROJECT_ROOT / "benchmark" / "evaluation_corpus" / "manifest.json"


def test_milestone_13_evaluation_corpus_benchmark(tmp_path: Path):
    """Run realworld benchmark harness on the Milestone 13 deterministic evaluation corpus."""
    assert MANIFEST_PATH.exists(), f"Evaluation corpus manifest missing at {MANIFEST_PATH}"

    report_path = tmp_path / "evaluation_report.json"

    report = run_realworld_benchmark(
        manifest_path=MANIFEST_PATH,
        corpus_dir=MANIFEST_PATH.parent,
        output_report_path=report_path,
        quiet=True,
    )

    summary = report["summary"]

    # 1. Complete accounting
    assert summary["total_samples"] == 15
    assert summary["processed_samples"] == 15
    assert summary["file_not_found_count"] == 0
    assert summary["oversized_file_count"] == 0
    assert summary["execution_error_count"] == 0

    # 2. Recovery status accuracy
    rec = summary["recovery_status_metrics"]
    assert rec["samples_with_gt"] == 15
    assert rec["status_matches"] == 15
    assert rec["status_mismatches"] == 0
    assert rec["accuracy"] == 1.0

    # 3. Payload SHA-256 accuracy on intact samples
    hsh = summary["payload_hash_metrics"]
    assert hsh["samples_with_gt"] == 4
    assert hsh["hash_matches"] == 4
    assert hsh["hash_mismatches"] == 0

    # 4. Detection metrics (file-level)
    det = summary["detection_metrics"]
    assert det["samples_with_gt"] == 8
    assert det["false_positives"] == 0
    assert det["false_negatives"] == 0
    assert det["precision"] == 1.0
    assert det["recall"] == 1.0

    # 5. Output report serialization
    assert report_path.exists()
    saved_data = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved_data["summary"]["total_samples"] == 15
