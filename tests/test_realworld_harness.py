"""tests/test_realworld_harness.py — Test Suite for Real-World Validation Harness (Milestone 12).

Verifies the empirical validation harness (benchmark/run_realworld.py) across all required behaviors:
  1. Clean execution with known ground truth
  2. Missing file handling without process crash
  3. Bounded file reading (5 MiB limit enforcement)
  4. Pure noise negative control (true negative accounting)
  5. Embedded artifact carving inside noise
  6. Unknown / blind ground-truth execution (NOT_MEASURABLE status)
  7. Malformed manifest JSON handling
  8. Read-only corpus invariant (no mutation of evidence files or directory)
  9. CLI execution and machine-readable report export
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from benchmark.run_realworld import (
    MAX_EVIDENCE_SIZE,
    RealWorldManifest,
    RealWorldSample,
    calculate_corpus_summary,
    evaluate_realworld_sample,
    main,
    run_realworld_benchmark,
)


def test_01_clean_samples_with_known_ground_truth(tmp_path: Path):
    """Verify that valid files with complete ground truth evaluate with 100% accuracy."""
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()

    # 1. Clean JSON
    json_bytes = b'{"status": "ok", "count": 100, "items": ["a", "b"]}'
    (corpus_dir / "sample.json").write_bytes(json_bytes)
    json_sha = hashlib.sha256(json_bytes).hexdigest()

    # 2. Clean TXT
    txt_bytes = b"This is clean text evidence.\n"
    (corpus_dir / "sample.txt").write_bytes(txt_bytes)
    txt_sha = hashlib.sha256(txt_bytes).hexdigest()

    manifest_data = {
        "manifest_version": "1.0.0",
        "corpus_name": "clean-test",
        "samples": [
            {
                "sample_id": "clean-json",
                "file_path": "sample.json",
                "format": "json",
                "corruption_category": "intact",
                "expected_detection": True,
                "expected_status": "FULLY_RECOVERED",
                "original_sha256": json_sha,
            },
            {
                "sample_id": "clean-txt",
                "file_path": "sample.txt",
                "format": "txt",
                "corruption_category": "intact",
                "expected_detection": True,
                "expected_status": "FULLY_RECOVERED",
                "original_sha256": txt_sha,
            },
        ],
    }

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    report = run_realworld_benchmark(manifest_path=manifest_path, corpus_dir=corpus_dir, quiet=True)

    summary = report["summary"]
    assert summary["total_samples"] == 2
    assert summary["processed_samples"] == 2
    assert summary["file_not_found_count"] == 0
    assert summary["oversized_file_count"] == 0
    assert summary["execution_error_count"] == 0

    assert summary["recovery_status_metrics"]["accuracy"] == 1.0
    assert summary["payload_hash_metrics"]["hash_matches"] == 2


def test_02_missing_file_handling_without_crash(tmp_path: Path):
    """Missing evidence files must be recorded as FILE_NOT_FOUND errors without crashing the run."""
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()

    manifest_data = {
        "manifest_version": "1.0.0",
        "corpus_name": "missing-file-test",
        "samples": [
            {
                "sample_id": "missing-sample",
                "file_path": "non_existent_file.pdf",
                "format": "pdf",
            }
        ],
    }

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    report = run_realworld_benchmark(manifest_path=manifest_path, corpus_dir=corpus_dir, quiet=True)

    summary = report["summary"]
    assert summary["total_samples"] == 1
    assert summary["processed_samples"] == 0
    assert summary["file_not_found_count"] == 1
    assert "FILE_NOT_FOUND" in report["samples"][0]["execution_error"]


def test_03_oversized_file_limit_enforced(tmp_path: Path):
    """Files exceeding 5 MiB limit must be rejected without full memory ingestion."""
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()

    # Create sparse or truncated file > 5 MiB
    large_file = corpus_dir / "oversized.bin"
    large_size = MAX_EVIDENCE_SIZE + 1024
    with open(large_file, "wb") as f:
        f.seek(large_size - 1)
        f.write(b"\x00")

    manifest_data = {
        "manifest_version": "1.0.0",
        "corpus_name": "oversized-test",
        "samples": [
            {
                "sample_id": "oversized-sample",
                "file_path": "oversized.bin",
                "format": "bin",
            }
        ],
    }

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    report = run_realworld_benchmark(manifest_path=manifest_path, corpus_dir=corpus_dir, quiet=True)

    summary = report["summary"]
    assert summary["oversized_file_count"] == 1
    assert "EXCEEDS_SIZE_LIMIT" in report["samples"][0]["execution_error"]


def test_04_pure_noise_negative_control(tmp_path: Path):
    """Random noise without valid signatures must evaluate cleanly as UNRECOVERABLE (True Negative)."""
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()

    noise_bytes = bytes((i * 37 + 13) % 256 for i in range(4096))
    noise_file = corpus_dir / "random_noise.bin"
    noise_file.write_bytes(noise_bytes)

    manifest_data = {
        "manifest_version": "1.0.0",
        "corpus_name": "noise-control",
        "samples": [
            {
                "sample_id": "noise-01",
                "file_path": "random_noise.bin",
                "corruption_category": "noise",
                "expected_detection": False,
                "expected_status": "UNRECOVERABLE",
            }
        ],
    }

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    report = run_realworld_benchmark(manifest_path=manifest_path, corpus_dir=corpus_dir, quiet=True)

    sample_res = report["samples"][0]
    gt_eval = sample_res["ground_truth_evaluation"]

    # Must NOT report FULLY_RECOVERED on noise
    if sample_res["recoveries"]:
        assert sample_res["recoveries"][0]["status"] in ("UNRECOVERABLE", "CORRUPTED")
    assert gt_eval["detection_match"] is True

    summary = report["summary"]
    assert summary["detection_metrics"]["true_negatives"] == 1
    assert summary["detection_metrics"]["false_positives"] == 0


def test_05_embedded_json_in_noise(tmp_path: Path):
    """An artifact embedded inside surrounding noise must be carved and detected."""
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()

    lead_noise = b"\xff\x00\xaa\x55" * 128
    payload = b'{"record_id": 9988, "system": "test_embed", "active": true}'
    trail_noise = b"\x11\x22\x33\x44" * 64
    combined = lead_noise + payload + trail_noise

    embed_file = corpus_dir / "embedded.img"
    embed_file.write_bytes(combined)

    manifest_data = {
        "manifest_version": "1.0.0",
        "corpus_name": "embedded-test",
        "samples": [
            {
                "sample_id": "embed-json-01",
                "file_path": "embedded.img",
                "format": "json",
                "corruption_category": "embedded",
                "detection_mode": "blind",
                "expected_detection": True,
            }
        ],
    }

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    report = run_realworld_benchmark(manifest_path=manifest_path, corpus_dir=corpus_dir, quiet=True)

    sample_res = report["samples"][0]
    assert sample_res["candidates_detected"] >= 1
    assert sample_res["ground_truth_evaluation"]["detection_match"] is True


def test_06_unknown_ground_truth_sample(tmp_path: Path):
    """Real-world files with unknown ground truth are observed and structurally evaluated."""
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()

    csv_data = b"id,val\n1,10\n2,20\n"
    (corpus_dir / "wild_data.csv").write_bytes(csv_data)

    manifest_data = {
        "manifest_version": "1.0.0",
        "corpus_name": "wild-samples",
        "samples": [
            {
                "sample_id": "wild-csv",
                "file_path": "wild_data.csv",
                "format": "csv",
                # No expected status or original sha256
            }
        ],
    }

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    report = run_realworld_benchmark(manifest_path=manifest_path, corpus_dir=corpus_dir, quiet=True)

    sample_res = report["samples"][0]
    gt_eval = sample_res["ground_truth_evaluation"]
    assert gt_eval["has_ground_truth"] is False
    assert gt_eval["payload_hash_match"] == "NOT_MEASURABLE"
    assert sample_res["recoveries"][0]["validation_valid"] is True


def test_07_malformed_manifest_json_fails_cleanly(tmp_path: Path):
    """A non-JSON or invalid manifest raises ValueError and fails cleanly."""
    bad_manifest = tmp_path / "broken.json"
    bad_manifest.write_text("NOT_VALID_JSON{:::}", encoding="utf-8")

    with pytest.raises(ValueError, match="Failed to parse corpus manifest"):
        run_realworld_benchmark(manifest_path=bad_manifest)


def test_08_corpus_read_only_invariant(tmp_path: Path):
    """The harness must NEVER write to or alter the corpus directory or its evidence files."""
    corpus_dir = tmp_path / "readonly_corpus"
    corpus_dir.mkdir()

    f1 = corpus_dir / "file1.txt"
    f1.write_bytes(b"Read only content 1\n")
    f2 = corpus_dir / "file2.json"
    f2.write_bytes(b'{"key": "value"}')

    before_state = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in corpus_dir.iterdir()}

    manifest_data = {
        "manifest_version": "1.0.0",
        "corpus_name": "readonly-test",
        "samples": [
            {"sample_id": "s1", "file_path": "file1.txt", "format": "txt"},
            {"sample_id": "s2", "file_path": "file2.json", "format": "json"},
        ],
    }
    m_path = tmp_path / "manifest.json"
    m_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    run_realworld_benchmark(manifest_path=m_path, corpus_dir=corpus_dir, quiet=True)

    after_state = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in corpus_dir.iterdir()}
    assert before_state == after_state
    assert set(before_state.keys()) == {"file1.txt", "file2.json"}


def test_09_cli_execution_and_report_export(tmp_path: Path):
    """The CLI entrypoint must accept arguments, run benchmark, and write output JSON report."""
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "test.txt").write_bytes(b"CLI test sample\n")

    manifest_data = {
        "manifest_version": "1.0.0",
        "corpus_name": "cli-test",
        "samples": [{"sample_id": "cli-01", "file_path": "test.txt", "format": "txt"}],
    }
    m_path = tmp_path / "manifest.json"
    m_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    report_path = tmp_path / "out" / "realworld_report.json"

    ret = main([
        "--manifest", str(m_path),
        "--corpus-dir", str(corpus_dir),
        "--output-report", str(report_path),
        "--quiet",
    ])
    assert ret == 0
    assert report_path.exists()

    report_data = json.loads(report_path.read_text(encoding="utf-8"))
    assert report_data["report_version"] == "1.0.0"
    assert report_data["summary"]["total_samples"] == 1
    assert report_data["summary"]["processed_samples"] == 1
