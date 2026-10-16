"""
test_cli.py — Comprehensive test suite for Recoverix CLI Tooling (Milestone 8).

Validates:
1. CLI help flag (--help, -h) exits 0 and prints usage instructions.
2. Invalid command and missing arguments exit with code 2.
3. Successful recovery of supported files (e.g. JSON) exits 0 and writes recovered_<name>.
4. Damaged PDF recovery via xref reconstruction exits 0 and produces valid PDF file.
5. Unrecoverable / corrupt input exits 1 and produces no output file.
6. Non-existent input path and directory input exit with code 2.
7. Output directory creation (auto-create if missing) and rejection if output path is a file.
8. Refusal to overwrite existing output files (exits 2).
9. Path traversal protection on input filename and output path resolution.
10. Formatted JSON output (--json) includes accurate V/R/M metrics and statuses.
11. Bounded reading: 0-byte file and >5 MiB file are rejected with exit code 2.
12. Standalone subprocess execution without FastAPI or Uvicorn server.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from backend.cli import (
    EXIT_SUCCESS,
    EXIT_UNRECOVERABLE,
    EXIT_ERROR,
    read_input_file_bounded,
    format_console_summary,
    run_recover_command,
    main,
)
from tests.test_pdf_recovery import build_minimal_pdf


# ── Test 1: Help Flag ────────────────────────────────────────────────────────

def test_cli_help(capsys):
    """Test --help and -h exit with code 0 and show usage information."""
    ret_help = main(["--help"])
    assert ret_help == EXIT_SUCCESS
    captured = capsys.readouterr()
    assert "recoverix" in captured.out
    assert "recover" in captured.out

    ret_h = main(["-h"])
    assert ret_h == EXIT_SUCCESS


# ── Test 2: Invalid Arguments & Commands ─────────────────────────────────────

def test_cli_invalid_command_or_args(capsys):
    """Test missing or invalid commands return or exit with code 2."""
    # No args
    ret_empty = main([])
    assert ret_empty == EXIT_ERROR

    # Invalid subcommand
    with pytest.raises(SystemExit) as exc_info:
        main(["invalid_command"])
    assert exc_info.value.code == EXIT_ERROR

    # Subcommand missing required arguments
    with pytest.raises(SystemExit) as exc_info:
        main(["recover"])
    assert exc_info.value.code == EXIT_ERROR

    # Subcommand missing --out
    with pytest.raises(SystemExit) as exc_info:
        main(["recover", "some_file.json"])
    assert exc_info.value.code == EXIT_ERROR


# ── Test 3: Successful Recovery of Supported File ────────────────────────────

def test_cli_recover_supported_json(tmp_path: Path):
    """Test full recovery of valid JSON file exits 0 and writes recovered_<filename>."""
    evidence_content = b'{"case_id": "REC-101", "investigator": "Forensics", "active": true}'
    in_file = tmp_path / "case_data.json"
    in_file.write_bytes(evidence_content)

    out_dir = tmp_path / "recovered_output"

    out_buf = io.StringIO()
    err_buf = io.StringIO()

    exit_code = run_recover_command(
        input_path_str=str(in_file),
        output_dir_str=str(out_dir),
        as_json=False,
        stdout_stream=out_buf,
        stderr_stream=err_buf,
    )

    assert exit_code == EXIT_SUCCESS
    out_text = out_buf.getvalue()
    assert "RECOVERIX — FORENSIC FILE RECOVERY SUMMARY" in out_text
    assert "FULLY_RECOVERED" in out_text
    assert "json" in out_text.lower()

    # Verify output file exists
    expected_out_file = out_dir / "recovered_case_data.json"
    assert expected_out_file.exists()
    assert expected_out_file.read_bytes() == evidence_content


# ── Test 4: Damaged PDF Recovery ─────────────────────────────────────────────

def test_cli_recover_damaged_pdf(tmp_path: Path):
    """Test damaged-xref PDF is reconstructed, validated, and saved (PARTIALLY_RECOVERED)."""
    pdf_bytes = build_minimal_pdf()
    corrupted_pdf = pdf_bytes.replace(b"xref", b"xxxx")

    in_file = tmp_path / "damaged.pdf"
    in_file.write_bytes(corrupted_pdf)

    out_dir = tmp_path / "pdf_out"

    out_buf = io.StringIO()
    err_buf = io.StringIO()

    exit_code = run_recover_command(
        input_path_str=str(in_file),
        output_dir_str=str(out_dir),
        as_json=False,
        stdout_stream=out_buf,
        stderr_stream=err_buf,
    )

    assert exit_code == EXIT_SUCCESS
    out_text = out_buf.getvalue()
    assert "PARTIALLY_RECOVERED" in out_text
    assert "pdf" in out_text.lower()
    assert "Reconstructed Bytes" in out_text

    # Verify recovered file exists and has valid PDF structure
    out_file = out_dir / "recovered_damaged.pdf"
    assert out_file.exists()
    recovered_data = out_file.read_bytes()
    assert recovered_data.startswith(b"%PDF-")
    assert b"%%EOF" in recovered_data
    assert b"xref" in recovered_data  # reconstructed xref table present


# ── Test 5: Unrecoverable Input ──────────────────────────────────────────────

def test_cli_unrecoverable_input(tmp_path: Path):
    """Test unrecoverable / corrupted data exits 1 and writes no file."""
    # Binary noise with no discernible file signature
    noise_content = bytes(range(256)) * 4
    in_file = tmp_path / "corrupt.bin"
    in_file.write_bytes(noise_content)

    out_dir = tmp_path / "out"

    out_buf = io.StringIO()
    err_buf = io.StringIO()

    exit_code = run_recover_command(
        input_path_str=str(in_file),
        output_dir_str=str(out_dir),
        as_json=False,
        stdout_stream=out_buf,
        stderr_stream=err_buf,
    )

    assert exit_code == EXIT_UNRECOVERABLE
    out_text = out_buf.getvalue()
    assert "UNRECOVERABLE" in out_text
    assert "None (no valid recoverable artifact produced)" in out_text

    # Ensure no file was written to output dir
    assert list(out_dir.glob("*")) == []


def test_cli_corrupted_input_rejected_no_file(tmp_path: Path):
    """Test corrupted input (status=CORRUPTED, val=FAILED) produces no output file and exits 1."""
    from benchmark.run_baseline import build_ground_truth_manifest

    gt_manifest, evidence_bytes = build_ground_truth_manifest(seed=42)
    art_corr = next(a for a in gt_manifest.artifacts if a.artifact_id == "art-corrupted-01")
    p = art_corr.placements[0]
    corrupted_data = evidence_bytes[p.evidence_offset : p.evidence_offset + p.evidence_length]

    in_file = tmp_path / "corrupted_text.txt"
    in_file.write_bytes(corrupted_data)

    out_dir = tmp_path / "corrupt_out"
    out_buf = io.StringIO()
    err_buf = io.StringIO()

    exit_code = run_recover_command(
        input_path_str=str(in_file),
        output_dir_str=str(out_dir),
        as_json=False,
        stdout_stream=out_buf,
        stderr_stream=err_buf,
    )

    assert exit_code == EXIT_UNRECOVERABLE
    out_text = out_buf.getvalue()
    assert "CORRUPTED" in out_text
    assert "FAILED" in out_text
    assert "None (no valid recoverable artifact produced)" in out_text
    # Invariant: Never write corrupted unvalidated output to disk
    assert list(out_dir.glob("*")) == []


# ── Test 6: Invalid and Missing Input Paths ──────────────────────────────────

def test_cli_missing_input_file(tmp_path: Path):
    """Test non-existent input file returns EXIT_ERROR."""
    out_dir = tmp_path / "out"
    missing_file = tmp_path / "does_not_exist.txt"

    err_buf = io.StringIO()
    exit_code = run_recover_command(
        input_path_str=str(missing_file),
        output_dir_str=str(out_dir),
        stderr_stream=err_buf,
    )

    assert exit_code == EXIT_ERROR
    assert "Input file not found" in err_buf.getvalue()


def test_cli_directory_as_input_file(tmp_path: Path):
    """Test passing a directory as input file returns EXIT_ERROR."""
    dir_input = tmp_path / "some_dir"
    dir_input.mkdir()
    out_dir = tmp_path / "out"

    err_buf = io.StringIO()
    exit_code = run_recover_command(
        input_path_str=str(dir_input),
        output_dir_str=str(out_dir),
        stderr_stream=err_buf,
    )

    assert exit_code == EXIT_ERROR
    assert "is a directory" in err_buf.getvalue()


# ── Test 7: Output Directory Creation and Validation ─────────────────────────

def test_cli_creates_nested_output_directory(tmp_path: Path):
    """Test CLI auto-creates missing nested output directory."""
    in_file = tmp_path / "data.json"
    in_file.write_bytes(b'{"key": "val"}')

    nested_out_dir = tmp_path / "deeply" / "nested" / "output_dir"
    assert not nested_out_dir.exists()

    exit_code = run_recover_command(
        input_path_str=str(in_file),
        output_dir_str=str(nested_out_dir),
    )

    assert exit_code == EXIT_SUCCESS
    assert nested_out_dir.is_dir()
    assert (nested_out_dir / "recovered_data.json").exists()


def test_cli_rejects_output_dir_when_file(tmp_path: Path):
    """Test CLI returns EXIT_ERROR if output_dir is an existing regular file."""
    in_file = tmp_path / "data.json"
    in_file.write_bytes(b'{"key": "val"}')

    out_file_as_dir = tmp_path / "existing_file.txt"
    out_file_as_dir.write_text("i am a file")

    err_buf = io.StringIO()
    exit_code = run_recover_command(
        input_path_str=str(in_file),
        output_dir_str=str(out_file_as_dir),
        stderr_stream=err_buf,
    )

    assert exit_code == EXIT_ERROR
    assert "not a directory" in err_buf.getvalue()


# ── Test 8: Non-Overwrite Policy ─────────────────────────────────────────────

def test_cli_refuse_overwrite_existing_file(tmp_path: Path):
    """Test CLI refuses to overwrite existing output file and returns EXIT_ERROR."""
    in_file = tmp_path / "document.json"
    in_file.write_bytes(b'{"evidence": 123}')

    out_dir = tmp_path / "out"
    out_dir.mkdir()

    # Pre-create the output file with distinct content
    pre_existing = out_dir / "recovered_document.json"
    original_pre_existing_data = b"DO_NOT_OVERWRITE_ME"
    pre_existing.write_bytes(original_pre_existing_data)

    err_buf = io.StringIO()
    exit_code = run_recover_command(
        input_path_str=str(in_file),
        output_dir_str=str(out_dir),
        stderr_stream=err_buf,
    )

    assert exit_code == EXIT_ERROR
    assert "already exists" in err_buf.getvalue()
    assert "Refusing to overwrite" in err_buf.getvalue()

    # Verify original file content was preserved
    assert pre_existing.read_bytes() == original_pre_existing_data


# ── Test 9: Safe Basename and Path Traversal Protection ───────────────────────

def test_cli_safe_basename_path_traversal(tmp_path: Path):
    """Test CLI strips directory traversal from input file path."""
    sub_folder = tmp_path / "subdir"
    sub_folder.mkdir()
    in_file = sub_folder / "evidence.json"
    in_file.write_bytes(b'{"safe": true}')

    out_dir = tmp_path / "out"

    exit_code = run_recover_command(
        input_path_str=str(in_file),
        output_dir_str=str(out_dir),
    )

    assert exit_code == EXIT_SUCCESS
    # Output file must be in out_dir directly as recovered_evidence.json
    expected_path = out_dir / "recovered_evidence.json"
    assert expected_path.exists()
    assert expected_path.parent.resolve() == out_dir.resolve()


# ── Test 10: JSON Output Reporting ───────────────────────────────────────────

def test_cli_json_output_metrics(tmp_path: Path):
    """Test --json flag produces structured JSON with accurate V/R/M metrics."""
    json_bytes = b'{"status": "ok", "items": [1, 2, 3]}'
    in_file = tmp_path / "metrics.json"
    in_file.write_bytes(json_bytes)

    out_dir = tmp_path / "json_out"
    out_buf = io.StringIO()

    exit_code = run_recover_command(
        input_path_str=str(in_file),
        output_dir_str=str(out_dir),
        as_json=True,
        stdout_stream=out_buf,
    )

    assert exit_code == EXIT_SUCCESS
    data = json.loads(out_buf.getvalue())

    assert data["input_filename"] == "metrics.json"
    assert data["input_size_bytes"] == len(json_bytes)
    assert data["format"] == "json"
    assert data["status"] == "FULLY_RECOVERED"
    assert data["validation_status"] == "PASSED"
    assert data["verified_bytes"] == len(json_bytes)
    assert data["reconstructed_bytes"] == 0
    assert data["missing_bytes"] == 0
    assert data["is_recoverable"] is True
    assert data["output_path"] == str(out_dir / "recovered_metrics.json")
    assert data["output_size_bytes"] == len(json_bytes)


def test_cli_partially_recovered_json_metrics(tmp_path: Path):
    """Test --json flag on partially recovered damaged PDF reflects accurate R>0 and PARTIALLY_RECOVERED."""
    pdf_bytes = build_minimal_pdf()
    corrupted_pdf = pdf_bytes.replace(b"xref", b"xxxx")

    in_file = tmp_path / "damaged_doc.pdf"
    in_file.write_bytes(corrupted_pdf)

    out_dir = tmp_path / "pdf_json_out"
    out_buf = io.StringIO()

    exit_code = run_recover_command(
        input_path_str=str(in_file),
        output_dir_str=str(out_dir),
        as_json=True,
        stdout_stream=out_buf,
    )

    assert exit_code == EXIT_SUCCESS
    data = json.loads(out_buf.getvalue())

    assert data["input_filename"] == "damaged_doc.pdf"
    assert data["format"] == "pdf"
    assert data["status"] == "PARTIALLY_RECOVERED"
    assert data["validation_status"] == "PASSED"
    assert data["verified_bytes"] > 0
    assert data["reconstructed_bytes"] > 0
    assert data["is_recoverable"] is True
    assert data["output_path"] == str(out_dir / "recovered_damaged_doc.pdf")
    assert Path(data["output_path"]).exists()
    assert Path(data["output_path"]).read_bytes().startswith(b"%PDF-")


# ── Test 11: Bounded File Reading Limits ─────────────────────────────────────

def test_cli_rejects_empty_file(tmp_path: Path):
    """Test 0-byte file is rejected with EXIT_ERROR."""
    empty_file = tmp_path / "empty.json"
    empty_file.write_bytes(b"")
    out_dir = tmp_path / "out"

    err_buf = io.StringIO()
    exit_code = run_recover_command(
        input_path_str=str(empty_file),
        output_dir_str=str(out_dir),
        stderr_stream=err_buf,
    )

    assert exit_code == EXIT_ERROR
    assert "empty (0 bytes)" in err_buf.getvalue()


def test_cli_rejects_file_exceeding_max_size(tmp_path: Path):
    """Test file larger than 5 MiB is rejected with EXIT_ERROR."""
    oversized_file = tmp_path / "large.dat"
    # Create 5 MiB + 10 bytes file without loading into memory
    with open(oversized_file, "wb") as f:
        f.seek(5 * 1024 * 1024 + 10 - 1)
        f.write(b"\0")

    out_dir = tmp_path / "out"
    err_buf = io.StringIO()
    exit_code = run_recover_command(
        input_path_str=str(oversized_file),
        output_dir_str=str(out_dir),
        stderr_stream=err_buf,
    )

    assert exit_code == EXIT_ERROR
    assert "exceeds maximum limit of 5 MiB" in err_buf.getvalue()


# ── Test 12: Standalone Subprocess Invocation ─────────────────────────────────

def test_cli_subprocess_invocation(tmp_path: Path):
    """Test python3 -m backend.cli works standalone via subprocess without server."""
    in_file = tmp_path / "input.json"
    in_file.write_bytes(b'{"recovered": "standalone"}')
    out_dir = tmp_path / "sub_out"

    cmd = [
        sys.executable,
        "-m",
        "backend.cli",
        "recover",
        str(in_file),
        "--out",
        str(out_dir),
    ]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )

    assert proc.returncode == 0
    assert "RECOVERIX — FORENSIC FILE RECOVERY SUMMARY" in proc.stdout
    assert (out_dir / "recovered_input.json").exists()
    assert (out_dir / "recovered_input.json").read_bytes() == b'{"recovered": "standalone"}'
