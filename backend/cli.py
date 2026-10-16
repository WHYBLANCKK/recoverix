"""
cli.py — Standalone command-line interface for Recoverix file recovery.

Provides deterministic forensic carving, structural reconstruction,
and validation without requiring FastAPI, Uvicorn, or the web frontend.

Usage:
    python3 -m backend.cli --help
    python3 -m backend.cli recover INPUT_FILE --out OUTPUT_DIR
    python3 -m backend.cli recover INPUT_FILE -o OUTPUT_DIR [--json]

Exit Codes:
    0 — Recovery successful; valid artifact recovered and saved to output directory.
    1 — Evidence unrecoverable or corrupted; no valid artifact could be produced.
    2 — Operational or usage error (file not found, permission denied, size exceeded,
        output file already exists, invalid arguments).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from backend.app.store import MAX_EVIDENCE_SIZE
from backend.app.recovery.tracer import execute_traced_recovery
from backend.app.recovery.adapter import extract_recovered_bytes

EXIT_SUCCESS = 0
EXIT_UNRECOVERABLE = 1
EXIT_ERROR = 2


def read_input_file_bounded(file_path: Path, max_size: int = MAX_EVIDENCE_SIZE) -> bytes:
    """Read an evidence file with strict boundary, type, and size checks.

    Args:
        file_path: Path to the input file.
        max_size: Maximum allowed file size in bytes (default 5 MiB).

    Raises:
        FileNotFoundError: If the file does not exist.
        IsADirectoryError: If the path is a directory.
        ValueError: If the file is empty or exceeds max_size.
        PermissionError: If the file cannot be opened due to permissions.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")

    if file_path.is_dir():
        raise IsADirectoryError(f"Input path is a directory, not a regular file: {file_path}")

    try:
        st = file_path.stat()
    except OSError as err:
        raise PermissionError(f"Cannot access input file: {err}")

    if st.st_size == 0:
        raise ValueError(f"Input file is empty (0 bytes): {file_path}")

    if st.st_size > max_size:
        raise ValueError(
            f"Input file size ({st.st_size:,} bytes) exceeds maximum limit of "
            f"5 MiB ({max_size:,} bytes): {file_path}"
        )

    # Read bounded chunk to prevent memory exhaustion even under concurrent growth
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_size + 1)
    except OSError as err:
        raise PermissionError(f"Cannot read input file: {err}")

    if len(data) > max_size:
        raise ValueError(
            f"Input file exceeds maximum limit of 5 MiB ({max_size:,} bytes): {file_path}"
        )
    if len(data) == 0:
        raise ValueError(f"Input file is empty (0 bytes): {file_path}")

    return data


def format_console_summary(report: Dict[str, Any]) -> str:
    """Render a human-readable forensic recovery summary table."""
    border = "═" * 72
    divider = "─" * 72

    lines = [
        border,
        "  RECOVERIX — FORENSIC FILE RECOVERY SUMMARY",
        border,
        f"  Input File         : {report['input_filename']} ({report['input_size_bytes']:,} bytes)",
        f"  Detected Format    : {report['format']}",
        f"  Recovery Status    : {report['status']}",
        f"  Validation Status  : {report['validation_status']}",
        f"  Verified Bytes     : {report['verified_bytes']:,} bytes (intact evidence bytes)",
        f"  Reconstructed Bytes: {report['reconstructed_bytes']:,} bytes (structural repair bytes)",
        f"  Missing Bytes      : {report['missing_bytes']:,} bytes (unrecovered damage)",
        f"  Reconstruction     : {report['reconstruction_method']}",
    ]

    if report.get("output_path"):
        out_size = report.get("output_size_bytes", 0)
        lines.append(f"  Output File        : {report['output_path']} ({out_size:,} bytes written)")
    else:
        lines.append("  Output File        : None (no valid recoverable artifact produced)")

    lines.append(divider)

    # Notices & Limitations
    if report["status"] == "FULLY_RECOVERED":
        lines.append("  Notice: Artifact fully recovered. All bytes verified with 100% structural validity.")
    elif report["status"] == "PARTIALLY_RECOVERED":
        lines.append(
            "  Notice: Artifact was partially recovered. Reconstructed or missing bytes exist;\n"
            "  reconstructed bytes represent structural repairs (e.g. delimiters, xref tables),\n"
            "  not original verified content. Inspect output before forensic reliance."
        )
    else:
        err_msg = report.get("error_message") or "File is unrecoverable from available evidence."
        lines.append(f"  Notice: Recovery failed ({report['status']}). {err_msg}")

    if report.get("validation_errors"):
        lines.append(divider)
        lines.append("  Structural Validation Errors:")
        for err in report["validation_errors"]:
            lines.append(f"    ! {err}")

    lines.append(border)
    return "\n".join(lines)


def run_recover_command(
    input_path_str: str,
    output_dir_str: str,
    as_json: bool = False,
    stdout_stream=sys.stdout,
    stderr_stream=sys.stderr,
) -> int:
    """Execute recovery of a single damaged file from CLI arguments.

    Returns:
        Exit code: 0 (success), 1 (unrecoverable), 2 (error).
    """
    input_path = Path(input_path_str)
    output_dir = Path(output_dir_str)

    # 1. Validate and read input file
    try:
        content = read_input_file_bounded(input_path)
    except (FileNotFoundError, IsADirectoryError, ValueError, PermissionError) as err:
        print(f"Error: {err}", file=stderr_stream)
        return EXIT_ERROR
    except Exception as err:
        print(f"Error reading input file: {err}", file=stderr_stream)
        return EXIT_ERROR

    # 2. Validate output directory
    try:
        if output_dir.exists() and not output_dir.is_dir():
            print(f"Error: Output destination exists and is not a directory: {output_dir}", file=stderr_stream)
            return EXIT_ERROR
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        print(f"Error preparing output directory '{output_dir}': {err}", file=stderr_stream)
        return EXIT_ERROR

    # 3. Execute deterministic recovery
    orig_filename = input_path.name
    try:
        recovery_run = execute_traced_recovery(
            filename=orig_filename,
            content=content,
        )
    except Exception as err:
        print(f"Error during recovery execution: {err}", file=stderr_stream)
        return EXIT_ERROR

    # 4. Extract results
    status_val = recovery_run.status
    fmt = recovery_run.format
    ver_bytes = recovery_run.total_verified_bytes
    rec_byte_cnt = recovery_run.total_reconstructed_bytes
    miss_bytes = recovery_run.total_missing_bytes
    method = (
        recovery_run.reconstruction_steps[0].method
        if recovery_run.reconstruction_steps
        else "NONE"
    )

    val_status = "PASSED"
    val_errors = []
    if recovery_run.validation:
        val_status = "PASSED" if recovery_run.validation.get("valid", False) else "FAILED"
        val_errors = recovery_run.validation.get("errors", [])
    elif status_val in ("UNRECOVERABLE", "CORRUPTED"):
        val_status = "FAILED"

    recovered_content = extract_recovered_bytes(recovery_run)
    is_downloadable = (status_val != "UNRECOVERABLE") and (len(recovered_content) > 0)

    # 5. Safe output path resolution
    output_file_path: Optional[Path] = None
    if is_downloadable:
        # Determine safe output filename: recovered_<input_filename>
        # Sanitize against path traversal: use strictly the basename
        safe_base_name = f"recovered_{orig_filename}"
        target_path = (output_dir / safe_base_name).resolve()

        # Enforce that output remains inside output_dir
        resolved_out_dir = output_dir.resolve()
        try:
            target_path.relative_to(resolved_out_dir)
        except ValueError:
            print(f"Error: Path traversal detected in output file name: {safe_base_name}", file=stderr_stream)
            return EXIT_ERROR

        # Enforce non-overwrite policy
        if target_path.exists():
            print(f"Error: Output file already exists: {target_path}. Refusing to overwrite.", file=stderr_stream)
            return EXIT_ERROR

        # Write output file safely
        try:
            target_path.write_bytes(recovered_content)
            output_file_path = target_path
        except OSError as err:
            print(f"Error writing recovered file to '{target_path}': {err}", file=stderr_stream)
            return EXIT_ERROR

    # 6. Build report
    report: Dict[str, Any] = {
        "input_filename": orig_filename,
        "input_size_bytes": len(content),
        "format": fmt,
        "status": status_val,
        "validation_status": val_status,
        "verified_bytes": ver_bytes,
        "reconstructed_bytes": rec_byte_cnt,
        "missing_bytes": miss_bytes,
        "reconstruction_method": method,
        "is_recoverable": is_downloadable,
        "output_path": str(output_file_path) if output_file_path else None,
        "output_size_bytes": len(recovered_content) if output_file_path else 0,
        "validation_errors": val_errors,
        "confidence_score": float(recovery_run.confidence.get("total", 0.0)),
    }

    if as_json:
        print(json.dumps(report, indent=2), file=stdout_stream)
    else:
        print(format_console_summary(report), file=stdout_stream)

    # 7. Map exit code
    if is_downloadable and status_val in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED"):
        return EXIT_SUCCESS
    else:
        return EXIT_UNRECOVERABLE


def build_cli_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="recoverix",
        description="Recoverix — Deterministic Digital Evidence Recovery and Reconstruction CLI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 -m backend.cli recover damaged_doc.pdf --out ./recovered\n"
            "  python3 -m backend.cli recover corrupted_data.json -o ./output --json\n\n"
            "Exit Codes:\n"
            "  0 — Recovery succeeded and file was saved.\n"
            "  1 — Evidence is unrecoverable or corrupted (no file produced).\n"
            "  2 — Operational or usage error.\n"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    recover_parser = subparsers.add_parser(
        "recover",
        help="Carve, reconstruct, and validate a damaged evidence file",
        description="Execute deterministic recovery on a damaged input file.",
    )
    recover_parser.add_argument(
        "input_file",
        type=str,
        help="Path to damaged evidence file (max 5 MiB)",
    )
    recover_parser.add_argument(
        "-o",
        "--out",
        "--output-dir",
        required=True,
        type=str,
        dest="output_dir",
        help="Directory where recovered output file will be stored",
    )
    recover_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output structured recovery summary as JSON",
    )

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint."""
    if argv is None:
        argv = sys.argv[1:]

    parser = build_cli_parser()

    if not argv or argv == ["-h"] or argv == ["--help"]:
        parser.print_help()
        return EXIT_SUCCESS if argv else EXIT_ERROR

    # Convenience fallback: if the first argument is not a known subcommand or help flag,
    # and ends up looking like an input file with --out, route to 'recover'
    if argv and argv[0] not in ("recover", "-h", "--help"):
        if any(flag in argv for flag in ("-o", "--out", "--output-dir")):
            argv = ["recover"] + argv

    args = parser.parse_args(argv)

    if args.command == "recover":
        return run_recover_command(
            input_path_str=args.input_file,
            output_dir_str=args.output_dir,
            as_json=args.as_json,
        )

    parser.print_help(file=sys.stderr)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
