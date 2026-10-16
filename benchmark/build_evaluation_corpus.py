"""benchmark/build_evaluation_corpus.py — Deterministic Evaluation Corpus Builder.

Builds a reproducible, self-contained evaluation corpus for Recoverix (Milestone 13).
Covers the 4 supported formats (PDF, JSON, CSV, TXT) across intact, truncated,
recoverable structural damage, unrecoverable damage, and negative control categories.

Licensing: All sample texts and structures are original, synthetic artifacts
released under the project MIT License.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List


def generate_corpus(target_dir: Path | str) -> Path:
    """Generate the deterministic evaluation corpus and manifest."""
    corpus_root = Path(target_dir).resolve()
    files_dir = corpus_root / "files"
    files_dir.mkdir(parents=True, exist_ok=True)

    samples: List[Dict[str, Any]] = []

    def register(
        filename: str,
        data: bytes,
        sample_id: str,
        fmt: str | None,
        category: str,
        description: str,
        expected_detection: bool | None = None,
        expected_status: str | None = None,
        original_sha256: str | None = None,
        expected_v: int | None = None,
        expected_r: int | None = None,
        expected_m: int | None = None,
        provenance: str = "Synthetic controlled fixture created for Milestone 13",
    ):
        file_path = files_dir / filename
        file_path.write_bytes(data)
        rel_path = f"files/{filename}"

        sample_record: Dict[str, Any] = {
            "sample_id": sample_id,
            "file_path": rel_path,
            "format": fmt,
            "corruption_category": category,
            "description": description,
            "expected_detection": expected_detection,
            "expected_status": expected_status,
            "original_sha256": original_sha256,
            "license": "MIT",
            "provenance_notes": provenance,
        }
        if expected_v is not None:
            sample_record["expected_verified_bytes"] = expected_v
        if expected_r is not None:
            sample_record["expected_reconstructed_bytes"] = expected_r
        if expected_m is not None:
            sample_record["expected_missing_bytes"] = expected_m

        samples.append(sample_record)

    # ── 1. PDF SAMPLES ────────────────────────────────────────────────────────
    # 1a. Clean intact single-page PDF with valid xref pointing to offset 162
    pdf_clean = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n0000000108 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n162\n%%EOF\n"
    )
    register(
        filename="pdf_01_intact.pdf",
        data=pdf_clean,
        sample_id="pdf-intact",
        fmt="pdf",
        category="intact",
        description="Complete, valid PDF with intact object hierarchy and verified xref table",
        expected_detection=True,
        expected_status="FULLY_RECOVERED",
        original_sha256=hashlib.sha256(pdf_clean).hexdigest(),
        expected_v=len(pdf_clean),
        expected_r=0,
        expected_m=0,
    )

    # 1b. PDF with stripped xref and trailer (recoverable via reconstruct_pdf_xref)
    pdf_missing_xref = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
    )
    register(
        filename="pdf_02_missing_xref.pdf",
        data=pdf_missing_xref,
        sample_id="pdf-missing-xref",
        fmt="pdf",
        category="recoverable_structural_damage",
        description="PDF with intact object tree but completely missing xref table and trailer",
        expected_detection=True,
        expected_status="PARTIALLY_RECOVERED",
        expected_v=162,
        expected_r=143,
        expected_m=0,
    )

    # 1c. PDF with corrupted / missing catalog object (unrecoverable broken tree)
    pdf_corrupt_catalog = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /CorruptedNoCatalog /Payload 12345 >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
    )
    register(
        filename="pdf_03_corrupted_catalog.pdf",
        data=pdf_corrupt_catalog,
        sample_id="pdf-corrupted-catalog",
        fmt="pdf",
        category="unrecoverable_damage",
        description="PDF with unrecoverable Catalog root object; object graph cannot be traversed",
        expected_detection=True,
        expected_status="UNRECOVERABLE",
    )

    # ── 2. JSON SAMPLES ───────────────────────────────────────────────────────
    # 2a. Intact clean JSON
    json_clean = b'{"case_id": "REC-2026", "active": true, "sensors": ["temp", "pressure"], "count": 42}'
    register(
        filename="json_01_intact.json",
        data=json_clean,
        sample_id="json-intact",
        fmt="json",
        category="intact",
        description="Complete, valid JSON document with key-value pairs and array elements",
        expected_detection=True,
        expected_status="FULLY_RECOVERED",
        original_sha256=hashlib.sha256(json_clean).hexdigest(),
        expected_v=len(json_clean),
        expected_r=0,
        expected_m=0,
    )

    # 2b. Truncated JSON without closing brackets (repaired deterministically)
    json_trunc = b'{"case_id": "REC-2026", "active": true, "sensors": ["temp", "pressure"'
    register(
        filename="json_02_truncated_closable.json",
        data=json_trunc,
        sample_id="json-truncated-closable",
        fmt="json",
        category="recoverable_structural_damage",
        description="JSON truncated before closing array and object delimiters; reconstructed via delimiter balance",
        expected_detection=True,
        expected_status="PARTIALLY_RECOVERED",
        expected_v=len(json_trunc),
        expected_r=2,
        expected_m=0,
    )

    # 2c. Unrecoverable syntax corruption
    json_bad = b'{"case_id": ::: invalid unrecoverable syntax :::}'
    register(
        filename="json_03_corrupted_syntax.json",
        data=json_bad,
        sample_id="json-corrupted-syntax",
        fmt="json",
        category="unrecoverable_damage",
        description="JSON with severe syntax corruption that cannot form a valid parser tree",
        expected_status="UNRECOVERABLE",
    )

    # ── 3. CSV SAMPLES ────────────────────────────────────────────────────────
    # 3a. Intact CSV
    csv_clean = (
        b"id,timestamp,sensor,value\n"
        b"1,2026-10-16T00:00:00Z,temp_1,22.4\n"
        b"2,2026-10-16T00:01:00Z,temp_2,23.1\n"
        b"3,2026-10-16T00:02:00Z,temp_3,21.9\n"
    )
    register(
        filename="csv_01_intact.csv",
        data=csv_clean,
        sample_id="csv-intact",
        fmt="csv",
        category="intact",
        description="Rectangular CSV table with consistent header and numeric/timestamp columns",
        expected_status="FULLY_RECOVERED",
        original_sha256=hashlib.sha256(csv_clean).hexdigest(),
        expected_v=len(csv_clean),
        expected_r=0,
        expected_m=0,
    )

    # 3b. Truncated CSV (incomplete last row dropped, complete rows preserved)
    csv_trunc = (
        b"id,timestamp,sensor,value\n"
        b"1,2026-10-16T00:00:00Z,temp_1,22.4\n"
        b"2,2026-10-16T00:01:00Z,temp_"
    )
    register(
        filename="csv_02_truncated.csv",
        data=csv_trunc,
        sample_id="csv-truncated",
        fmt="csv",
        category="truncated",
        description="CSV with truncated trailing row; engine isolates damaged sector and validates complete rows",
        expected_status="PARTIALLY_RECOVERED",
    )

    # 3c. Corrupted CSV delimiter (inconsistent columns in middle row)
    csv_corrupt = (
        b"id,timestamp,sensor,value\n"
        b"1,2026-10-16T00:00:00Z,temp_1,22.4\n"
        b"2,corrupted_delimiter_without_commas\n"
        b"3,2026-10-16T00:02:00Z,temp_3,21.9\n"
    )
    register(
        filename="csv_03_corrupted.csv",
        data=csv_corrupt,
        sample_id="csv-corrupted",
        fmt="csv",
        category="controlled_corruption",
        description="CSV with mid-file delimiter corruption and column count mismatch",
        expected_status="PARTIALLY_RECOVERED",
    )

    # ── 4. TXT SAMPLES ────────────────────────────────────────────────────────
    # 4a. Intact TXT
    txt_clean = (
        b"Recoverix deterministic evidence recovery validation report.\n"
        b"Verified evidence is preserved without speculative prediction.\n"
        b"Reconstructed structures are separated explicitly.\n"
    )
    register(
        filename="txt_01_intact.txt",
        data=txt_clean,
        sample_id="txt-intact",
        fmt="txt",
        category="intact",
        description="UTF-8 plain text document with uniform lines and newlines",
        expected_status="FULLY_RECOVERED",
        original_sha256=hashlib.sha256(txt_clean).hexdigest(),
        expected_v=len(txt_clean),
        expected_r=0,
        expected_m=0,
    )

    # 4b. Truncated TXT
    txt_trunc = (
        b"Recoverix deterministic evidence recovery validation report.\n"
        b"Verified evidence is preserved without speculative "
    )
    register(
        filename="txt_02_truncated.txt",
        data=txt_trunc,
        sample_id="txt-truncated",
        fmt="txt",
        category="truncated",
        description="Plain text truncated mid-sentence without trailing newline",
        expected_status="PARTIALLY_RECOVERED",
    )

    # 4c. TXT with controlled null-byte sector corruption
    txt_corrupt = (
        b"Recoverix deterministic evidence recovery validation report.\n"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n"
        b"Reconstructed structures are separated explicitly.\n"
    )
    register(
        filename="txt_03_corrupted.txt",
        data=txt_corrupt,
        sample_id="txt-corrupted",
        fmt="txt",
        category="controlled_corruption",
        description="Plain text containing a zeroed-out corruption sector between valid lines",
        expected_status="PARTIALLY_RECOVERED",
    )

    # ── 5. NEGATIVE CONTROLS & UNSUPPORTED FORMATS ────────────────────────────
    # 5a. Pure pseudo-random noise (no valid headers or format grammar)
    noise_bytes = bytes((i * 47 + 29) % 256 for i in range(2048))
    register(
        filename="control_01_noise.bin",
        data=noise_bytes,
        sample_id="control-noise",
        fmt=None,
        category="negative_control",
        description="Deterministic high-entropy pseudo-random noise with no valid signatures",
        expected_detection=False,
        expected_status="UNRECOVERABLE",
    )

    # 5b. Misleading PDF magic header followed by immediate binary noise
    misleading_pdf = b"%PDF-1.4\n" + bytes((i * 19 + 7) % 256 for i in range(512))
    register(
        filename="control_02_misleading_pdf.bin",
        data=misleading_pdf,
        sample_id="control-misleading-header",
        fmt="pdf",
        category="negative_control",
        description="Spurious PDF header followed immediately by high-entropy noise with no objects",
        expected_detection=True,
        expected_status="UNRECOVERABLE",
    )

    # 5c. Unsupported ZIP archive
    zip_bytes = b"PK\x03\x04\x14\x00\x00\x00\x08\x00\x00\x00\x00\x00" + b"\x00" * 32
    register(
        filename="control_03_unsupported.zip",
        data=zip_bytes,
        sample_id="control-unsupported-zip",
        fmt=None,
        category="unsupported_format",
        description="PKZip archive container, representing an unsupported format handled without crash",
        expected_detection=False,
        expected_status="UNRECOVERABLE",
    )

    manifest_data = {
        "manifest_version": "1.0.0",
        "corpus_name": "recoverix-deterministic-evaluation-corpus",
        "description": "Deterministic ground-truth evaluation corpus for Recoverix Milestone 13",
        "samples": samples,
    }

    manifest_path = corpus_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    return manifest_path


if __name__ == "__main__":
    out = generate_corpus(Path(__file__).parent / "evaluation_corpus")
    print(f"Corpus generated successfully: {out}")
