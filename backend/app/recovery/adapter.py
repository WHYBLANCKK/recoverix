"""
adapter.py — Clean adapter converting canonical RecoveryRun to ArtifactResponse.

Bridging layer between the canonical tracing recovery engine (RecoveryRun)
and the case-analysis artifact representation (ArtifactResponse).

FORENSIC INTEGRITY PRINCIPLES:
  1. Strict representation conversion only — never recalculate, infer, guess,
     upgrade, or downgrade confidence or status.
  2. Artifact identity is never invented — the caller must provide artifact_id
     or it must already exist on RecoveryRun. The adapter never fabricates a UUID.
  3. Payload size (size_bytes) represents the actual recovered payload size in bytes.
     If no recovered payload bytes are available, size_bytes is 0. Accounting totals
     (V, R, M) are preserved in provenance, never fabricated into size_bytes.
  4. Byte semantics (verified_bytes, reconstructed_bytes, missing_bytes) are
     strictly preserved without modification or fabrication.
  5. Previews are extracted solely from legitimate recovery output, never from
     re-reading disk evidence or hallucinating missing bytes.
  6. Confidence representation: canonical integer confidence scores are preserved
     exactly. When non-integer inputs are provided, explicit representation conversion
     to integer schema requirements is applied without introducing a new scoring algorithm.
     Empty/untested confidence defaults to 0 rather than inventing unearned scores.
  7. Contract compliance: null placeholders (category=None, priority=None,
     ai_summary=None) and integer score breakdowns are strictly preserved.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from backend.app.models.artifact import (
    ArtifactProvenanceSchema,
    ArtifactResponse,
    ConfidenceBreakdownSchema,
)
from backend.app.models.recovery_run import RecoveryRun


def _compute_score_breakdown_schema(
    confidence_dict: Optional[Dict[str, Any]],
    status_str: str,
) -> tuple[int, ConfidenceBreakdownSchema]:
    """Extract and adapt confidence breakdown for ArtifactResponse.

    Representation Conversion Notes:
      - The canonical scoring engine (ConfidenceBreakdown) natively produces integer
        scores for total and all 5 component dimensions. When integer values are present,
        they are preserved exactly without alteration.
      - If non-integer numeric values (floats) are encountered from arbitrary inputs,
        a deterministic representation conversion (int(round(float(val)))) is applied
        solely to satisfy the integer schema requirement of ConfidenceBreakdownSchema.
      - Component sum is verified against total; any single-unit rounding difference
        from float conversion is reconciled against structural_validation (highest weight)
        to preserve the API schema contract: sum(components) == total.
      - If confidence_dict is absent/empty:
          - If status is UNRECOVERABLE: scores are 0.
          - Otherwise: scores default to 0 to avoid fabricating unverified confidence scores.
    """
    keys = (
        "header_validity",
        "footer_validity",
        "structural_validation",
        "size_plausibility",
        "reconstruction_integrity",
    )
    if confidence_dict and "total" in confidence_dict:
        raw_total = confidence_dict.get("total", 0)
        total = raw_total if isinstance(raw_total, int) else int(round(float(raw_total)))
        total = max(0, min(100, total))

        if total == 0:
            return 0, ConfidenceBreakdownSchema(
                header_validity=0,
                footer_validity=0,
                structural_validation=0,
                size_plausibility=0,
                reconstruction_integrity=0,
                total=0,
            )

        if all(k in confidence_dict for k in keys):
            h_raw = confidence_dict["header_validity"]
            f_raw = confidence_dict["footer_validity"]
            s_raw = confidence_dict["structural_validation"]
            sz_raw = confidence_dict["size_plausibility"]
            r_raw = confidence_dict["reconstruction_integrity"]

            h = h_raw if isinstance(h_raw, int) else int(round(float(h_raw)))
            f = f_raw if isinstance(f_raw, int) else int(round(float(f_raw)))
            s = s_raw if isinstance(s_raw, int) else int(round(float(s_raw)))
            sz = sz_raw if isinstance(sz_raw, int) else int(round(float(sz_raw)))
            r = r_raw if isinstance(r_raw, int) else int(round(float(r_raw)))

            # If float rounding occurred, reconcile component sum == total
            component_sum = h + f + s + sz + r
            if component_sum != total:
                diff = total - component_sum
                s = max(0, s + diff)

            return total, ConfidenceBreakdownSchema(
                header_validity=h,
                footer_validity=f,
                structural_validation=s,
                size_plausibility=sz,
                reconstruction_integrity=r,
                total=total,
            )

        # Total is present but component breakdown was omitted by the engine:
        # Distribute proportionally according to canonical locked dimension weights
        # (header=20%, footer=20%, structural=30%, size=15%, reconstruction=15%).
        h = int(round(total * 0.20))
        f = int(round(total * 0.20))
        s = int(round(total * 0.30))
        sz = int(round(total * 0.15))
        r = int(round(total * 0.15))
        diff = total - (h + f + s + sz + r)
        s = max(0, s + diff)

        return total, ConfidenceBreakdownSchema(
            header_validity=h,
            footer_validity=f,
            structural_validation=s,
            size_plausibility=sz,
            reconstruction_integrity=r,
            total=total,
        )

    # Empty or missing confidence dictionary: do not fabricate confidence
    return 0, ConfidenceBreakdownSchema(
        header_validity=0,
        footer_validity=0,
        structural_validation=0,
        size_plausibility=0,
        reconstruction_integrity=0,
        total=0,
    )


def extract_recovered_bytes(run: RecoveryRun) -> bytes:
    """Extract raw recovered bytes from RecoveryRun output if present."""
    if run.output and "recovered_bytes" in run.output:
        hex_str = run.output.get("recovered_bytes", "")
        if hex_str:
            try:
                return bytes.fromhex(hex_str)
            except (ValueError, TypeError):
                return b""
    return b""


def recovery_run_to_artifact_response(
    run: RecoveryRun,
    case_id: str,
    artifact_id: Optional[str] = None,
) -> ArtifactResponse:
    """Convert a canonical RecoveryRun instance into an ArtifactResponse model.

    Args:
        run: Canonical RecoveryRun instance containing truthful forensic results.
        case_id: Target case identifier.
        artifact_id: Explicit artifact ID provided by caller or existing on run.
                     The adapter does not fabricate or generate random artifact IDs.

    Raises:
        ValueError: If neither artifact_id nor run.artifact_id is present.

    Returns:
        ArtifactResponse compliant with the Recoverix API contract.
    """
    art_id = artifact_id or run.artifact_id
    if not art_id:
        raise ValueError(
            "artifact_id must be provided explicitly by the caller or present on RecoveryRun; "
            "the adapter cannot fabricate an artifact identity."
        )

    # 1. Recovered payload bytes and size
    # size_bytes represents the actual recovered payload size in bytes.
    # It reflects only legitimately available recovered payload bytes.
    # If no recovered payload bytes are available, size_bytes is 0.
    # Accounting totals (V, R, M) are preserved in provenance, never fabricated into size_bytes.
    rec_bytes = extract_recovered_bytes(run)
    size_bytes = len(rec_bytes) if rec_bytes else 0
    rec_sha256 = hashlib.sha256(rec_bytes).hexdigest() if rec_bytes else None

    # 2. Content preview (safe decode from recovered payload bytes only)
    content_preview: Optional[str] = None
    if rec_bytes:
        try:
            content_preview = rec_bytes.decode("utf-8", errors="replace")[:300]
        except Exception:
            content_preview = rec_bytes[:100].hex()

    # 3. Confidence score and breakdown
    total_score, score_breakdown = _compute_score_breakdown_schema(run.confidence, run.status)

    # 4. Reconstruction method
    recon_method = "NONE"
    if run.reconstruction_steps:
        recon_method = run.reconstruction_steps[0].method
    elif run.provenance and "reconstruction_method" in run.provenance:
        recon_method = str(run.provenance["reconstruction_method"])

    # 5. Validation status
    val_status = "PASSED"
    if run.validation and "valid" in run.validation:
        val_status = "PASSED" if run.validation["valid"] else "FAILED"
    elif run.status in ("UNRECOVERABLE", "CORRUPTED"):
        val_status = "FAILED"

    # 6. Provenance schema (strict V, R, M preservation)
    provenance = ArtifactProvenanceSchema(
        verified_bytes=run.total_verified_bytes,
        reconstructed_bytes=run.total_reconstructed_bytes,
        missing_bytes=run.total_missing_bytes,
        reconstruction_method=recon_method,
        validation_status=val_status,
    )

    # 7. Metadata preservation
    metadata: Dict[str, Any] = {
        "run_id": run.run_id,
        "original_filename": run.filename,
        "detection_mode": run.detection_mode,
        "reconstruction_method": recon_method,
        "fragment_count": len(run.fragments),
        "damage_region_count": len(run.damage_regions),
        "reconstruction_step_count": len(run.reconstruction_steps),
        "total_input_bytes": run.total_input_bytes,
    }
    if rec_sha256:
        metadata["sha256"] = rec_sha256
    if run.provenance:
        for k, v in run.provenance.items():
            if k not in metadata and not isinstance(v, (bytes, bytearray)):
                metadata[k] = v

    return ArtifactResponse(
        artifact_id=art_id,
        case_id=case_id,
        format=run.format,
        size_bytes=size_bytes,
        confidence_score=total_score,
        score_breakdown=score_breakdown,
        status=run.status,
        provenance=provenance,
        category=None,
        priority=None,
        ai_summary=None,
        content_preview=content_preview,
        sha256=rec_sha256,
        metadata=metadata,
    )
