"""
tracer.py — Deterministic execution tracer and observer for Recoverix pipelines.

Observes real recovery execution across candidate scanning, carving,
bifragment reconstruction, structural validation, and confidence scoring.
Generates structured RecoveryRun models, PipelineEvent sequence traces,
Fragment representations, DamageRegions, and ReconstructionSteps.

Supports both single-candidate and multi-candidate forensic recovery runs.
Does NOT modify existing recovery logic or confidence algorithms.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Any, Tuple

from backend.app.models.recovery_run import (
    RecoveryRun,
    PipelineEvent,
    Fragment,
    FragmentRelationship,
    DamageRegion,
    ReconstructionStep,
)
from backend.app.store import store
from backend.app.recovery.scanner import scan_evidence, Candidate, get_last_scan_metadata
from backend.app.recovery.carver import carve_candidate, RecoveredArtifact
from backend.app.recovery.validators import validate_artifact, VALIDATORS
from backend.app.recovery.validators.pdf import reconstruct_pdf_xref
from backend.app.recovery.bifragment import reconstruct_bifragment
from backend.app.recovery.reconstruction import reconstruct_artifact, reconstruct_fragment_pair
from backend.app.recovery.fragment_detector import detect_text_fragments
from backend.app.recovery.relationship import select_fragment_pairs
from backend.app.scoring.confidence import evaluate_artifact_confidence
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    PNG_SIGNATURE,
    PDF_HEADER_SIGNATURE,
    PDF_TRAILER_SIGNATURE,
)
from backend.app.recovery.completeness import assess_artifact_completeness

@dataclass(frozen=True)
class CandidateEvidenceSpan:
    """Represents the physical evidence span attributable to a candidate.

    Distinguishes between:
    - a candidate with a trustworthy/bounded physical end (evidence_end is int)
    - a candidate with an unknown/unbounded end (evidence_end is None)
    - the search window limit used for safe scanning without claiming ownership
    """

    evidence_start: int
    evidence_end: Optional[int]
    search_limit: int

    @property
    def is_bounded(self) -> bool:
        """True if the candidate has a known, trustworthy physical end boundary."""
        return self.evidence_end is not None

    @property
    def known_span_length(self) -> Optional[int]:
        """Physical length if bounded, else None to preserve end uncertainty."""
        if self.evidence_end is not None:
            return max(0, self.evidence_end - self.evidence_start)
        return None

    def bound_verified_bytes(self, proposed_verified: int) -> int:
        """Ensure verified bytes are strictly supported by the attributable evidence span.

        Never permits an unbounded candidate to claim beyond attributable bytes,
        and never permits verified bytes to exceed the search window.
        """
        if self.is_bounded:
            max_allowed = max(0, (self.evidence_end or self.evidence_start) - self.evidence_start)
            return min(proposed_verified, max_allowed)
        max_window = max(0, self.search_limit - self.evidence_start)
        return min(proposed_verified, max_window)

    def compute_fragment_bounds(self, verified_bytes: int) -> Tuple[int, int]:
        """Compute (length, end_offset) for Fragment model accounting.

        For bounded candidates: uses the known physical boundary.
        For unbounded candidates: strictly bounds the fragment to the verified bytes
        (or 0 if unrecoverable), preserving end uncertainty without claiming the
        remainder of the evidence buffer.
        """
        if self.is_bounded:
            end = self.evidence_end if self.evidence_end is not None else self.evidence_start
            return (end - self.evidence_start, end)
        if verified_bytes > 0:
            return (verified_bytes, self.evidence_start + verified_bytes)
        return (0, self.evidence_start)


def resolve_candidate_evidence_span(
    content_len: int,
    cand: Candidate,
    next_offset: Optional[int] = None,
) -> CandidateEvidenceSpan:
    """Resolve physical evidence span and search limit for a candidate.

    Enforces that an unknown candidate end (estimated_end_offset is None)
    is preserved as None rather than silently becoming len(content).
    When estimated_end_offset is known, limits search to the known boundary.
    """
    start = getattr(cand, "offset", 0)
    end = getattr(cand, "estimated_end_offset", None)

    if end is not None and end > start:
        search_lim = min(end, content_len)
        if next_offset is not None and next_offset > start:
            search_lim = min(search_lim, next_offset)
    elif next_offset is not None and next_offset > start:
        search_lim = min(next_offset, content_len)
    else:
        search_lim = content_len

    return CandidateEvidenceSpan(
        evidence_start=start,
        evidence_end=end,
        search_limit=search_lim,
    )



def _init_trace_context(run_id: str):
    """Initialize sequence trace events and an event emission closure for a recovery run."""
    started_at = datetime.now(timezone.utc)
    events: List[PipelineEvent] = []
    seq = 1

    def emit_event(
        event_type: str,
        message: str,
        relevant_fragment_ids: Optional[List[str]] = None,
        relevant_artifact_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        nonlocal seq
        events.append(
            PipelineEvent(
                event_id=f"evt-{seq}",
                run_id=run_id,
                sequence=seq,
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                message=message,
                relevant_fragment_ids=relevant_fragment_ids or [],
                relevant_artifact_info=relevant_artifact_info,
            )
        )
        seq += 1

    return started_at, events, emit_event


_VALID_DAMAGE_STATUSES = {"RECONSTRUCTED", "UNRECOVERABLE", "UNRESOLVED", "DETECTED"}


def _resolve_damage_region_status(raw_status: Optional[str], recon_success: bool) -> str:
    """Resolve and validate damage region status from reconstructor output.

    - 'RECONSTRUCTABLE': translates to 'RECONSTRUCTED' if reconstruction succeeded,
      otherwise 'UNRECOVERABLE'.
    - Known terminal statuses ('RECONSTRUCTED', 'UNRECOVERABLE', 'UNRESOLVED', 'DETECTED'):
      preserved as declared.
    - Missing, absent, or unrecognized status values: handled deliberately by falling back
      to 'RECONSTRUCTED' if reconstruction succeeded, else 'UNRECOVERABLE'.
      Arbitrary invalid status strings are never silently passed to DamageRegion.
    """
    if raw_status == "RECONSTRUCTABLE":
        return "RECONSTRUCTED" if recon_success else "UNRECOVERABLE"
    if raw_status in _VALID_DAMAGE_STATUSES:
        return raw_status
    return "RECONSTRUCTED" if recon_success else "UNRECOVERABLE"


def _finalize_recovery_run(
    *,
    run_id: str,
    started_at: datetime,
    events: List[PipelineEvent],
    emit_event: Any,
    filename: str,
    fmt: str,
    candidate_id: Optional[str],
    case_id: Optional[str] = None,
    artifact_id: Optional[str] = None,
    status_val: str,
    ver_bytes: int,
    rec_byte_cnt: int,
    miss_bytes: int,
    fragments: List[Fragment],
    damage_regions: List[DamageRegion],
    reconstruction_steps: List[ReconstructionStep],
    val_details_dict: Dict[str, Any],
    score_breakdown_dict: Dict[str, Any],
    prov_dict: Dict[str, Any],
    output_dict: Optional[Dict[str, Any]],
    output_raw: bytes,
    detection_mode: str,
) -> RecoveryRun:
    prov_dict["detection_mode"] = detection_mode

    # Coordinate system provenance guard
    if "coordinate_system" not in prov_dict:
        if candidate_id is None:
            prov_dict["evidence_start"] = 0
            prov_dict["evidence_end"] = len(output_raw)
            prov_dict["coordinate_system"] = "whole_buffer_fallback"
            prov_dict.setdefault("relationships", [])
        else:
            prov_dict["coordinate_system"] = "physical_evidence_offsets"
            prov_dict.setdefault("relationships", [])

    # Absolute final invariant guard:
    # FULLY_RECOVERED is permitted ONLY when:
    # R == 0, M == 0, structurally valid, and evidence is sufficient to establish a complete artifact.
    is_complete_final = assess_artifact_completeness(
        fmt=fmt,
        content=output_raw,
        detection_mode=detection_mode,
        missing_bytes=miss_bytes,
        reconstructed_bytes=rec_byte_cnt,
    )
    if (rec_byte_cnt > 0 or miss_bytes > 0 or not is_complete_final) and status_val == "FULLY_RECOVERED":
        status_val = "PARTIALLY_RECOVERED"

    total_input_bytes = ver_bytes + rec_byte_cnt + miss_bytes
    emit_event("RECOVERY_COMPLETED", f"Recovery run completed with status '{status_val}'")

    completed_at = datetime.now(timezone.utc)
    run = RecoveryRun(
        run_id=run_id,
        case_id=case_id,
        artifact_id=artifact_id,
        candidate_id=candidate_id,
        filename=filename,
        format=fmt,
        status=status_val,
        started_at=started_at,
        completed_at=completed_at,
        total_input_bytes=total_input_bytes,
        total_verified_bytes=ver_bytes,
        total_reconstructed_bytes=rec_byte_cnt,
        total_missing_bytes=miss_bytes,
        fragments=fragments,
        damage_regions=damage_regions,
        reconstruction_steps=reconstruction_steps,
        events=events,
        validation=val_details_dict,
        confidence=score_breakdown_dict,
        provenance=prov_dict,
        output=output_dict,
        detection_mode=detection_mode,
    )
    store.add_recovery_run(run)
    return run


def _rank_candidate(c: Any, ext_fmt: Optional[str] = None) -> tuple[int, int, int, int, int]:
    """Heuristic rank for legacy primary candidate selection: matches extension, method, length, known end, and offset."""
    ext_match = 1 if (ext_fmt and getattr(c, "format", None) == ext_fmt) else 0
    method_score = {
        "synthetic_boundary": 100,
        "magic_bytes": 80,
    }.get(getattr(c, "detection_method", ""), 50)
    sig_len = getattr(c, "detected_header_length", 0)
    has_end = 1 if getattr(c, "estimated_end_offset", None) is not None else 0
    return (ext_match, method_score, sig_len, has_end, -getattr(c, "offset", 0))


def _create_error_recovery_run(
    *,
    filename: str,
    cand: Any,
    error: Exception,
    case_id: Optional[str] = None,
    artifact_id: Optional[str] = None,
    detection_mode: str = "known_file",
    scan_meta: Optional[Dict[str, Any]] = None,
) -> RecoveryRun:
    """Constructs an isolated UNRECOVERABLE run when a candidate raises an unexpected exception."""
    if scan_meta is None:
        scan_meta = get_last_scan_metadata()
    run_id = f"run_{uuid.uuid4().hex[:8]}"
    started_at, events, emit_event = _init_trace_context(run_id)
    cand_id = getattr(cand, "candidate_id", None)
    fmt = getattr(cand, "format", "unknown")

    emit_event("RECOVERY_STARTED", f"Started recovery run for '{filename}' candidate '{cand_id}'")
    emit_event("DAMAGE_DETECTED", f"Candidate execution failed with error: {error}")
    emit_event("RECOVERY_COMPLETED", "Recovery run completed with status 'UNRECOVERABLE'")

    completed_at = datetime.now(timezone.utc)
    prov_dict = {
        "detection_mode": detection_mode,
        "error": str(error),
        "evidence_start": getattr(cand, "offset", 0),
        "evidence_end": getattr(cand, "estimated_end_offset", None),
        "coordinate_system": "physical_evidence_offsets",
        "detection_method": getattr(cand, "detection_method", "unknown"),
        "relationships": [
            asdict(r) if hasattr(r, "__dataclass_fields__") else r
            for r in getattr(cand, "relationships", ())
        ],
        "candidate_cap_enforced": scan_meta.get("candidate_cap_enforced", False) if scan_meta else False,
        "total_discovered_candidates": scan_meta.get("total_discovered_candidates", 0) if scan_meta else 0,
        "candidates_omitted": scan_meta.get("candidates_omitted", 0) if scan_meta else 0,
    }
    run = RecoveryRun(
        run_id=run_id,
        case_id=case_id,
        artifact_id=artifact_id,
        candidate_id=cand_id,
        filename=filename,
        format=fmt,
        status="UNRECOVERABLE",
        started_at=started_at,
        completed_at=completed_at,
        total_input_bytes=0,
        total_verified_bytes=0,
        total_reconstructed_bytes=0,
        total_missing_bytes=0,
        fragments=[],
        damage_regions=[],
        reconstruction_steps=[],
        events=events,
        validation={"error": str(error)},
        confidence={"total": 0.0},
        provenance=prov_dict,
        output=None,
        detection_mode=detection_mode,
    )
    store.add_recovery_run(run)
    return run


def _recover_contiguous_candidate(
    filename: str,
    content: bytes,
    cand: Candidate,
    case_id: Optional[str] = None,
    artifact_id: Optional[str] = None,
    detection_mode: str = "known_file",
    scan_meta: Optional[Dict[str, Any]] = None,
) -> RecoveryRun:
    """Execute traced recovery for a single contiguous candidate with known boundaries."""
    if scan_meta is None:
        scan_meta = get_last_scan_metadata()
    run_id = f"run_{uuid.uuid4().hex[:8]}"
    started_at, events, emit_event = _init_trace_context(run_id)

    emit_event("RECOVERY_STARTED", f"Started recovery run for '{filename}' candidate '{cand.candidate_id}'")
    emit_event("SCANNING_STARTED", f"Scanning {len(content)} bytes for format signatures")
    if scan_meta and scan_meta.get("candidate_cap_enforced"):
        emit_event(
            "SCANNING_COMPLETED",
            f"Candidate cap enforced: processed first 250 of {scan_meta['total_discovered_candidates']} discovered candidates ({scan_meta['candidates_omitted']} omitted)",
        )
    emit_event(
        "FORMAT_DETECTED",
        f"Detected format signature '{cand.format}' at byte offset {cand.offset}",
        relevant_artifact_info={"format": cand.format, "offset": cand.offset},
    )
    emit_event(
        "CANDIDATE_FOUND",
        f"Candidate '{cand.candidate_id}' located at offset {cand.offset} via {cand.detection_method}",
        relevant_artifact_info={
            "candidate_id": cand.candidate_id,
            "offset": cand.offset,
            "evidence_start": cand.offset,
            "evidence_end": cand.estimated_end_offset,
            "coordinate_system": "physical_evidence_offsets",
            "relationships": [
                {
                    "target_candidate_id": r.target_candidate_id,
                    "target_format": r.target_format,
                    "relationship_type": r.relationship_type,
                }
                for r in getattr(cand, "relationships", ())
            ],
        },
    )
    fmt = cand.format
    validator = VALIDATORS.get(fmt, lambda data: validate_artifact(fmt, data))

    span = resolve_candidate_evidence_span(len(content), cand)
    frag_len, frag_end = span.compute_fragment_bounds(span.known_span_length or 0)
    frag0 = Fragment(
        fragment_id="frag-0",
        offset=cand.offset,
        length=frag_len,
        end_offset=frag_end,
        status="VERIFIED",
        source="synthetic_boundary" if cand.detection_method == "synthetic_boundary" else "magic_bytes",
        format=fmt,
        verified_bytes=frag_len,
        reconstructed_bytes=0,
        missing_bytes=0,
        validation_status="PASSED",
    )
    fragments: List[Fragment] = [frag0]
    damage_regions: List[DamageRegion] = []
    reconstruction_steps: List[ReconstructionStep] = []

    status_val: str = "UNRECOVERABLE"
    ver_bytes: int = 0
    rec_byte_cnt: int = 0
    miss_bytes: int = frag_len
    score_breakdown_dict: Dict[str, Any] = {}
    val_details_dict: Dict[str, Any] = {}
    prov_dict: Dict[str, Any] = {}
    output_dict: Optional[Dict[str, Any]] = None

    emit_event(
        "FRAGMENT_IDENTIFIED",
        f"Identified contiguous fragment frag-0 [{cand.offset}..{cand.estimated_end_offset}] ({frag_len} bytes)",
        relevant_fragment_ids=["frag-0"],
    )

    carved_bytes: bytes = b""
    try:
        carved: RecoveredArtifact = carve_candidate(content, cand)
        carved_bytes = carved.recovered_bytes
        if fmt in ("txt", "csv", "json"):
            emit_event("RECONSTRUCTION_STARTED", f"Attempting deterministic {fmt.upper()} format reconstruction")
            recon_res = reconstruct_artifact(fmt, carved, detection_mode=detection_mode)
            emit_event(
                "RECONSTRUCTION_COMPLETED",
                f"{fmt.upper()} reconstruction completed with status '{recon_res.status}'",
            )
            status_val = recon_res.status
            ver_bytes = recon_res.verified_bytes
            rec_byte_cnt = recon_res.reconstructed_bytes
            miss_bytes = recon_res.missing_bytes
            emit_event("VALIDATION_STARTED", f"Validating structural integrity for format '{fmt}'")
            val_res = recon_res.validation_result or validator(carved)
            val_status_str = "PASSED" if val_res.valid else "FAILED"
            emit_event(
                "VALIDATION_COMPLETED",
                f"Structural validation {val_status_str}: {len(val_res.errors)} errors, {len(val_res.warnings)} warnings",
            )
            val_details_dict = asdict(val_res)
            output_dict = {"recovered_bytes": recon_res.recovered_bytes.hex()}

            eval_res = evaluate_artifact_confidence(
                validation_result=val_res,
                artifact=recon_res.recovered_bytes,
                actual_verified_bytes=ver_bytes,
                actual_reconstructed_bytes=rec_byte_cnt,
                actual_missing_bytes=miss_bytes,
            )
            emit_event(
                "CONFIDENCE_CALCULATED",
                f"Confidence evaluated: total={eval_res.score_breakdown.total}/100, status={eval_res.status.value}",
            )
            score_breakdown_dict = asdict(eval_res.score_breakdown)
            prov_dict = asdict(eval_res.provenance)
            prov_dict["evidence_size"] = len(content)
            if "reconstruction_method" in (recon_res.details or {}):
                prov_dict["reconstruction_method"] = recon_res.details["reconstruction_method"]

            is_complete = assess_artifact_completeness(
                fmt=fmt,
                content=recon_res.recovered_bytes,
                detection_mode=detection_mode,
                validation_result=val_res,
                missing_bytes=miss_bytes,
                reconstructed_bytes=rec_byte_cnt,
            )
            if (not is_complete or miss_bytes > 0 or rec_byte_cnt > 0) and status_val == "FULLY_RECOVERED":
                status_val = "PARTIALLY_RECOVERED"

                step_in_ids = [
                    f"frag-{i}"
                    for i in range(len(recon_res.details.get("physical_fragments", [])))
                ] if (recon_res.details and "physical_fragments" in recon_res.details and len(recon_res.details["physical_fragments"]) > 1) else ["frag-0"]
                step = ReconstructionStep(
                    step_id=f"step-{idx_m}",
                    method=m,
                    input_fragment_ids=step_in_ids,
                    gap_start=None,
                    gap_end=None,
                    gap_size=None,
                    result="SUCCESS" if recon_res.success else "FAILED",
                    verified_bytes=ver_bytes,
                    reconstructed_bytes=rec_byte_cnt,
                    missing_bytes=miss_bytes,
                    validation_status=val_status_str,
                    confidence=float(recon_res.details.get("confidence_score", 100.0)),
                )
                reconstruction_steps.append(step)

            for idx_d, dmg in enumerate(recon_res.damage_regions):
                damage_regions.append(
                    DamageRegion(
                        region_id=f"damage-{idx_d}",
                        start_offset=dmg.get("offset", 0),
                        end_offset=dmg.get("offset", 0) + dmg.get("length", 0),
                        length=dmg.get("length", 0),
                        type=dmg.get("type", "CORRUPTED"),
                        status=_resolve_damage_region_status(dmg.get("status"), recon_res.success),
                        affected_fragment_ids=["frag-0"],
                    )
                )
                emit_event(
                    "DAMAGE_DETECTED",
                    f"Detected damage region ({dmg.get('type')}) of {dmg.get('length')} bytes at offset {dmg.get('offset')}",
                    relevant_fragment_ids=["frag-0"],
                )
        else:
            emit_event("VALIDATION_STARTED", f"Validating structural integrity for format '{fmt}'")
            val_res = validator(carved)
            val_status_str = "PASSED" if val_res.valid else "FAILED"
            emit_event(
                "VALIDATION_COMPLETED",
                f"Structural validation {val_status_str}: {len(val_res.errors)} errors, {len(val_res.warnings)} warnings",
            )

            is_complete = assess_artifact_completeness(
                fmt=fmt,
                content=carved.recovered_bytes,
                detection_mode=detection_mode,
                validation_result=val_res,
            )
            eval_res = evaluate_artifact_confidence(validation_result=val_res, artifact=carved, is_complete=is_complete)
            emit_event(
                "CONFIDENCE_CALCULATED",
                f"Confidence evaluated: total={eval_res.score_breakdown.total}/100, status={eval_res.status.value}",
            )

            status_val = eval_res.status.value
            if (not is_complete) and status_val == "FULLY_RECOVERED":
                status_val = "PARTIALLY_RECOVERED"
            if status_val == "UNRECOVERABLE":
                ver_bytes = 0
                rec_byte_cnt = 0
                miss_bytes = frag_len
                output_dict = {"recovered_bytes": ""}
                eval_res = evaluate_artifact_confidence(
                    validation_result=val_res,
                    artifact=None,
                    actual_verified_bytes=0,
                    actual_missing_bytes=frag_len,
                    is_complete=False,
                )
                score_breakdown_dict = asdict(eval_res.score_breakdown)
                val_details_dict = asdict(val_res)
                prov_dict = asdict(eval_res.provenance)
                if not damage_regions:
                    damage_regions.append(
                        DamageRegion(
                            region_id="damage-0",
                            start_offset=cand.offset,
                            end_offset=frag_end,
                            length=frag_len,
                            type="UNRECOVERABLE",
                            status="UNRECOVERABLE",
                            affected_fragment_ids=["frag-0"],
                        )
                    )
            else:
                ver_bytes = eval_res.provenance.verified_bytes
                rec_byte_cnt = eval_res.provenance.reconstructed_bytes
                miss_bytes = eval_res.provenance.missing_bytes
                score_breakdown_dict = asdict(eval_res.score_breakdown)
                val_details_dict = asdict(val_res)
                prov_dict = asdict(eval_res.provenance)
                output_dict = {"recovered_bytes": carved.recovered_bytes.hex()}

        if fmt in ("txt", "csv", "json") and recon_res.details and "physical_fragments" in recon_res.details:
            phys_frags = recon_res.details["physical_fragments"]
            if len(phys_frags) > 1:
                fragments = [
                    Fragment(
                        fragment_id=f"frag-{i}",
                        offset=p_off,
                        length=p_len,
                        end_offset=p_off + p_len,
                        status="VERIFIED",
                        source="synthetic_boundary" if cand.detection_method == "synthetic_boundary" else "carved",
                        format=fmt,
                        verified_bytes=p_len,
                        reconstructed_bytes=0,
                        missing_bytes=0,
                        validation_status=val_status_str,
                    )
                    for i, (p_off, p_len) in enumerate(phys_frags)
                ]
            else:
                frag_status = (
                    "VERIFIED"
                    if status_val == "FULLY_RECOVERED"
                    else (
                        "UNRECOVERABLE"
                        if status_val == "UNRECOVERABLE"
                        else ("CORRUPTED" if status_val == "CORRUPTED" else "PARTIAL")
                    )
                )
                frag0_updated = frag0.model_copy(
                    update={
                        "status": frag_status,
                        "verified_bytes": ver_bytes,
                        "reconstructed_bytes": rec_byte_cnt,
                        "missing_bytes": miss_bytes,
                        "validation_status": val_status_str,
                    }
                )
                fragments[0] = frag0_updated
        else:
            frag_status = (
                "VERIFIED"
                if status_val == "FULLY_RECOVERED"
                else (
                    "UNRECOVERABLE"
                    if status_val == "UNRECOVERABLE"
                    else ("CORRUPTED" if status_val == "CORRUPTED" else "PARTIAL")
                )
            )
            frag0_updated = frag0.model_copy(
                update={
                    "status": frag_status,
                    "verified_bytes": ver_bytes,
                    "reconstructed_bytes": rec_byte_cnt,
                    "missing_bytes": miss_bytes,
                    "validation_status": val_status_str,
                }
            )
            fragments[0] = frag0_updated
    except Exception as e:
        val_details_dict = {"error": str(e)}

    output_raw = bytes.fromhex(output_dict["recovered_bytes"]) if (output_dict and "recovered_bytes" in output_dict) else carved_bytes
    prov_dict["evidence_start"] = span.evidence_start
    prov_dict["evidence_end"] = span.evidence_end
    prov_dict["coordinate_system"] = "physical_evidence_offsets"
    prov_dict["detection_method"] = cand.detection_method
    prov_dict["relationships"] = [
        {
            "target_candidate_id": r.target_candidate_id,
            "target_format": r.target_format,
            "relationship_type": r.relationship_type,
        }
        for r in getattr(cand, "relationships", ())
    ]
    if scan_meta:
        prov_dict["candidate_cap_enforced"] = scan_meta.get("candidate_cap_enforced", False)
        prov_dict["total_discovered_candidates"] = scan_meta.get("total_discovered_candidates", 0)
        prov_dict["candidates_omitted"] = scan_meta.get("candidates_omitted", 0)

    return _finalize_recovery_run(
        run_id=run_id,
        started_at=started_at,
        events=events,
        emit_event=emit_event,
        filename=filename,
        fmt=fmt,
        candidate_id=getattr(cand, "candidate_id", None),
        case_id=case_id,
        artifact_id=artifact_id,
        status_val=status_val,
        ver_bytes=ver_bytes,
        rec_byte_cnt=rec_byte_cnt,
        miss_bytes=miss_bytes,
        fragments=fragments,
        damage_regions=damage_regions,
        reconstruction_steps=reconstruction_steps,
        val_details_dict=val_details_dict,
        score_breakdown_dict=score_breakdown_dict,
        prov_dict=prov_dict,
        output_dict=output_dict,
        output_raw=output_raw,
        detection_mode=detection_mode,
    )


def _recover_bifragment_candidate_pair(
    filename: str,
    content: bytes,
    cand: Candidate,
    cand2: Candidate,
    case_id: Optional[str] = None,
    detection_mode: str = "known_file",
    scan_meta: Optional[Dict[str, Any]] = None,
    precomputed_recon: Optional[Any] = None,
    next_offset: Optional[int] = None,
) -> RecoveryRun:
    """Execute traced recovery for a bifragment candidate pair of matching formats."""
    if scan_meta is None:
        scan_meta = get_last_scan_metadata()
    run_id = f"run_{uuid.uuid4().hex[:8]}"
    started_at, events, emit_event = _init_trace_context(run_id)

    emit_event(
        "RECOVERY_STARTED",
        f"Started recovery run for '{filename}' bifragment pair '{cand.candidate_id}' + '{cand2.candidate_id}'",
    )
    if scan_meta and scan_meta.get("candidate_cap_enforced"):
        emit_event(
            "SCANNING_COMPLETED",
            f"Candidate cap enforced: processed first 250 of {scan_meta['total_discovered_candidates']} discovered candidates ({scan_meta['candidates_omitted']} omitted)",
        )
    emit_event(
        "FORMAT_DETECTED",
        f"Detected format signature '{cand.format}' at byte offset {cand.offset}",
        relevant_artifact_info={"format": cand.format, "offset": cand.offset},
    )
    emit_event(
        "CANDIDATE_FOUND",
        f"Candidate '{cand.candidate_id}' located at offset {cand.offset} via {cand.detection_method}",
        relevant_artifact_info={
            "candidate_id": cand.candidate_id,
            "offset": cand.offset,
            "evidence_start": cand.offset,
            "evidence_end": cand.estimated_end_offset,
            "coordinate_system": "physical_evidence_offsets",
            "relationships": [
                {
                    "target_candidate_id": r.target_candidate_id,
                    "target_format": r.target_format,
                    "relationship_type": r.relationship_type,
                }
                for r in getattr(cand, "relationships", ())
            ],
        },
    )
    emit_event(
        "FORMAT_DETECTED",
        f"Detected format signature '{cand2.format}' at byte offset {cand2.offset}",
        relevant_artifact_info={"format": cand2.format, "offset": cand2.offset},
    )
    emit_event(
        "CANDIDATE_FOUND",
        f"Candidate '{cand2.candidate_id}' located at offset {cand2.offset} via {cand2.detection_method}",
        relevant_artifact_info={
            "candidate_id": cand2.candidate_id,
            "offset": cand2.offset,
            "evidence_start": cand2.offset,
            "evidence_end": cand2.estimated_end_offset,
            "coordinate_system": "physical_evidence_offsets",
            "relationships": [
                {
                    "target_candidate_id": r.target_candidate_id,
                    "target_format": r.target_format,
                    "relationship_type": r.relationship_type,
                }
                for r in getattr(cand2, "relationships", ())
            ],
        },
    )
    fmt = cand.format
    validator = VALIDATORS.get(fmt, lambda data: validate_artifact(fmt, data))

    raw_between = content[cand.offset:cand2.offset]
    frag_a_bytes = raw_between.rstrip(b"\x00")
    if not frag_a_bytes:
        frag_a_bytes = raw_between

    frag_a_end = cand.offset + len(frag_a_bytes)
    frag_a_len = frag_a_end - cand.offset
    gap_start = frag_a_end
    gap_end = cand2.offset
    gap_size = max(0, gap_end - gap_start)

    frag_a = Fragment(
        fragment_id="frag-0",
        offset=cand.offset,
        length=frag_a_len,
        end_offset=frag_a_end,
        status="PARTIAL",
        source="bifragment_a",
        format=fmt,
        verified_bytes=frag_a_len,
        reconstructed_bytes=0,
        missing_bytes=0,
        validation_status="PARTIAL",
    )

    frag_b_end = min(next_offset, len(content)) if next_offset is not None else len(content)
    frag_b_len = frag_b_end - cand2.offset
    frag_b = Fragment(
        fragment_id="frag-1",
        offset=cand2.offset,
        length=frag_b_len,
        end_offset=frag_b_end,
        status="PARTIAL",
        source="bifragment_b",
        format=fmt,
        verified_bytes=frag_b_len,
        reconstructed_bytes=0,
        missing_bytes=0,
        validation_status="PARTIAL",
    )

    rel_ab = FragmentRelationship(
        source_fragment_id="frag-0",
        target_fragment_id="frag-1",
        relationship_type="BOUNDED_GAP",
        details={"gap_size": gap_size},
    )
    frag_a_rel = frag_a.model_copy(update={"relationships": [rel_ab]})
    fragments: List[Fragment] = [frag_a_rel, frag_b]

    emit_event(
        "FRAGMENT_IDENTIFIED",
        f"Identified bifragment frag-0 [{cand.offset}..{frag_a_end}] and frag-1 [{cand2.offset}..{frag_b_end}]",
        relevant_fragment_ids=["frag-0", "frag-1"],
    )

    damage_regions: List[DamageRegion] = []
    reconstruction_steps: List[ReconstructionStep] = []

    dam0 = DamageRegion(
        region_id="damage-0",
        start_offset=gap_start,
        end_offset=gap_end,
        length=gap_size,
        type="MISSING",
        status="RECONSTRUCTABLE",
        affected_fragment_ids=["frag-0", "frag-1"],
    )
    damage_regions.append(dam0)
    emit_event(
        "DAMAGE_DETECTED",
        f"Detected missing gap of {gap_size} bytes between offset {gap_start} and {gap_end}",
        relevant_fragment_ids=["frag-0", "frag-1"],
    )

    emit_event(
        "RECONSTRUCTION_STARTED",
        f"Attempting bifragment gap reconstruction (gap size bounds: 1 to 4096)",
        relevant_fragment_ids=["frag-0", "frag-1"],
    )

    status_val: str = "UNRECOVERABLE"
    ver_bytes: int = 0
    rec_byte_cnt: int = 0
    miss_bytes: int = gap_size
    score_breakdown_dict: Dict[str, Any] = {}
    val_details_dict: Dict[str, Any] = {}
    prov_dict: Dict[str, Any] = {}
    output_dict: Optional[Dict[str, Any]] = None

    try:
        frag_b_bytes = content[cand2.offset:frag_b_end]
        if precomputed_recon is not None:
            recon_res = precomputed_recon
        else:
            recon_res = reconstruct_bifragment(
                frag_a_bytes, frag_b_bytes, validator=validator, min_gap=1, max_gap=4096
            )

        rec_success = recon_res.success
        emit_event(
            "RECONSTRUCTION_COMPLETED",
            f"Bifragment reconstruction {'succeeded' if rec_success else 'failed'}",
            relevant_fragment_ids=["frag-0", "frag-1"],
        )

        val_res_for_eval = recon_res.validation_result if (recon_res and recon_res.validation_result) else validator(frag_a_bytes + frag_b_bytes)
        eval_res = evaluate_artifact_confidence(
            validation_result=val_res_for_eval,
            reconstruction_result=recon_res,
            actual_missing_bytes=gap_size,
        )
        emit_event(
            "CONFIDENCE_CALCULATED",
            f"Confidence evaluated: total={eval_res.score_breakdown.total}/100, status={eval_res.status.value}",
        )

        status_val = eval_res.status.value
        # If multiple gaps validated with preserve_ambiguity=True, gap_size is None
        if recon_res.gap_size is None and rec_success:
            if status_val == "FULLY_RECOVERED":
                status_val = "PARTIALLY_RECOVERED"

        ver_bytes = eval_res.provenance.verified_bytes
        rec_byte_cnt = eval_res.provenance.reconstructed_bytes
        miss_bytes = eval_res.provenance.missing_bytes

        score_breakdown_dict = asdict(eval_res.score_breakdown)
        val_details_dict = asdict(val_res_for_eval)
        prov_dict = asdict(eval_res.provenance)
        output_bytes = (recon_res.fragment_a_bytes + recon_res.fragment_b_bytes) if (recon_res and hasattr(recon_res, "fragment_a_bytes")) else (frag_a_bytes + frag_b_bytes)
        output_dict = {"recovered_bytes": output_bytes.hex()}

        step0 = ReconstructionStep(
            step_id="step-0",
            method="BIFRAGMENT_GAP",
            input_fragment_ids=["frag-0", "frag-1"],
            gap_start=gap_start,
            gap_end=gap_end,
            gap_size=gap_size,
            validated_gap_size=recon_res.gap_size if (rec_success and recon_res.gap_size is not None) else None,
            result="SUCCESS" if rec_success else "FAILED",
            verified_bytes=ver_bytes,
            reconstructed_bytes=rec_byte_cnt,
            missing_bytes=miss_bytes,
            validation_status="PASSED" if (recon_res.validation_result and recon_res.validation_result.valid) else "FAILED",
            confidence=float(eval_res.score_breakdown.total),
        )
        reconstruction_steps.append(step0)

        dam0_updated = dam0.model_copy(
            update={"status": "RECONSTRUCTED" if (rec_success and recon_res.gap_size is not None) else "UNRECOVERABLE"}
        )
        damage_regions[0] = dam0_updated
    except Exception as e:
        val_details_dict = {"error": str(e)}

    output_raw = bytes.fromhex(output_dict["recovered_bytes"]) if (output_dict and "recovered_bytes" in output_dict) else (frag_a_bytes + frag_b_bytes)
    prov_dict["evidence_start"] = cand.offset
    prov_dict["evidence_end"] = cand2.estimated_end_offset
    prov_dict["coordinate_system"] = "physical_evidence_offsets"
    prov_dict["detection_method"] = cand.detection_method
    prov_dict["bifragment_offsets"] = [cand.offset, cand2.offset]
    prov_dict["relationships"] = [
        {
            "target_candidate_id": r.target_candidate_id,
            "target_format": r.target_format,
            "relationship_type": r.relationship_type,
        }
        for r in getattr(cand, "relationships", ())
    ]
    if scan_meta:
        prov_dict["candidate_cap_enforced"] = scan_meta.get("candidate_cap_enforced", False)
        prov_dict["total_discovered_candidates"] = scan_meta.get("total_discovered_candidates", 0)
        prov_dict["candidates_omitted"] = scan_meta.get("candidates_omitted", 0)

    return _finalize_recovery_run(
        run_id=run_id,
        started_at=started_at,
        events=events,
        emit_event=emit_event,
        filename=filename,
        fmt=fmt,
        candidate_id=getattr(cand, "candidate_id", None),
        case_id=case_id,
        artifact_id=None,
        status_val=status_val,
        ver_bytes=ver_bytes,
        rec_byte_cnt=rec_byte_cnt,
        miss_bytes=miss_bytes,
        fragments=fragments,
        damage_regions=damage_regions,
        reconstruction_steps=reconstruction_steps,
        val_details_dict=val_details_dict,
        score_breakdown_dict=score_breakdown_dict,
        prov_dict=prov_dict,
        output_dict=output_dict,
        output_raw=output_raw,
        detection_mode=detection_mode,
    )


def _recover_standalone_candidate(
    filename: str,
    content: bytes,
    cand: Candidate,
    case_id: Optional[str] = None,
    artifact_id: Optional[str] = None,
    detection_mode: str = "known_file",
    next_offset: Optional[int] = None,
    scan_meta: Optional[Dict[str, Any]] = None,
) -> RecoveryRun:
    """Execute traced recovery for a single candidate without estimated end offset."""
    if scan_meta is None:
        scan_meta = get_last_scan_metadata()
    run_id = f"run_{uuid.uuid4().hex[:8]}"
    started_at, events, emit_event = _init_trace_context(run_id)

    emit_event("RECOVERY_STARTED", f"Started recovery run for '{filename}' candidate '{cand.candidate_id}'")
    emit_event("SCANNING_STARTED", f"Scanning {len(content)} bytes for format signatures")
    if scan_meta and scan_meta.get("candidate_cap_enforced"):
        emit_event(
            "SCANNING_COMPLETED",
            f"Candidate cap enforced: processed first 250 of {scan_meta['total_discovered_candidates']} discovered candidates ({scan_meta['candidates_omitted']} omitted)",
        )
    emit_event(
        "FORMAT_DETECTED",
        f"Detected format signature '{cand.format}' at byte offset {cand.offset}",
        relevant_artifact_info={"format": cand.format, "offset": cand.offset},
    )
    emit_event(
        "CANDIDATE_FOUND",
        f"Candidate '{cand.candidate_id}' located at offset {cand.offset} via {cand.detection_method}",
        relevant_artifact_info={
            "candidate_id": cand.candidate_id,
            "offset": cand.offset,
            "evidence_start": cand.offset,
            "evidence_end": cand.estimated_end_offset,
            "coordinate_system": "physical_evidence_offsets",
            "relationships": [
                {
                    "target_candidate_id": r.target_candidate_id,
                    "target_format": r.target_format,
                    "relationship_type": r.relationship_type,
                }
                for r in getattr(cand, "relationships", ())
            ],
        },
    )
    fmt = cand.format
    validator = VALIDATORS.get(fmt, lambda data: validate_artifact(fmt, data))

    span = resolve_candidate_evidence_span(len(content), cand, next_offset)
    search_end = span.search_limit
    search_len = search_end - cand.offset

    init_len, init_end = span.compute_fragment_bounds(0)
    frag0 = Fragment(
        fragment_id="frag-0",
        offset=cand.offset,
        length=init_len,
        end_offset=init_end,
        status="PARTIAL",
        source="magic_bytes" if cand.detection_method == "magic_bytes" else "synthetic_boundary",
        format=fmt,
        verified_bytes=0,
        reconstructed_bytes=0,
        missing_bytes=search_len,
        validation_status="UNTESTED",
    )
    fragments: List[Fragment] = [frag0]
    damage_regions: List[DamageRegion] = []
    reconstruction_steps: List[ReconstructionStep] = []

    status_val: str = "UNRECOVERABLE"
    ver_bytes: int = 0
    rec_byte_cnt: int = 0
    miss_bytes: int = search_len
    score_breakdown_dict: Dict[str, Any] = {}
    val_details_dict: Dict[str, Any] = {}
    prov_dict: Dict[str, Any] = {}
    output_dict: Optional[Dict[str, Any]] = None
    total_input_bytes: int = search_len
    reconstruction_attempted: bool = False

    emit_event(
        "FRAGMENT_IDENTIFIED",
        f"Identified candidate fragment frag-0 [{cand.offset}..{search_end}] ({search_len} bytes)",
        relevant_fragment_ids=["frag-0"],
    )

    if fmt in ("txt", "json"):
        reconstruction_attempted = True
        raw_bytes = content[cand.offset:search_end]
        emit_event("RECONSTRUCTION_STARTED", f"Attempting deterministic {fmt.upper()} format reconstruction")
        recon_res = reconstruct_artifact(fmt, raw_bytes)
        emit_event(
            "RECONSTRUCTION_COMPLETED",
            f"{fmt.upper()} reconstruction completed with status '{recon_res.status}'",
        )
        status_val = recon_res.status
        ver_bytes = span.bound_verified_bytes(recon_res.verified_bytes)
        rec_byte_cnt = recon_res.reconstructed_bytes
        miss_bytes = recon_res.missing_bytes
        val_res = recon_res.validation_result or validator(raw_bytes)
        val_status_str = "PASSED" if val_res.valid else "FAILED"
        val_details_dict = asdict(val_res)
        output_dict = {"recovered_bytes": recon_res.recovered_bytes.hex()}

        eval_res = evaluate_artifact_confidence(
            validation_result=val_res,
            artifact=recon_res.recovered_bytes,
            actual_verified_bytes=ver_bytes,
            actual_reconstructed_bytes=rec_byte_cnt,
            actual_missing_bytes=miss_bytes,
        )
        score_breakdown_dict = asdict(eval_res.score_breakdown)
        prov_dict = asdict(eval_res.provenance)
        prov_dict["evidence_size"] = len(content)
        if "reconstruction_method" in (recon_res.details or {}):
            prov_dict["reconstruction_method"] = recon_res.details["reconstruction_method"]

        for idx_m, m in enumerate(recon_res.reconstruction_methods):
            step = ReconstructionStep(
                step_id=f"step-{idx_m}",
                method=m,
                input_fragment_ids=["frag-0"],
                gap_start=None,
                gap_end=None,
                gap_size=None,
                result="SUCCESS" if recon_res.success else "FAILED",
                verified_bytes=ver_bytes,
                reconstructed_bytes=rec_byte_cnt,
                missing_bytes=miss_bytes,
                validation_status=val_status_str,
                confidence=float(recon_res.details.get("confidence_score", 100.0)),
            )
            reconstruction_steps.append(step)

        for idx_d, dmg in enumerate(recon_res.damage_regions):
            damage_regions.append(
                DamageRegion(
                    region_id=f"damage-{idx_d}",
                    start_offset=dmg.get("offset", 0),
                    end_offset=dmg.get("offset", 0) + dmg.get("length", 0),
                    length=dmg.get("length", 0),
                    type=dmg.get("type", "CORRUPTED"),
                    status=_resolve_damage_region_status(dmg.get("status"), recon_res.success),
                    affected_fragment_ids=["frag-0"],
                )
            )
            emit_event(
                "DAMAGE_DETECTED",
                f"Detected damage region ({dmg.get('type')}) of {dmg.get('length')} bytes at offset {dmg.get('offset')}",
                relevant_fragment_ids=["frag-0"],
            )

    elif fmt == "pdf":
        reconstruction_attempted = True
        raw_bytes = content[cand.offset:search_end]
        val_initial = validator(raw_bytes)

        shuffled_recovered = False
        if cand.offset > 0 and b"%%EOF" in content[:cand.offset]:
            trailer_slice = content[:cand.offset]
            eof_pos = trailer_slice.rfind(PDF_TRAILER_SIGNATURE)
            if eof_pos != -1:
                eof_end = eof_pos + len(PDF_TRAILER_SIGNATURE)
                if eof_end < cand.offset and trailer_slice[eof_end:eof_end + 2] == b"\r\n":
                    eof_end += 2
                elif eof_end < cand.offset and trailer_slice[eof_end:eof_end + 1] in (b"\n", b"\r"):
                    eof_end += 1

                trailer_bytes = trailer_slice[:eof_end]
                header_bytes = content[cand.offset:search_end]
                gap_size = cand.offset - eof_end

                candidate_unshuffled = header_bytes + trailer_bytes
                val_unshuffled = validator(candidate_unshuffled)
                if not val_unshuffled.valid and (b"xref" not in candidate_unshuffled or any("xref" in e.lower() for e in val_unshuffled.errors)):
                    rebuilt_unshuffled, xref_ok = reconstruct_pdf_xref(candidate_unshuffled)
                    if xref_ok:
                        candidate_unshuffled = rebuilt_unshuffled
                        val_unshuffled = validator(candidate_unshuffled)

                if val_unshuffled.valid:
                    shuffled_recovered = True
                    emit_event(
                        "RECONSTRUCTION_STARTED",
                        "Detected shuffled PDF fragments; executing deterministic un-shuffle reconstruction",
                    )
                    emit_event(
                        "RECONSTRUCTION_COMPLETED",
                        "Shuffled PDF fragments reordered and structurally validated",
                    )
                    header_frag_len = len(header_bytes)
                    trailer_frag_len = len(trailer_bytes)
                    actual_ver = header_frag_len + trailer_frag_len
                    actual_miss = gap_size

                    f_head = Fragment(
                        fragment_id="frag-0",
                        offset=cand.offset,
                        length=header_frag_len,
                        end_offset=cand.offset + header_frag_len,
                        status="VERIFIED",
                        source="shuffled_header",
                        format="pdf",
                        verified_bytes=header_frag_len,
                        reconstructed_bytes=0,
                        missing_bytes=0,
                        validation_status="PASSED",
                    )
                    f_tail = Fragment(
                        fragment_id="frag-1",
                        offset=0,
                        length=trailer_frag_len,
                        end_offset=eof_end,
                        status="VERIFIED",
                        source="shuffled_trailer",
                        format="pdf",
                        verified_bytes=trailer_frag_len,
                        reconstructed_bytes=0,
                        missing_bytes=0,
                        validation_status="PASSED",
                    )
                    rel = FragmentRelationship(
                        source_fragment_id="frag-0",
                        target_fragment_id="frag-1",
                        relationship_type="SHUFFLED_SEQUENCE",
                        details={"unshuffle_offset": cand.offset, "gap_size": gap_size},
                    )
                    f_head = f_head.model_copy(update={"relationships": [rel]})
                    fragments.clear()
                    fragments.extend([f_head, f_tail])

                    if gap_size > 0:
                        damage_regions.append(
                            DamageRegion(
                                region_id="damage-gap",
                                start_offset=eof_end,
                                end_offset=cand.offset,
                                length=gap_size,
                                type="MISSING",
                                status="UNRECOVERABLE",
                                affected_fragment_ids=["frag-0", "frag-1"],
                            )
                        )
                        emit_event(
                            "DAMAGE_DETECTED",
                            f"Detected missing gap of {gap_size} bytes between shuffled fragments at {eof_end}..{cand.offset}",
                            relevant_fragment_ids=["frag-0", "frag-1"],
                        )

                    step0 = ReconstructionStep(
                        step_id="step-0",
                        method="FRAGMENT_UNSHUFFLE",
                        input_fragment_ids=["frag-0", "frag-1"],
                        gap_start=eof_end if gap_size > 0 else None,
                        gap_end=cand.offset if gap_size > 0 else None,
                        gap_size=gap_size if gap_size > 0 else None,
                        result="SUCCESS",
                        verified_bytes=actual_ver,
                        reconstructed_bytes=0,
                        missing_bytes=actual_miss,
                        validation_status="PASSED",
                        confidence=100.0 if gap_size == 0 else 80.0,
                    )
                    reconstruction_steps.append(step0)

                    eval_res = evaluate_artifact_confidence(
                        validation_result=val_unshuffled,
                        artifact=candidate_unshuffled,
                        actual_verified_bytes=actual_ver,
                        actual_reconstructed_bytes=0,
                        actual_missing_bytes=actual_miss,
                        is_complete=(gap_size == 0),
                    )
                    status_val = eval_res.status.value
                    ver_bytes = eval_res.provenance.verified_bytes
                    rec_byte_cnt = eval_res.provenance.reconstructed_bytes
                    miss_bytes = eval_res.provenance.missing_bytes
                    total_input_bytes = actual_ver + actual_miss
                    score_breakdown_dict = asdict(eval_res.score_breakdown)
                    val_details_dict = asdict(val_unshuffled)
                    prov_dict = asdict(eval_res.provenance)
                    prov_dict["evidence_size"] = total_input_bytes
                    prov_dict["reconstruction_method"] = "FRAGMENT_UNSHUFFLE"
                    output_dict = {"recovered_bytes": candidate_unshuffled.hex()}

        if not shuffled_recovered and (not val_initial.valid and b"xref" not in raw_bytes or any("xref" in e.lower() for e in val_initial.errors)):
            emit_event(
                "DAMAGE_DETECTED",
                "Detected damaged or missing PDF cross-reference table (xref)",
                relevant_fragment_ids=["frag-0"],
            )
            dam0 = DamageRegion(
                region_id="damage-0",
                start_offset=cand.offset,
                end_offset=search_end,
                length=search_len,
                type="CORRUPTED",
                status="RECONSTRUCTABLE",
                affected_fragment_ids=["frag-0"],
            )
            damage_regions.append(dam0)

            emit_event(
                "RECONSTRUCTION_STARTED",
                "Attempting deterministic PDF cross-reference (xref) reconstruction",
                relevant_fragment_ids=["frag-0"],
            )

            rebuilt_bytes, xref_ok = reconstruct_pdf_xref(raw_bytes)
            emit_event(
                "RECONSTRUCTION_COMPLETED",
                f"PDF xref reconstruction {'succeeded' if xref_ok else 'failed'}",
                relevant_fragment_ids=["frag-0"],
            )

            if xref_ok:
                carved_rebuilt = RecoveredArtifact(
                    candidate_id=cand.candidate_id,
                    format="pdf",
                    mime_type="application/pdf",
                    category="document",
                    source_offset=cand.offset,
                    recovered_bytes=rebuilt_bytes,
                    recovered_byte_count=len(rebuilt_bytes),
                    carving_method="XREF_RECONSTRUCTED",
                )
                val_res = validator(carved_rebuilt)
                pdf_input_bytes = len(raw_bytes)
                pdf_reconstructed_bytes = max(0, len(rebuilt_bytes) - pdf_input_bytes)
                pdf_missing_bytes = max(0, pdf_input_bytes - len(rebuilt_bytes))
                pdf_verified_bytes = pdf_input_bytes - pdf_missing_bytes
                eval_res = evaluate_artifact_confidence(
                    validation_result=val_res,
                    artifact=carved_rebuilt,
                    actual_verified_bytes=pdf_verified_bytes,
                    actual_reconstructed_bytes=pdf_reconstructed_bytes,
                    actual_missing_bytes=pdf_missing_bytes,
                )

                status_val = eval_res.status.value
                ver_bytes = eval_res.provenance.verified_bytes
                rec_byte_cnt = eval_res.provenance.reconstructed_bytes
                miss_bytes = eval_res.provenance.missing_bytes
                total_input_bytes = ver_bytes + rec_byte_cnt + miss_bytes
                score_breakdown_dict = asdict(eval_res.score_breakdown)
                val_details_dict = asdict(val_res)
                prov_dict = asdict(eval_res.provenance)
                prov_dict["evidence_size"] = len(content)
                output_dict = {"recovered_bytes": rebuilt_bytes.hex()}

                step0 = ReconstructionStep(
                    step_id="step-0",
                    method="XREF_RECONSTRUCTION",
                    input_fragment_ids=["frag-0"],
                    gap_start=None,
                    gap_end=None,
                    gap_size=None,
                    result="SUCCESS",
                    verified_bytes=ver_bytes,
                    reconstructed_bytes=rec_byte_cnt,
                    validation_status="PASSED" if val_res.valid else "FAILED",
                    confidence=float(eval_res.score_breakdown.total),
                )
                reconstruction_steps.append(step0)
                damage_regions[0] = dam0.model_copy(update={"status": "RECONSTRUCTED"})
            else:
                val_res = val_initial
                status_val = "UNRECOVERABLE"
                ver_bytes = 0
                rec_byte_cnt = 0
                miss_bytes = search_len
                eval_res = evaluate_artifact_confidence(
                    validation_result=val_res,
                    artifact=None,
                    actual_verified_bytes=0,
                    actual_missing_bytes=search_len,
                    is_complete=False,
                )
                score_breakdown_dict = asdict(eval_res.score_breakdown)
                val_details_dict = asdict(val_res)
                prov_dict = asdict(eval_res.provenance)
                output_dict = {"recovered_bytes": ""}

    if not reconstruction_attempted and status_val == "UNRECOVERABLE":
        try:
            raw_frag = content[cand.offset:search_end]
            emit_event("VALIDATION_STARTED", f"Validating format '{fmt}' on raw fragment")
            val_res = validator(raw_frag)
            val_status_str = "PASSED" if val_res.valid else "FAILED"
            emit_event("VALIDATION_COMPLETED", f"Validation {val_status_str}")

            if val_res.valid:
                eval_res = evaluate_artifact_confidence(val_res, artifact=raw_frag)
                emit_event(
                    "CONFIDENCE_CALCULATED",
                    f"Confidence evaluated: total={eval_res.score_breakdown.total}/100, status={eval_res.status.value}",
                )

                status_val = eval_res.status.value
                ver_bytes = span.bound_verified_bytes(eval_res.provenance.verified_bytes)
                rec_byte_cnt = eval_res.provenance.reconstructed_bytes
                miss_bytes = eval_res.provenance.missing_bytes
                score_breakdown_dict = asdict(eval_res.score_breakdown)
                val_details_dict = asdict(val_res)
                prov_dict = asdict(eval_res.provenance)
                output_dict = {"recovered_bytes": raw_frag.hex()}
            else:
                status_val = "UNRECOVERABLE"
                ver_bytes = 0
                rec_byte_cnt = 0
                miss_bytes = search_len
                eval_res = evaluate_artifact_confidence(val_res, actual_verified_bytes=0, actual_missing_bytes=search_len)
                score_breakdown_dict = asdict(eval_res.score_breakdown)
                val_details_dict = asdict(val_res)
                prov_dict = asdict(eval_res.provenance)
                output_dict = {"recovered_bytes": ""}
        except Exception as e:
            val_details_dict = {"error": str(e)}

    output_raw = (
        bytes.fromhex(output_dict["recovered_bytes"])
        if (output_dict and "recovered_bytes" in output_dict)
        else b""
    )
    prov_dict["evidence_start"] = span.evidence_start
    prov_dict["evidence_end"] = span.evidence_end
    prov_dict["coordinate_system"] = "physical_evidence_offsets"
    prov_dict["detection_method"] = cand.detection_method
    prov_dict["relationships"] = [
        {
            "target_candidate_id": r.target_candidate_id,
            "target_format": r.target_format,
            "relationship_type": r.relationship_type,
        }
        for r in getattr(cand, "relationships", ())
    ]
    if scan_meta:
        prov_dict["candidate_cap_enforced"] = scan_meta.get("candidate_cap_enforced", False)
        prov_dict["total_discovered_candidates"] = scan_meta.get("total_discovered_candidates", 0)
        prov_dict["candidates_omitted"] = scan_meta.get("candidates_omitted", 0)

    if len(fragments) == 1 and fragments[0].fragment_id == "frag-0":
        final_len, final_end = span.compute_fragment_bounds(ver_bytes)
        frag0_updated = frag0.model_copy(
            update={
                "length": final_len,
                "end_offset": final_end,
                "verified_bytes": ver_bytes,
                "reconstructed_bytes": rec_byte_cnt,
                "missing_bytes": miss_bytes,
                "validation_status": val_status_str if "val_status_str" in locals() else "UNTESTED",
                "status": (
                    "VERIFIED"
                    if status_val == "FULLY_RECOVERED"
                    else ("UNRECOVERABLE" if status_val == "UNRECOVERABLE" else "PARTIAL")
                ),
            }
        )
        fragments[0] = frag0_updated

    return _finalize_recovery_run(
        run_id=run_id,
        started_at=started_at,
        events=events,
        emit_event=emit_event,
        filename=filename,
        fmt=fmt,
        candidate_id=getattr(cand, "candidate_id", None),
        case_id=case_id,
        artifact_id=artifact_id,
        status_val=status_val,
        ver_bytes=ver_bytes,
        rec_byte_cnt=rec_byte_cnt,
        miss_bytes=miss_bytes,
        fragments=fragments,
        damage_regions=damage_regions,
        reconstruction_steps=reconstruction_steps,
        val_details_dict=val_details_dict,
        score_breakdown_dict=score_breakdown_dict,
        prov_dict=prov_dict,
        output_dict=output_dict,
        output_raw=output_raw,
        detection_mode=detection_mode,
    )


def _recover_direct_fallback(
    filename: str,
    content: bytes,
    case_id: Optional[str] = None,
    artifact_id: Optional[str] = None,
    detection_mode: str = "known_file",
    forced_text_fmt: Optional[str] = None,
    scan_meta: Optional[Dict[str, Any]] = None,
) -> RecoveryRun:
    """Execute direct fallback recovery when zero candidates are detected."""
    run_id = f"run_{uuid.uuid4().hex[:8]}"
    started_at, events, emit_event = _init_trace_context(run_id)

    emit_event("RECOVERY_STARTED", f"Started recovery run for '{filename}'")
    emit_event("SCANNING_STARTED", f"Scanning {len(content)} bytes for format signatures")
    fragments: List[Fragment] = []
    damage_regions: List[DamageRegion] = []
    reconstruction_steps: List[ReconstructionStep] = []

    fmt: str = "unknown"
    status_val: str = "UNRECOVERABLE"
    ver_bytes: int = 0
    rec_byte_cnt: int = 0
    miss_bytes: int = len(content)
    score_breakdown_dict: Dict[str, Any] = {}
    val_details_dict: Dict[str, Any] = {}
    prov_dict: Dict[str, Any] = {}
    output_dict: Optional[Dict[str, Any]] = None
    total_input_bytes: int = len(content)

    # Scenario 3b: Text fragment detection for TXT/CSV evidence
    if (filename.rsplit(".", 1)[-1].lower() in ("txt", "csv")) or forced_text_fmt is not None:
        target_fmt = forced_text_fmt or filename.rsplit(".", 1)[-1].lower()

        emit_event(
            "FRAGMENT_DETECTION_STARTED",
            f"Scanning {len(content)} bytes for {target_fmt.upper()} text fragments",
        )
        detected = detect_text_fragments(content, target_fmt)
        emit_event(
            "FRAGMENT_DETECTION_COMPLETED",
            f"Detected {len(detected)} {target_fmt.upper()} fragment(s) from evidence structure",
            relevant_fragment_ids=[f.fragment_id for f in detected],
        )

        for frag in detected:
            emit_event(
                "FRAGMENT_IDENTIFIED",
                f"Identified {frag.fragment_id} [{frag.offset}..{frag.end_offset}] "
                f"({frag.length} bytes, {frag.line_count} lines)",
                relevant_fragment_ids=[frag.fragment_id],
            )

        if not detected:
            status_val = "UNRECOVERABLE"
            fmt = target_fmt
            ver_bytes = 0
            rec_byte_cnt = 0
            miss_bytes = len(content)
            val_details_dict = {"error": "No text-structured fragment detected"}
            prov_dict = {
                "verified_bytes": 0,
                "reconstructed_bytes": 0,
                "missing_bytes": len(content),
            }
            damage_regions.append(
                DamageRegion(
                    region_id="damage-0",
                    start_offset=0,
                    end_offset=len(content),
                    length=len(content),
                    type="UNRECOVERABLE",
                    status="UNRECOVERABLE",
                    affected_fragment_ids=[],
                )
            )
            emit_event(
                "DAMAGE_DETECTED",
                f"No recoverable text structure in {len(content)} bytes of evidence",
            )
        else:
            fmt = target_fmt
            pairs = select_fragment_pairs(detected)
            fragment_objs = []
            for frag in detected:
                fragment_objs.append(
                    Fragment(
                        fragment_id=frag.fragment_id,
                        offset=frag.offset,
                        length=frag.length,
                        end_offset=frag.end_offset,
                        status="VERIFIED",
                        source="text_structure",
                        format=target_fmt,
                        verified_bytes=frag.length,
                        reconstructed_bytes=0,
                        missing_bytes=0,
                        validation_status="PASSED",
                    )
                )
            fragments.extend(fragment_objs)

            # Record leading non-text bytes if any
            lead_unatt = detected[0].offset
            if lead_unatt > 0:
                damage_regions.append(
                    DamageRegion(
                        region_id="damage-leading",
                        start_offset=0,
                        end_offset=lead_unatt,
                        length=lead_unatt,
                        type="MISSING",
                        status="UNRECOVERABLE",
                        affected_fragment_ids=[detected[0].fragment_id],
                    )
                )

            # Record trailing non-text bytes if any
            trail_unatt = len(content) - detected[-1].end_offset
            if trail_unatt > 0:
                damage_regions.append(
                    DamageRegion(
                        region_id="damage-trailing",
                        start_offset=detected[-1].end_offset,
                        end_offset=len(content),
                        length=trail_unatt,
                        type="MISSING",
                        status="UNRECOVERABLE",
                        affected_fragment_ids=[detected[-1].fragment_id],
                    )
                )

            if pairs:
                frag_a, frag_b, rel = pairs[0]
                emit_event(
                    "FRAGMENT_RELATIONSHIP_IDENTIFIED",
                    f"{rel.relationship_type}: {rel.fragment_a_id} + unknown gap + "
                    f"{rel.fragment_b_id} (observed gap {rel.observed_gap} bytes)",
                    relevant_fragment_ids=[rel.fragment_a_id, rel.fragment_b_id],
                )
                for obj in fragments:
                    if obj.fragment_id == rel.fragment_b_id:
                        obj.relationships.append(
                            FragmentRelationship(
                                source_fragment_id=rel.fragment_a_id,
                                target_fragment_id=rel.fragment_b_id,
                                relationship_type="BOUNDED_GAP",
                                details={
                                    "observed_gap": rel.observed_gap,
                                    "signals": rel.signals,
                                },
                            )
                        )

                emit_event(
                    "RECONSTRUCTION_STARTED",
                    f"Bounded gap search for {target_fmt.upper()} in range [1, 4096]",
                    relevant_fragment_ids=[rel.fragment_a_id, rel.fragment_b_id],
                )
                recon_res = reconstruct_fragment_pair(
                    target_fmt, frag_a.data, frag_b.data, observed_gap=rel.observed_gap
                )
                emit_event(
                    "RECONSTRUCTION_COMPLETED",
                    f"{target_fmt.upper()} fragment reconstruction status "
                    f"'{recon_res.status}': "
                    f"{recon_res.details.get('notice') or recon_res.details.get('reason') or recon_res.details.get('error') or 'no detail provided'}",
                    relevant_fragment_ids=[rel.fragment_a_id, rel.fragment_b_id],
                )

                status_val = recon_res.status
                ver_bytes = recon_res.verified_bytes
                rec_byte_cnt = recon_res.reconstructed_bytes
                miss_bytes = recon_res.missing_bytes
                val_res = recon_res.validation_result
                val_details_dict = asdict(val_res) if val_res else {}
                score_breakdown_dict = {
                    "total": float(
                        (val_res.details or {}).get("confidence_score", 100.0)
                        if val_res
                        else 0.0
                    )
                }
                prov_dict = {
                    "verified_bytes": ver_bytes,
                    "reconstructed_bytes": rec_byte_cnt,
                    "missing_bytes": miss_bytes,
                    "attributed_input_bytes": recon_res.details.get(
                        "fragment_input_bytes", frag_a.length + frag_b.length
                    ),
                    **recon_res.details,
                }
                output_dict = {"recovered_bytes": recon_res.recovered_bytes.hex()}

                reconstruction_steps.append(
                    ReconstructionStep(
                        step_id="step-0",
                        method="BIFRAGMENT_GAP",
                        input_fragment_ids=[rel.fragment_a_id, rel.fragment_b_id],
                        gap_start=frag_a.end_offset,
                        gap_end=frag_b.offset,
                        gap_size=rel.observed_gap,
                        validated_gap_size=recon_res.details.get("selected_gap_size"),
                        result="SUCCESS" if recon_res.success else "FAILED",
                        verified_bytes=ver_bytes,
                        reconstructed_bytes=rec_byte_cnt,
                        missing_bytes=miss_bytes,
                        validation_status="PASSED" if val_res and val_res.valid else "FAILED",
                        confidence=score_breakdown_dict["total"],
                    )
                )
                damage_regions.append(
                    DamageRegion(
                        region_id="damage-0",
                        start_offset=frag_a.end_offset,
                        end_offset=frag_b.offset,
                        length=rel.observed_gap,
                        type="MISSING",
                        status="UNRECOVERABLE",
                        affected_fragment_ids=[rel.fragment_a_id, rel.fragment_b_id],
                    )
                )
                emit_event(
                    "DAMAGE_DETECTED",
                    f"Confirmed physically missing region of {rel.observed_gap} bytes "
                    f"between offset {frag_a.end_offset} and {frag_b.offset}",
                    relevant_fragment_ids=[rel.fragment_a_id, rel.fragment_b_id],
                )
            elif len(detected) >= 2:
                # Multiple detected fragments without joinable pair
                for i in range(len(detected) - 1):
                    g_start = detected[i].end_offset
                    g_end = detected[i + 1].offset
                    g_len = max(0, g_end - g_start)
                    if g_len > 0:
                        damage_regions.append(
                            DamageRegion(
                                region_id=f"damage-gap-{i}",
                                start_offset=g_start,
                                end_offset=g_end,
                                length=g_len,
                                type="MISSING",
                                status="UNRECOVERABLE",
                                affected_fragment_ids=[detected[i].fragment_id, detected[i + 1].fragment_id],
                            )
                        )
                ver_bytes = sum(f.length for f in detected)
                rec_byte_cnt = 0
                miss_bytes = max(0, len(content) - ver_bytes)
                status_val = "PARTIALLY_RECOVERED"
                merged_output = b"".join(f.data for f in detected)
                val_res = validate_artifact(target_fmt, merged_output)
                val_details_dict = asdict(val_res) if val_res else {}
                score_breakdown_dict = {"total": 50.0 if (val_res and val_res.valid) else 20.0}
                prov_dict = {
                    "verified_bytes": ver_bytes,
                    "reconstructed_bytes": 0,
                    "missing_bytes": miss_bytes,
                    "attributed_input_bytes": ver_bytes,
                }
                output_dict = {"recovered_bytes": merged_output.hex()}
            else:
                # Single detected fragment: no seam is provable from the evidence,
                # so no gap is claimed. Reconstruct the surviving text honestly.
                recon_res = reconstruct_artifact(target_fmt, detected[0].data, detection_mode=detection_mode)
                emit_event(
                    "RECONSTRUCTION_COMPLETED",
                    f"{target_fmt.upper()} single-fragment reconstruction status "
                    f"'{recon_res.status}'",
                    relevant_fragment_ids=[detected[0].fragment_id],
                )
                status_val = recon_res.status
                ver_bytes = recon_res.verified_bytes
                rec_byte_cnt = recon_res.reconstructed_bytes
                miss_bytes = recon_res.missing_bytes
                val_res = recon_res.validation_result
                val_details_dict = asdict(val_res) if val_res else {}
                score_breakdown_dict = {
                    "total": float(recon_res.details.get("confidence_score", 100.0))
                }
                prov_dict = {
                    "verified_bytes": ver_bytes,
                    "reconstructed_bytes": rec_byte_cnt,
                    "missing_bytes": miss_bytes,
                    "attributed_input_bytes": len(detected[0].data),
                }
                output_dict = {"recovered_bytes": recon_res.recovered_bytes.hex()}
                # "NONE" is the sentinel meaning "no reconstruction was required".
                # An intact file must not acquire a fake reconstruction step.
                actual_methods = [
                    m for m in recon_res.reconstruction_methods if m != "NONE"
                ]
                for idx_m, m in enumerate(actual_methods):
                    reconstruction_steps.append(
                        ReconstructionStep(
                            step_id=f"step-{idx_m}",
                            method=m,
                            input_fragment_ids=[detected[0].fragment_id],
                            result="SUCCESS" if recon_res.success else "FAILED",
                            verified_bytes=ver_bytes,
                            reconstructed_bytes=rec_byte_cnt,
                            missing_bytes=miss_bytes,
                            validation_status="PASSED" if val_res and val_res.valid else "FAILED",
                            confidence=score_breakdown_dict["total"],
                        )
                    )
                for idx_d, dmg in enumerate(recon_res.damage_regions):
                    damage_regions.append(
                        DamageRegion(
                            region_id=f"damage-{idx_d}",
                            start_offset=dmg.get("offset", 0),
                            end_offset=dmg.get("offset", 0) + dmg.get("length", 0),
                            length=dmg.get("length", 0),
                            type=dmg.get("type", "CORRUPTED"),
                            status=_resolve_damage_region_status(dmg.get("status"), recon_res.success),
                            affected_fragment_ids=[detected[0].fragment_id],
                        )
                    )

            # Accounting base is the artifact byte budget: verified + reconstructed
            # + missing. When a joinable pair was found, the bytes between the two
            # fragments are non-artifact separator data and are excluded from the
            # artifact budget (they are the spatial separation that bounds the
            # missing region, not artifact bytes). With a single fragment there is
            # no such separator, so any evidence byte outside it is unattributed
            # artifact data and is reported missing rather than claimed recovered.
            attributed_input = int(prov_dict.get("attributed_input_bytes", 0) or 0)
            if pairs:
                separator = max(0, len(content) - attributed_input)
                prov_dict["inter_fragment_separator_bytes"] = separator
                prov_dict["unattributed_evidence_bytes"] = 0
            else:
                unattributed = max(0, len(content) - attributed_input)
                prov_dict["unattributed_evidence_bytes"] = unattributed
                if unattributed:
                    miss_bytes += unattributed
                    if status_val == "FULLY_RECOVERED":
                        status_val = "PARTIALLY_RECOVERED"
                    emit_event(
                        "DAMAGE_DETECTED",
                        f"{unattributed} evidence byte(s) fall outside every detected "
                        "text fragment and are reported as missing, not recovered",
                    )
            prov_dict["evidence_size"] = len(content)
            prov_dict["missing_bytes"] = miss_bytes

            is_complete = assess_artifact_completeness(
                fmt=target_fmt,
                content=bytes.fromhex(output_dict["recovered_bytes"]) if (output_dict and "recovered_bytes" in output_dict) else content,
                detection_mode=detection_mode,
                validation_result=val_res,
                missing_bytes=miss_bytes,
                reconstructed_bytes=rec_byte_cnt,
            )
            if (not is_complete or miss_bytes > 0 or rec_byte_cnt > 0 or (detected and any(f.is_truncated for f in detected))) and status_val == "FULLY_RECOVERED":
                status_val = "PARTIALLY_RECOVERED"

            total_input_bytes = ver_bytes + rec_byte_cnt + miss_bytes

            # Structural validity alone must not yield full confidence. Scale it by
            # the fraction of the artifact budget that is actually accounted for, so
            # a file missing most of its bytes can never report near-100% confidence.
            if total_input_bytes:
                coverage = (ver_bytes + rec_byte_cnt) / total_input_bytes
                score_breakdown_dict = {
                    **score_breakdown_dict,
                    "total": round(
                        float(score_breakdown_dict.get("total", 0.0)) * coverage, 2
                    ),
                    "structural_score": score_breakdown_dict.get("total"),
                    "byte_coverage": round(coverage, 6),
                }

    # Scenario 4: Direct format validation or unrecoverable fallback
    else:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin"
        target_fmt = ext if ext in VALIDATORS else "bin"

        emit_event("VALIDATION_STARTED", f"Testing direct format validation for '{target_fmt}'")
        val_res = validate_artifact(target_fmt, content)

        if val_res.valid:
            fmt = target_fmt
            emit_event("VALIDATION_COMPLETED", f"Direct validation passed for '{fmt}'")
            is_complete = assess_artifact_completeness(
                fmt=target_fmt,
                content=content,
                detection_mode=detection_mode,
                validation_result=val_res,
                missing_bytes=0,
                reconstructed_bytes=0,
            )
            eval_res = evaluate_artifact_confidence(val_res, artifact=content, is_complete=is_complete)
            emit_event(
                "CONFIDENCE_CALCULATED",
                f"Confidence evaluated: total={eval_res.score_breakdown.total}/100, status={eval_res.status.value}",
            )

            status_val = eval_res.status.value
            if (not is_complete) and status_val == "FULLY_RECOVERED":
                status_val = "PARTIALLY_RECOVERED"
            ver_bytes = len(content)
            rec_byte_cnt = 0
            miss_bytes = 0
            score_breakdown_dict = asdict(eval_res.score_breakdown)
            val_details_dict = asdict(val_res)
            prov_dict = asdict(eval_res.provenance)
            output_dict = {"recovered_bytes": content.hex()}

            frag0 = Fragment(
                fragment_id="frag-0",
                offset=0,
                length=len(content),
                end_offset=len(content),
                status="VERIFIED",
                source="direct_validation",
                format=fmt,
                verified_bytes=ver_bytes,
                reconstructed_bytes=0,
                missing_bytes=0,
                validation_status="PASSED",
            )
            fragments.append(frag0)
        elif target_fmt == "txt" or ext == "txt":
            recon_res = reconstruct_artifact("txt", content, detection_mode=detection_mode)
            if recon_res.success:
                fmt = "txt"
                emit_event("RECONSTRUCTION_STARTED", "Attempting deterministic TXT format reconstruction on raw file")
                emit_event("RECONSTRUCTION_COMPLETED", f"TXT reconstruction completed with status '{recon_res.status}'")
                status_val = recon_res.status
                ver_bytes = recon_res.verified_bytes
                rec_byte_cnt = recon_res.reconstructed_bytes
                miss_bytes = recon_res.missing_bytes
                val_res = recon_res.validation_result or validate_artifact("txt", recon_res.recovered_bytes)
                val_status_str = "PASSED" if val_res.valid else "FAILED"
                val_details_dict = asdict(val_res)
                output_dict = {"recovered_bytes": recon_res.recovered_bytes.hex()}
                score_breakdown_dict = {"total": recon_res.details.get("confidence_score", 100.0)}

                is_complete = assess_artifact_completeness(
                    fmt="txt",
                    content=recon_res.recovered_bytes,
                    detection_mode=detection_mode,
                    validation_result=val_res,
                    missing_bytes=miss_bytes,
                    reconstructed_bytes=rec_byte_cnt,
                )
                if (not is_complete or miss_bytes > 0 or rec_byte_cnt > 0) and status_val == "FULLY_RECOVERED":
                    status_val = "PARTIALLY_RECOVERED"

                frag0 = Fragment(
                    fragment_id="frag-0",
                    offset=0,
                    length=len(content),
                    end_offset=len(content),
                    status="PARTIAL",
                    source="direct_reconstruction",
                    format="txt",
                    verified_bytes=ver_bytes,
                    reconstructed_bytes=rec_byte_cnt,
                    missing_bytes=miss_bytes,
                    validation_status=val_status_str,
                )
                fragments.append(frag0)

                for idx_m, m in enumerate(recon_res.reconstruction_methods):
                    step = ReconstructionStep(
                        step_id=f"step-{idx_m}",
                        method=m,
                        input_fragment_ids=["frag-0"],
                        gap_start=None,
                        gap_end=None,
                        gap_size=None,
                        result="SUCCESS" if recon_res.success else "FAILED",
                        verified_bytes=ver_bytes,
                        reconstructed_bytes=rec_byte_cnt,
                        missing_bytes=miss_bytes,
                        validation_status=val_status_str,
                        confidence=float(recon_res.details.get("confidence_score", 100.0)),
                    )
                    reconstruction_steps.append(step)

                for idx_d, dmg in enumerate(recon_res.damage_regions):
                    damage_regions.append(
                        DamageRegion(
                            region_id=f"damage-{idx_d}",
                            start_offset=dmg.get("offset", 0),
                            end_offset=dmg.get("offset", 0) + dmg.get("length", 0),
                            length=dmg.get("length", 0),
                            type=dmg.get("type", "CORRUPTED"),
                            status=_resolve_damage_region_status(dmg.get("status"), recon_res.success),
                            affected_fragment_ids=["frag-0"],
                        )
                    )
            else:
                fmt = ext
                status_val = "UNRECOVERABLE"
                val_details_dict = {"error": "TXT reconstruction failed"}
                # The evidence is not recoverable text. Record the whole buffer as
                # an unrecoverable damage region rather than returning a bare
                # status with no record of why.
                ver_bytes = 0
                rec_byte_cnt = 0
                miss_bytes = len(content)
                damage_regions.append(
                    DamageRegion(
                        region_id="damage-0",
                        start_offset=0,
                        end_offset=len(content),
                        length=len(content),
                        type="BINARY_GARBAGE",
                        status="UNRECOVERABLE",
                        details="Evidence yielded no recoverable text content",
                        affected_fragment_ids=["frag-0"],
                    )
                )
                total_input_bytes = len(content)
        elif target_fmt == "json" or ext == "json":
            # JSON is never allowed to fall through to the CSV/TXT validators
            # below: a truncated or malformed JSON document must be reported as
            # JSON (with honest V/R/M) rather than silently reinterpreted.
            emit_event(
                "RECONSTRUCTION_STARTED",
                "Attempting deterministic JSON structural reconstruction",
            )
            recon_res = reconstruct_artifact("json", content)
            emit_event(
                "RECONSTRUCTION_COMPLETED",
                f"JSON reconstruction completed with status '{recon_res.status}'",
            )

            ver_bytes = recon_res.verified_bytes
            rec_byte_cnt = recon_res.reconstructed_bytes
            miss_bytes = recon_res.missing_bytes
            # The artifact budget is verified + reconstructed + missing (the
            # convention enforced by tests/test_fragment_pipeline.py); the actual
            # uploaded evidence size is preserved separately as evidence_size.
            total_input_bytes = ver_bytes + rec_byte_cnt + miss_bytes

            out_bytes = recon_res.recovered_bytes
            val_res = recon_res.validation_result or validate_artifact("json", out_bytes)
            val_status_str = "PASSED" if val_res.valid else "FAILED"
            val_details_dict = asdict(val_res)
            output_dict = {"recovered_bytes": out_bytes.hex()}

            eval_res = evaluate_artifact_confidence(
                validation_result=val_res,
                artifact=out_bytes,
                actual_verified_bytes=ver_bytes,
                actual_reconstructed_bytes=rec_byte_cnt,
                actual_missing_bytes=miss_bytes,
            )
            score_breakdown_dict = asdict(eval_res.score_breakdown)
            prov_dict = asdict(eval_res.provenance)
            prov_dict["evidence_size"] = len(content)
            prov_dict["reconstruction_method"] = recon_res.details.get(
                "reconstruction_method", "JSON_STRUCTURAL_RECONSTRUCTION"
            )
            # The reconstructor holds the forensically-correct status: it knows
            # whether bytes were structurally reconstructed or left missing, so
            # FULLY_RECOVERED is never claimed when R>0 or M>0.
            status_val = recon_res.status
            fmt = "json"

            fragments.append(
                Fragment(
                    fragment_id="frag-0",
                    offset=0,
                    length=len(content),
                    end_offset=len(content),
                    status="VERIFIED" if miss_bytes == 0 and rec_byte_cnt == 0 else "PARTIAL",
                    source="direct_reconstruction",
                    format="json",
                    verified_bytes=ver_bytes,
                    reconstructed_bytes=rec_byte_cnt,
                    missing_bytes=miss_bytes,
                    validation_status=val_status_str,
                )
            )

            for idx_m, m in enumerate(recon_res.reconstruction_methods):
                reconstruction_steps.append(
                    ReconstructionStep(
                        step_id=f"step-{idx_m}",
                        method=m,
                        input_fragment_ids=["frag-0"],
                        gap_start=None,
                        gap_end=None,
                        gap_size=None,
                        result="SUCCESS" if recon_res.success else "FAILED",
                        verified_bytes=ver_bytes,
                        reconstructed_bytes=rec_byte_cnt,
                        missing_bytes=miss_bytes,
                        validation_status=val_status_str,
                        confidence=float(score_breakdown_dict.get("total", 0.0)),
                    )
                )

            for idx_d, dmg in enumerate(recon_res.damage_regions):
                damage_regions.append(
                    DamageRegion(
                        region_id=f"damage-{idx_d}",
                        start_offset=dmg.get("offset", 0),
                        end_offset=dmg.get("offset", 0) + dmg.get("length", 0),
                        length=dmg.get("length", 0),
                        type=dmg.get("type", "CORRUPTED"),
                        status=_resolve_damage_region_status(dmg.get("status"), recon_res.success),
                        affected_fragment_ids=["frag-0"],
                    )
                )
        else:
            matched_fmt = None
            for test_fmt in ["json", "xml", "png", "jpeg", "csv", "txt"]:
                val_test = validate_artifact(test_fmt, content)
                if val_test.valid:
                    matched_fmt = test_fmt
                    val_res = val_test
                    break

            if matched_fmt:
                fmt = matched_fmt
                emit_event("VALIDATION_COMPLETED", f"Direct validation passed for format '{fmt}'")
                is_complete = assess_artifact_completeness(
                    fmt=fmt,
                    content=content,
                    detection_mode=detection_mode,
                    validation_result=val_res,
                )
                eval_res = evaluate_artifact_confidence(val_res, artifact=content, is_complete=is_complete)
                emit_event(
                    "CONFIDENCE_CALCULATED",
                    f"Confidence evaluated: total={eval_res.score_breakdown.total}/100, status={eval_res.status.value}",
                )

                status_val = eval_res.status.value
                if (not is_complete) and status_val == "FULLY_RECOVERED":
                    status_val = "PARTIALLY_RECOVERED"
                ver_bytes = len(content)
                # The evidence validated as-is, so nothing was reconstructed.
                # Previously this counted every content byte as reconstructed,
                # which broke the verified+reconstructed+missing identity and
                # mislabelled pass-through results as full reconstruction.
                rec_byte_cnt = 0
                miss_bytes = 0
                score_breakdown_dict = asdict(eval_res.score_breakdown)
                val_details_dict = asdict(val_res)
                prov_dict = asdict(eval_res.provenance)
                output_dict = {"recovered_bytes": content.hex()}

                frag0 = Fragment(
                    fragment_id="frag-0",
                    offset=0,
                    length=len(content),
                    end_offset=len(content),
                    status="VERIFIED",
                    source="direct_validation",
                    format=fmt,
                    verified_bytes=ver_bytes,
                    reconstructed_bytes=0,
                    missing_bytes=0,
                    validation_status="PASSED",
                )
                fragments.append(frag0)
            else:
                fmt = ext
                status_val = "UNRECOVERABLE"
                emit_event("VALIDATION_COMPLETED", "Direct validation failed across all formats")

                eval_res = evaluate_artifact_confidence(val_res)
                emit_event(
                    "CONFIDENCE_CALCULATED",
                    f"Confidence evaluated: total={eval_res.score_breakdown.total}/100, status={eval_res.status.value}",
                )

                score_breakdown_dict = asdict(eval_res.score_breakdown)
                val_details_dict = asdict(val_res)
                prov_dict = asdict(eval_res.provenance)
                ver_bytes = 0
                rec_byte_cnt = 0
                miss_bytes = len(content)

                dam0 = DamageRegion(
                    region_id="damage-0",
                    start_offset=0,
                    end_offset=len(content),
                    length=len(content),
                    type="CORRUPTED",
                    status="UNRECOVERABLE",
                    affected_fragment_ids=[],
                )
                damage_regions.append(dam0)
                emit_event(
                    "DAMAGE_DETECTED",
                    f"Entire evidence buffer of {len(content)} bytes is severely corrupt/unrecoverable",
                )

    output_raw = bytes.fromhex(output_dict["recovered_bytes"]) if (output_dict and "recovered_bytes" in output_dict) else content
    prov_dict["evidence_start"] = 0
    prov_dict["evidence_end"] = len(content)
    prov_dict["coordinate_system"] = "whole_buffer_fallback"
    prov_dict["relationships"] = []
    if scan_meta is None:
        scan_meta = get_last_scan_metadata()
    if scan_meta:
        prov_dict["candidate_cap_enforced"] = scan_meta.get("candidate_cap_enforced", False)
        prov_dict["total_discovered_candidates"] = scan_meta.get("total_discovered_candidates", 0)
        prov_dict["candidates_omitted"] = scan_meta.get("candidates_omitted", 0)

    return _finalize_recovery_run(
        run_id=run_id,
        started_at=started_at,
        events=events,
        emit_event=emit_event,
        filename=filename,
        fmt=fmt,
        candidate_id=None,
        case_id=case_id,
        artifact_id=artifact_id,
        status_val=status_val,
        ver_bytes=ver_bytes,
        rec_byte_cnt=rec_byte_cnt,
        miss_bytes=miss_bytes,
        fragments=fragments,
        damage_regions=damage_regions,
        reconstruction_steps=reconstruction_steps,
        val_details_dict=val_details_dict,
        score_breakdown_dict=score_breakdown_dict,
        prov_dict=prov_dict,
        output_dict=output_dict,
        output_raw=output_raw,
        detection_mode=detection_mode,
    )


def execute_traced_recoveries(
    filename: str,
    content: bytes,
    case_id: Optional[str] = None,
    detection_mode: Optional[str] = None,
    candidates: Optional[List[Candidate]] = None,
) -> List[RecoveryRun]:
    """Execute canonical traced forensic recovery runs supporting multiple candidates.

    - Scans evidence once if candidates are not explicitly provided.
    - Deterministically orders candidates by (offset, header_length, candidate_id).
    - Preserves complete candidate isolation: failure of one does not affect others.
    - Preserves independent per-candidate V/R/M accounting.
    - Enforces completeness and status invariants.
    - Preserves bifragment ambiguity when evidence cannot discriminate.

    Args:
        filename: Name of the evidence file.
        content: Raw evidence bytes.
        case_id: Optional associated case identifier.
        detection_mode: Optional detection mode ('known_file', 'blind', 'synthetic_harness').
        candidates: Optional explicit list of Candidate objects to evaluate.

    Returns:
        List of stored RecoveryRun instances for all evaluated candidates.
    """
    if detection_mode is None:
        if SYNTHETIC_START_MARKER in content:
            detection_mode = "synthetic_harness"
        else:
            ext_check = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext_check in ("txt", "csv", "json", "xml", "png", "jpg", "jpeg", "pdf") and not any(
                filename.lower().startswith(prefix) for prefix in ("carved_", "blind_", "dump", "unallocated", "raw_")
            ):
                detection_mode = "known_file"
            else:
                detection_mode = "blind"

    # Resolve filename extension hint
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    ext_fmt_map = {
        "txt": "txt",
        "csv": "csv",
        "json": "json",
        "xml": "xml",
        "png": "png",
        "jpg": "jpeg",
        "jpeg": "jpeg",
        "pdf": "pdf",
    }
    ext_fmt = ext_fmt_map.get(ext)

    forced_text_fmt: Optional[str] = None

    if candidates is not None:
        if len(candidates) == 0:
            return []
        total_discovered = len(candidates)
        cap_enforced = total_discovered > 250
        omitted = max(0, total_discovered - 250)
        scan_meta = {
            "total_discovered_candidates": total_discovered,
            "candidate_cap_enforced": cap_enforced,
            "candidates_omitted": omitted,
        }
        candidates_to_process = list(candidates)
        if cap_enforced:
            candidates_to_process = candidates_to_process[:250]
    else:
        candidates_to_process = scan_evidence(content)
        scan_meta = get_last_scan_metadata()

        # Filter out spurious candidates when unambiguous evidence signatures or hints exist
        # ONLY enforce format suppression when running in known_file mode with a specific format hint
        if detection_mode == "known_file":
            if ext_fmt == "pdf":
                pdf_cands = [c for c in candidates_to_process if c.format == "pdf"]
                if pdf_cands:
                    candidates_to_process = pdf_cands
            elif ext_fmt == "png":
                png_cands = [c for c in candidates_to_process if c.format == "png"]
                if png_cands:
                    candidates_to_process = png_cands
            elif ext_fmt in ("txt", "csv", "json") and not any(c.detection_method == "synthetic_boundary" for c in candidates_to_process):
                matching_cands = [c for c in candidates_to_process if c.format == ext_fmt]
                if matching_cands:
                    candidates_to_process = matching_cands
                else:
                    candidates_to_process = []

            if not any(c.detection_method == "synthetic_boundary" for c in candidates_to_process):
                if not (b"%PDF-" in content or PNG_SIGNATURE in content or content.startswith(b"\xff\xd8") or content.startswith(b"<?xml")):
                    probe_csv = detect_text_fragments(content, "csv")
                    probe_txt = detect_text_fragments(content, "txt")
                    if len(probe_csv) >= 2 and (ext_fmt == "csv" or not ext_fmt):
                        candidates_to_process = []
                        forced_text_fmt = "csv"
                    elif len(probe_txt) >= 2 and (ext_fmt == "txt" or not ext_fmt):
                        candidates_to_process = []
                        forced_text_fmt = "txt"

    # Deterministic sorting: offset ascending, header length ascending, candidate_id ascending
    candidates_to_process.sort(
        key=lambda c: (
            getattr(c, "offset", 0),
            getattr(c, "detected_header_length", 0),
            getattr(c, "candidate_id", ""),
        )
    )

    if not candidates_to_process:
        fallback_run = _recover_direct_fallback(
            filename=filename,
            content=content,
            case_id=case_id,
            artifact_id=None,
            detection_mode=detection_mode,
            forced_text_fmt=forced_text_fmt,
            scan_meta=scan_meta,
        )
        return [fallback_run]

    runs: List[RecoveryRun] = []
    idx = 0
    while idx < len(candidates_to_process):
        cand = candidates_to_process[idx]
        try:
            # Check for bifragment candidate pairing: consecutive candidates of same format without end offsets
            # that form a validated bifragment or are explicitly designated bifragments
            cand2 = candidates_to_process[idx + 1] if idx + 1 < len(candidates_to_process) else None
            is_same_format_unbounded = (
                getattr(cand, "estimated_end_offset", None) is None
                and cand2 is not None
                and getattr(cand2, "estimated_end_offset", None) is None
                and getattr(cand2, "format", "") == getattr(cand, "format", "")
            )
            should_pair = False
            precomputed_recon = None
            if is_same_format_unbounded and cand2 is not None:
                cand3 = candidates_to_process[idx + 2] if idx + 2 < len(candidates_to_process) else None
                next_cand_offset = cand3.offset if cand3 is not None else None
                fmt = cand.format
                validator = VALIDATORS.get(fmt, lambda data: validate_artifact(fmt, data))
                raw_between = content[cand.offset:cand2.offset]
                frag_a_bytes = raw_between.rstrip(b"\x00") or raw_between
                frag_b_bytes = content[cand2.offset:next_cand_offset] if next_cand_offset is not None else content[cand2.offset:]

                is_explicit_bifrag = (
                    any(term in filename.lower() for term in ("bifrag", "split"))
                    or any("bifrag" in getattr(r, "relationship_type", "").lower() for r in getattr(cand, "relationships", ()))
                )

                # In blind mode, plain text candidates are independent runs unless explicitly indicated
                allow_text_blind_pair = detection_mode == "known_file" or is_explicit_bifrag
                if fmt in ("txt", "csv") and not allow_text_blind_pair:
                    should_pair = False
                else:
                    try:
                        precomputed_recon = reconstruct_bifragment(
                            frag_a_bytes, frag_b_bytes, validator=validator, min_gap=1, max_gap=4096
                        )
                        if precomputed_recon.success or is_explicit_bifrag:
                            should_pair = True
                    except Exception:
                        if is_explicit_bifrag:
                            should_pair = True

            if should_pair and cand2 is not None:
                pair_run = _recover_bifragment_candidate_pair(
                    filename=filename,
                    content=content,
                    cand=cand,
                    cand2=cand2,
                    case_id=case_id,
                    detection_mode=detection_mode,
                    scan_meta=scan_meta,
                    precomputed_recon=precomputed_recon,
                    next_offset=next_cand_offset,
                )
                runs.append(pair_run)
                idx += 2
            elif getattr(cand, "estimated_end_offset", None) is not None:
                contig_run = _recover_contiguous_candidate(
                    filename=filename,
                    content=content,
                    cand=cand,
                    case_id=case_id,
                    detection_mode=detection_mode,
                    scan_meta=scan_meta,
                )
                runs.append(contig_run)
                idx += 1
            else:
                # Standalone candidate without estimated end offset (bound by next candidate or EOF)
                next_offset = (
                    getattr(candidates_to_process[idx + 1], "offset", None)
                    if idx + 1 < len(candidates_to_process)
                    else None
                )
                standalone_run = _recover_standalone_candidate(
                    filename=filename,
                    content=content,
                    cand=cand,
                    case_id=case_id,
                    detection_mode=detection_mode,
                    next_offset=next_offset,
                    scan_meta=scan_meta,
                )
                runs.append(standalone_run)
                idx += 1
        except Exception as exc:
            # True failure isolation: record error run and proceed to next candidate
            err_run = _create_error_recovery_run(
                filename=filename,
                cand=cand,
                error=exc,
                case_id=case_id,
                detection_mode=detection_mode or "known_file",
                scan_meta=scan_meta,
            )
            runs.append(err_run)
            idx += 1

    return runs


# Canonical alias for compatibility
execute_traced_multi_recovery = execute_traced_recoveries




def execute_traced_recovery(
    filename: str,
    content: bytes,
    case_id: Optional[str] = None,
    artifact_id: Optional[str] = None,
    detection_mode: Optional[str] = None,
    candidates: Optional[List[Candidate]] = None,
) -> RecoveryRun:
    """Execute a single-candidate traced forensic recovery run over *content*.

    Maintains full backward compatibility for existing callers. Delegates to
    execute_traced_recoveries and returns the primary RecoveryRun selected using
    the canonical candidate ranking (_rank_candidate).

    Args:
        filename: Name of the evidence file.
        content: Raw evidence bytes.
        case_id: Optional associated case identifier.
        artifact_id: Optional associated artifact identifier.
        detection_mode: Optional detection mode ('known_file', 'blind', 'synthetic_harness').
        candidates: Optional explicit list of Candidate objects to evaluate.

    Returns:
        Stored RecoveryRun instance containing the real forensic trace.
    """
    runs = execute_traced_recoveries(
        filename=filename,
        content=content,
        case_id=case_id,
        detection_mode=detection_mode,
        candidates=candidates,
    )
    if runs:
        if len(runs) == 1:
            primary_run = runs[0]
        else:
            # Resolve extension hint for candidate ranking
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            ext_fmt_map = {
                "txt": "txt",
                "csv": "csv",
                "json": "json",
                "xml": "xml",
                "png": "png",
                "jpg": "jpeg",
                "jpeg": "jpeg",
                "pdf": "pdf",
            }
            ext_fmt = ext_fmt_map.get(ext)

            cands_to_rank = list(candidates) if candidates is not None else scan_evidence(content)
            if cands_to_rank:
                cands_to_rank.sort(key=lambda c: _rank_candidate(c, ext_fmt), reverse=True)
                top_cand_id = getattr(cands_to_rank[0], "candidate_id", None)
                matched_run = next((r for r in runs if r.candidate_id == top_cand_id), None)
                primary_run = matched_run or runs[0]
            else:
                primary_run = runs[0]

        if artifact_id is not None:
            store.link_artifact_to_run(artifact_id, primary_run.run_id)
        return primary_run

    # Defensive fallback when no runs produced
    fallback_run = _recover_direct_fallback(
        filename=filename,
        content=content,
        case_id=case_id,
        artifact_id=None,
        detection_mode=detection_mode or "blind",
    )
    if artifact_id is not None:
        store.link_artifact_to_run(artifact_id, fallback_run.run_id)
    return fallback_run
