"""
analysis.py — Analysis API router orchestrating canonical forensic recovery.
"""

from __future__ import annotations

import hashlib
import threading
from typing import List, Optional, Dict, Set
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from backend.app.models.artifact import ArtifactResponse
from backend.app.store import store
from backend.app.recovery.tracer import execute_traced_recoveries
from backend.app.recovery.adapter import (
    recovery_run_to_artifact_response,
    extract_recovered_bytes,
)


class AnalysisSummaryResponse(BaseModel):
    """Analysis execution summary response model."""

    case_id: str
    status: str = "COMPLETED"
    artifact_count: int
    artifacts: List[ArtifactResponse]


router = APIRouter(prefix="/cases", tags=["analysis"])

# Concurrency guard for case analysis operations
_analysis_lock = threading.Lock()


@router.post("/{case_id}/analyze", response_model=AnalysisSummaryResponse, status_code=status.HTTP_200_OK)
def analyze_case(case_id: str) -> AnalysisSummaryResponse:
    """Execute the canonical traced recovery engine for a case's uploaded evidence."""
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    evidence_bytes = store.get_evidence_bytes(case_id)
    if evidence_bytes is None or len(evidence_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No evidence uploaded for case '{case_id}'",
        )

    # 1. Determine evidence filename hint and hash
    filename = case.evidence.filename if case.evidence else "evidence.img"
    evidence_sha256 = (
        case.evidence.sha256
        if (case.evidence and case.evidence.sha256)
        else hashlib.sha256(evidence_bytes).hexdigest()
    )

    # 2. Invoke Canonical Traced Recovery Engine
    # Executed before store mutation so failures never corrupt or destroy prior valid state (Test 6)
    runs = execute_traced_recoveries(
        filename=filename,
        content=evidence_bytes,
        case_id=case_id,
    )

    with _analysis_lock:
        current_case = store.get_case(case_id)
        if current_case is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case '{case_id}' not found",
            )

        # 3. Retrieve existing artifacts for this case to reconcile previous results
        existing_artifacts = store.get_case_artifacts(case_id) or []

        # Map existing artifacts specifically belonging to this evidence file
        # Artifacts from other evidence files in multi-evidence cases are preserved (Test 4)
        evidence_existing_map: Dict[str, ArtifactResponse] = {}
        for ea in existing_artifacts:
            ea_ev_file = (
                ea.metadata.get("evidence_filename")
                or ea.metadata.get("original_filename")
                or getattr(ea, "original_filename", None)
            )
            ea_sha = ea.metadata.get("evidence_sha256")

            if ea_ev_file == filename or (ea_sha is not None and ea_sha == evidence_sha256):
                cand_id = ea.metadata.get("candidate_id")
                if cand_id:
                    evidence_existing_map[f"cand:{cand_id}"] = ea
                run_idx = ea.metadata.get("run_index")
                if run_idx is not None:
                    evidence_existing_map[f"idx:{run_idx}"] = ea
                ev_start = ea.metadata.get("evidence_start")
                if ev_start is not None:
                    evidence_existing_map[f"span:{ea.format}:{ev_start}"] = ea
                evidence_existing_map[ea.artifact_id] = ea

        # 4. Adapt Canonical RecoveryRuns to Case Artifacts with stable/deterministic IDs
        recovered_artifacts: List[ArtifactResponse] = []
        new_artifact_ids: Set[str] = set()

        for idx, run in enumerate(runs):
            cand_key = run.candidate_id if run.candidate_id is not None else f"run_{idx}"
            det_hash = hashlib.sha256(
                f"{case_id}:{filename}:{cand_key}:{run.format}".encode("utf-8")
            ).hexdigest()[:8]
            det_artifact_id = f"art_{det_hash}"

            # Attempt to reuse existing artifact_id for stability across repeated analyses
            matched_art: Optional[ArtifactResponse] = None
            if run.candidate_id and f"cand:{run.candidate_id}" in evidence_existing_map:
                matched_art = evidence_existing_map[f"cand:{run.candidate_id}"]
            elif f"idx:{idx}" in evidence_existing_map and evidence_existing_map[f"idx:{idx}"].format == run.format:
                matched_art = evidence_existing_map[f"idx:{idx}"]
            elif run.provenance and "evidence_start" in run.provenance:
                ev_start = run.provenance["evidence_start"]
                if f"span:{run.format}:{ev_start}" in evidence_existing_map:
                    matched_art = evidence_existing_map[f"span:{run.format}:{ev_start}"]
            elif det_artifact_id in evidence_existing_map:
                matched_art = evidence_existing_map[det_artifact_id]

            if matched_art is not None and matched_art.artifact_id not in new_artifact_ids:
                artifact_id = matched_art.artifact_id
            else:
                artifact_id = det_artifact_id

            new_artifact_ids.add(artifact_id)

            art_resp = recovery_run_to_artifact_response(
                run,
                case_id=case_id,
                artifact_id=artifact_id,
            )

            # Preserve prior ai_summary if present
            if matched_art is not None and matched_art.ai_summary is not None and art_resp.ai_summary is None:
                art_resp.ai_summary = matched_art.ai_summary

            art_resp.metadata["original_filename"] = filename
            art_resp.metadata["evidence_filename"] = filename
            art_resp.metadata["evidence_sha256"] = evidence_sha256
            art_resp.metadata["candidate_id"] = run.candidate_id
            art_resp.metadata["run_index"] = idx

            store.add_artifact(art_resp)
            store.link_artifact_to_run(artifact_id, run.run_id)
            run.artifact_id = artifact_id
            store.add_recovery_run(run)
            payload = extract_recovered_bytes(run)
            store.store_artifact_bytes(artifact_id, payload)
            recovered_artifacts.append(art_resp)

        # 5. Clean up stale artifacts belonging specifically to THIS evidence file
        # that are no longer produced (Test 5: Reanalysis after evidence changes)
        for ea in existing_artifacts:
            ea_ev_file = (
                ea.metadata.get("evidence_filename")
                or ea.metadata.get("original_filename")
                or getattr(ea, "original_filename", None)
            )
            ea_sha = ea.metadata.get("evidence_sha256")
            is_this_evidence = (
                ea_ev_file == filename
                or (ea_sha is not None and ea_sha == evidence_sha256)
            )
            if is_this_evidence and ea.artifact_id not in new_artifact_ids:
                store.delete_artifact(ea.artifact_id)

    return AnalysisSummaryResponse(
        case_id=case_id,
        status="COMPLETED",
        artifact_count=len(recovered_artifacts),
        artifacts=recovered_artifacts,
    )
