"""
artifacts.py — Artifacts API router for case artifact listing and detail retrieval.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
import hashlib
import json
from fastapi import APIRouter, HTTPException, status, Response, Body

from backend.app.models.artifact import ArtifactResponse
from backend.app.store import store
from backend.app.scoring.explainer import explain_artifact
from backend.app.api.file_recovery import sanitize_filename, format_content_disposition
from backend.app.recovery.artifact_integrity import verify_artifact_download_integrity

router = APIRouter(tags=["artifacts"])


from backend.app.scoring.classifier import classify_artifact
from backend.app.scoring.priority import determine_priority
import json

def _enrich_artifact(artifact: ArtifactResponse) -> ArtifactResponse:
    enriched = artifact.model_copy()
    
    # Extract filename from preview
    preview = enriched.content_preview or ""
    if "filename: " in preview:
        try:
            fn = preview.split("filename: ")[1].split("\n")[0].strip()
            if fn:
                if not enriched.metadata:
                    enriched.metadata = {}
                enriched.metadata["filename"] = fn
        except:
            pass

    if enriched.category is None:
        enriched.category = classify_artifact(enriched.format, enriched.content_preview)
    if enriched.priority is None:
        enriched.priority = determine_priority(enriched.category, enriched.content_preview, enriched.status)

    return enriched


@router.get("/cases/{case_id}/artifacts", response_model=List[ArtifactResponse], status_code=status.HTTP_200_OK)
def list_case_artifacts(case_id: str) -> List[ArtifactResponse]:
    """Retrieve all recovered artifacts associated with a specific case."""

    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    artifacts = store.get_case_artifacts(case_id)
    if artifacts is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )
    return [_enrich_artifact(art) for art in artifacts]


@router.get("/artifacts/{artifact_id}", response_model=ArtifactResponse, status_code=status.HTTP_200_OK)
def get_artifact_detail(artifact_id: str) -> ArtifactResponse:
    """Retrieve details for a single recovered artifact by artifact_id."""
    artifact = store.get_artifact(artifact_id)
    if artifact is not None:
        return _enrich_artifact(artifact)

    meta = store.get_recovered_file_metadata(artifact_id)
    if meta is not None:
        from backend.app.models.artifact import ArtifactRecord
        rec = ArtifactRecord.from_file_recovery_dict(meta)
        return _enrich_artifact(rec.to_artifact_response())

    run = store.get_recovery_run(artifact_id) or store.get_recovery_run_by_artifact(artifact_id)
    if run is not None:
        from backend.app.api.analysis import recovery_run_to_artifact_response
        art_resp = recovery_run_to_artifact_response(run)
        return _enrich_artifact(art_resp)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Artifact '{artifact_id}' not found",
    )


@router.post("/artifacts/{artifact_id}/explain", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
def explain_artifact_route(artifact_id: str, body: Optional[Dict[str, Any]] = Body(None)) -> Dict[str, Any]:
    """Generate or retrieve a cached evidence interpretation for an artifact."""
    artifact = store.get_artifact(artifact_id)
    if artifact is not None:
        explanation = explain_artifact(artifact_id, artifact)
        # Store ai_summary onto artifact to populate next fetch
        artifact.ai_summary = explanation
        try:
            exp_str = json.dumps(explanation) if isinstance(explanation, dict) else str(explanation)
            store.update_artifact_ai_summary(artifact_id, exp_str)
        except Exception:
            pass
        return explanation

    # Check recovered file metadata
    file_meta = store.get_recovered_file_metadata(artifact_id)
    if file_meta is not None:
        explanation = explain_artifact(artifact_id, file_meta)
        try:
            exp_str = json.dumps(explanation) if isinstance(explanation, dict) else str(explanation)
            store.update_artifact_ai_summary(artifact_id, exp_str)
        except Exception:
            pass
        return explanation

    # Check recovery runs
    run = store.get_recovery_run(artifact_id) or store.get_recovery_run_by_artifact(artifact_id)
    if run is not None:
        explanation = explain_artifact(artifact_id, run)
        try:
            exp_str = json.dumps(explanation) if isinstance(explanation, dict) else str(explanation)
            target_id = run.artifact_id or artifact_id
            store.update_artifact_ai_summary(target_id, exp_str)
        except Exception:
            pass
        return explanation

    if body and isinstance(body, dict):
        return explain_artifact(artifact_id, body)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Artifact '{artifact_id}' not found",
    )


@router.get("/artifacts/{artifact_id}/download", status_code=status.HTTP_200_OK)
def download_artifact(artifact_id: str) -> Response:
    """Download raw byte buffer of a recovered case artifact with strict SHA-256 integrity verification."""
    record = store.get_artifact_record(artifact_id)
    if record is None:
        run = store.get_recovery_run(artifact_id)
        if run and run.artifact_id:
            record = store.get_artifact_record(run.artifact_id)

    content = None
    if record is not None:
        content = store.get_artifact_bytes(record.artifact_id)
    if content is None or len(content) == 0:
        content = store.get_artifact_bytes(artifact_id)

    verified_bytes = verify_artifact_download_integrity(record, content, artifact_id, context="artifact")

    fmt_ext = record.format if record and record.format else "bin"
    raw_filename = (record.recovered_filename if record else None) or f"recovered_artifact_{artifact_id}.{fmt_ext}"
    filename = sanitize_filename(raw_filename, default=f"recovered_artifact_{artifact_id}.bin")

    fmt_key = (record.format if record else "").lower()
    mime_map = {
        "txt": "text/plain",
        "csv": "text/csv",
        "json": "application/json",
        "xml": "application/xml",
        "png": "image/png",
        "jpeg": "image/jpeg",
        "jpg": "image/jpeg",
        "pdf": "application/pdf",
        "zip": "application/zip",
    }
    media_type = mime_map.get(fmt_key, "application/octet-stream")
    sha_val = (record.sha256 if record and record.sha256 else hashlib.sha256(verified_bytes).hexdigest()).lower()

    return Response(
        content=verified_bytes,
        media_type=media_type,
        headers={
            "Content-Disposition": format_content_disposition(filename),
            "ETag": f'"{sha_val}"',
            "X-Artifact-SHA256": sha_val,
        },
    )
