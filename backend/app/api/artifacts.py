"""
artifacts.py — Artifacts API router for case artifact listing and detail retrieval.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status, Response, Body

from backend.app.models.artifact import ArtifactResponse
from backend.app.store import store
from backend.app.scoring.explainer import explain_artifact

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
    if artifact is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{artifact_id}' not found",
        )
    return _enrich_artifact(artifact)


@router.post("/artifacts/{artifact_id}/explain", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
def explain_artifact_route(artifact_id: str, body: Optional[Dict[str, Any]] = Body(None)) -> Dict[str, Any]:
    """Generate or retrieve a cached evidence interpretation for an artifact."""
    artifact = store.get_artifact(artifact_id)
    if artifact is not None:
        explanation = explain_artifact(artifact_id, artifact)
        # Store ai_summary onto artifact to populate next fetch
        artifact.ai_summary = explanation
        return explanation

    # Check recovered file metadata
    file_meta = store.get_recovered_file_metadata(artifact_id)
    if file_meta is not None:
        return explain_artifact(artifact_id, file_meta)

    # Check recovery runs
    run = store.get_recovery_run(artifact_id) or store.get_recovery_run_by_artifact(artifact_id)
    if run is not None:
        return explain_artifact(artifact_id, run)

    if body and isinstance(body, dict):
        return explain_artifact(artifact_id, body)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Artifact '{artifact_id}' not found",
    )


@router.get("/artifacts/{artifact_id}/download", status_code=status.HTTP_200_OK)
def download_artifact(artifact_id: str) -> Response:
    """Download raw byte buffer of a recovered case artifact."""
    record = store.get_artifact_record(artifact_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{artifact_id}' not found",
        )

    # 1. Unrecoverable or non-downloadable artifacts must never be downloaded as valid files
    if record.status == "UNRECOVERABLE" or not record.is_downloadable:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{artifact_id}' is unrecoverable and cannot be downloaded",
        )

    # 2. Retrieve authoritative recovered payload bytes
    content = store.get_artifact_bytes(artifact_id)

    # 3. If payload bytes are missing or empty, fail with 404 (never synthesize from preview)
    if content is None or len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovered payload for artifact '{artifact_id}' is unavailable",
        )

    filename = record.recovered_filename or f"recovered_artifact_{artifact_id}.{record.format}"
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
