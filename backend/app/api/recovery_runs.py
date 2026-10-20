"""
recovery_runs.py — API router for Recovery Run forensic execution traces.

Provides endpoints to query stored RecoveryRun traces and event streams,
with strict session-level data isolation, output byte stripping, and deletion.
"""

from __future__ import annotations

from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Request, status

from backend.app.models.recovery_run import RecoveryRun
from backend.app.store import store
from backend.app.session import get_session_id

router = APIRouter(tags=["recovery_runs"])


def sanitize_recovery_run_for_api(run: RecoveryRun) -> RecoveryRun:
    """Sanitize RecoveryRun output dictionary for API exposure to prevent leaking recovered bytes."""
    clean_run = run.model_copy(deep=True)
    if clean_run.output:
        raw_hex = clean_run.output.get("recovered_bytes", "")
        has_bytes = bool(raw_hex and len(raw_hex) > 0)
        byte_count = (len(raw_hex) // 2) if has_bytes else 0
        clean_run.output = {
            "has_recovered_bytes": has_bytes,
            "byte_count": byte_count,
        }
    return clean_run


@router.get("/recovery-runs", response_model=List[RecoveryRun], status_code=status.HTTP_200_OK, operation_id="list_recovery_runs")
@router.get("/recovery/runs", response_model=List[RecoveryRun], status_code=status.HTTP_200_OK, operation_id="list_recovery_runs_alias")
def list_recovery_runs(request: Request) -> List[RecoveryRun]:
    """List stored forensic recovery run traces for the active caller session.

    Returns empty list if unauthenticated or session has no recorded runs,
    preventing global data enumeration across browser sessions.
    """
    session_id = get_session_id(request)
    all_runs = store.list_recovery_runs()
    filtered = [
        r for r in all_runs
        if (r.session_id == session_id)
    ]
    return [sanitize_recovery_run_for_api(r) for r in filtered]


@router.get("/recovery-runs/{run_id}", response_model=RecoveryRun, status_code=status.HTTP_200_OK, operation_id="get_recovery_run")
@router.get("/recovery/runs/{run_id}", response_model=RecoveryRun, status_code=status.HTTP_200_OK, operation_id="get_recovery_run_alias")
def get_recovery_run(run_id: str, request: Request) -> RecoveryRun:
    """Retrieve a specific forensic recovery run trace by run_id with session ownership verification."""
    session_id = get_session_id(request)
    run = store.get_recovery_run(run_id, session_id=session_id) or store.get_recovery_run_by_artifact(run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovery run '{run_id}' not found",
        )

    # If run has a session_id assigned, enforce that caller matches
    if run.session_id is not None:
        if session_id is None or run.session_id != session_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Recovery run '{run_id}' not found",
            )

    return sanitize_recovery_run_for_api(run)


@router.delete("/recovery-runs/{run_id}", status_code=status.HTTP_200_OK, operation_id="delete_recovery_run")
@router.delete("/recovery/runs/{run_id}", status_code=status.HTTP_200_OK, operation_id="delete_recovery_run_alias")
def delete_recovery_run_route(run_id: str, request: Request) -> Dict[str, Any]:
    """Delete a recovery run and its associated standalone artifacts and blobs immediately."""
    session_id = get_session_id(request)
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovery run '{run_id}' not found",
        )
    deleted = store.delete_recovery_run(run_id, session_id=session_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovery run '{run_id}' not found",
        )
    return {"status": "DELETED", "run_id": run_id}
