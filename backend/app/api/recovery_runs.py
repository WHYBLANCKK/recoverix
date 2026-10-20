"""
recovery_runs.py — API router for Recovery Run forensic execution traces.

Provides endpoints to query stored RecoveryRun traces and event streams.
"""

from __future__ import annotations

from typing import List
from fastapi import APIRouter, HTTPException, status

from backend.app.models.recovery_run import RecoveryRun
from backend.app.store import store

router = APIRouter(tags=["recovery_runs"])


@router.get("/recovery-runs", response_model=List[RecoveryRun], status_code=status.HTTP_200_OK, operation_id="list_recovery_runs")
@router.get("/recovery/runs", response_model=List[RecoveryRun], status_code=status.HTTP_200_OK, operation_id="list_recovery_runs_alias")
def list_recovery_runs() -> List[RecoveryRun]:
    """List all stored forensic recovery run traces."""
    return store.list_recovery_runs()


@router.get("/recovery-runs/{run_id}", response_model=RecoveryRun, status_code=status.HTTP_200_OK, operation_id="get_recovery_run")
@router.get("/recovery/runs/{run_id}", response_model=RecoveryRun, status_code=status.HTTP_200_OK, operation_id="get_recovery_run_alias")
def get_recovery_run(run_id: str) -> RecoveryRun:
    """Retrieve a specific forensic recovery run trace by run_id."""
    run = store.get_recovery_run(run_id) or store.get_recovery_run_by_artifact(run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovery run '{run_id}' not found",
        )
    return run
