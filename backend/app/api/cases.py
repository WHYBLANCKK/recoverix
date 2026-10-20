"""
cases.py — Cases API router for case creation, retrieval, and evidence ingestion.
"""

from __future__ import annotations

from typing import Optional, List
from fastapi import APIRouter, HTTPException, Request, UploadFile, File, Response, status

from backend.app.models.case import CaseCreate, CaseResponse
from backend.app.models.recovery_run import RecoveryRun
from backend.app.store import store, MAX_EVIDENCE_SIZE
from backend.app.ingestion.reader import (
    read_upload_bounded,
    read_request_stream_bounded,
    UploadTooLargeError,
)

router = APIRouter(prefix="/cases", tags=["cases"])


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(payload: CaseCreate) -> CaseResponse:
    """Create a new forensic recovery case."""
    if not payload.name or not payload.name.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid case name. Case name must be a non-empty string.",
        )

    try:
        case_res = store.create_case(name=payload.name, description=payload.description)
        return case_res
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )


@router.get("/{case_id}", response_model=CaseResponse, status_code=status.HTTP_200_OK)
def get_case(case_id: str) -> CaseResponse:
    """Retrieve details for a specific forensic case."""
    # case_001 auto-seed removed
        
    case_res = store.get_case(case_id)
    if case_res is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )
    return case_res


@router.get("/{case_id}/runs", response_model=List[RecoveryRun], status_code=status.HTTP_200_OK)
def get_case_runs(case_id: str) -> List[RecoveryRun]:
    """Retrieve all canonical recovery execution runs for a specific forensic case."""
    runs = store.get_case_recovery_runs(case_id)
    if runs is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )
    return runs


@router.post("/{case_id}/evidence", response_model=CaseResponse, status_code=status.HTTP_200_OK)
async def upload_evidence(
    case_id: str,
    request: Request,
    file: Optional[UploadFile] = File(None),
) -> CaseResponse:
    """Upload evidence payload for a specific forensic case."""
    case_res = store.get_case(case_id)
    if case_res is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    # 1. Early Content-Length check
    cl_header = request.headers.get("content-length")
    if cl_header and cl_header.strip().isdigit():
        content_len = int(cl_header.strip())
        content_type = request.headers.get("content-type", "").lower()
        is_multipart = "multipart/form-data" in content_type
        max_allowed = MAX_EVIDENCE_SIZE + 65536 if is_multipart else MAX_EVIDENCE_SIZE
        if content_len > max_allowed:
            if file is not None:
                await file.close()
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Evidence file size ({content_len} bytes) exceeds maximum limit of 5 MiB ({MAX_EVIDENCE_SIZE} bytes)",
            )

    content: bytes = b""
    filename: str = "evidence.img"

    if file is not None:
        filename = file.filename or "evidence.img"
        try:
            content = await read_upload_bounded(file, max_size=MAX_EVIDENCE_SIZE)
        except UploadTooLargeError as err:
            await file.close()
            actual_sz = err.actual_size if err.actual_size is not None else MAX_EVIDENCE_SIZE + 1
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Evidence file size ({actual_sz} bytes) exceeds maximum limit of 5 MiB ({MAX_EVIDENCE_SIZE} bytes)",
            )
        finally:
            await file.close()

    if not content and file is None:
        # Fallback to reading raw body if form upload wasn't used
        try:
            content = await read_request_stream_bounded(request, max_size=MAX_EVIDENCE_SIZE)
        except UploadTooLargeError as err:
            actual_sz = err.actual_size if err.actual_size is not None else MAX_EVIDENCE_SIZE + 1
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Evidence file size ({actual_sz} bytes) exceeds maximum limit of 5 MiB ({MAX_EVIDENCE_SIZE} bytes)",
            )
        except RuntimeError:
            pass

    if not content or len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Evidence file cannot be empty",
        )

    if len(content) > MAX_EVIDENCE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Evidence file size ({len(content)} bytes) exceeds maximum limit of 5 MiB ({MAX_EVIDENCE_SIZE} bytes)",
        )

    try:
        store.add_evidence(case_id, filename, content)
        updated_case = store.get_case(case_id)
        if updated_case is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
        return updated_case
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )
    except ValueError as err:
        err_msg = str(err)
        if "FILE_TOO_LARGE" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Evidence file exceeds maximum limit of 5 MiB",
            )
        elif "EMPTY_FILE" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Evidence file cannot be empty",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=err_msg,
            )

@router.get("/{case_id}/groundtruth", status_code=status.HTTP_200_OK)
def get_groundtruth(case_id: str):
    """Return synthetic ground-truth for UI verification."""
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    return {
        "case_id": case_id,
        "image_filename": "phantom_disk.img",
        "expected_artifacts": [
            {
                "id": "artifact_002",
                "filename": "auth_trace.txt",
                "scenario": "CLEAN_CONTIGUOUS",
                "expected_status": "FULLY_RECOVERED",
                "original_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "total_bytes": 1500
            },
            {
                "id": "artifact_005",
                "filename": "deleted_notes.txt",
                "scenario": "DELETED",
                "expected_status": "FULLY_RECOVERED",
                "original_sha256": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                "total_bytes": 350
            },
            {
                "id": "artifact_006",
                "filename": "contacts.csv",
                "scenario": "FRAGMENTED",
                "expected_status": "PARTIALLY_RECOVERED",
                "original_sha256": "e57929424c52f6f4d2b2cd33a35a60e0a359fa5b5f6b216964ff8dbd846f499b",
                "total_bytes": 3072
            },
            {
                "id": "artifact_001",
                "filename": "ledger.csv",
                "scenario": "BIFRAGMENT_GAP",
                "expected_status": "PARTIALLY_RECOVERED",
                "original_sha256": "db838b0008892787e38318db51ff56bbcf793a8904571f30e61d8bc5eefbd427",
                "total_bytes": 10000
            },
            {
                "id": "artifact_003",
                "filename": "evidence_capture.png",
                "scenario": "CORRUPTED",
                "expected_status": "CORRUPTED",
                "original_sha256": "740f95fc74e0d4df7cc23999ec9da7c0a6a246dd24b3383a5ea45145cd338fc1",
                "total_bytes": 2500
            },
            {
                "id": "artifact_004",
                "filename": "damaged_sector.txt",
                "scenario": "UNRECOVERABLE",
                "expected_status": "UNRECOVERABLE",
                "original_sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "total_bytes": 1000
            }
        ]
    }
