"""
file_recovery.py — Single-file forensic recovery API router for Recoverix.

Enables uploading a single corrupted or supported file, executing deterministic
carving, validation, and scoring across 6 supported formats (TXT, CSV, JSON, XML, PNG, JPEG),
and producing downloadable recovered byte buffers.
"""

from __future__ import annotations

import hashlib
import os
import re
import urllib.parse
import uuid
from pathlib import PurePath
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status, Response, Body, Request
from pydantic import BaseModel

from backend.app.store import store, MAX_EVIDENCE_SIZE
from backend.app.ingestion.reader import read_upload_bounded, UploadTooLargeError
from backend.app.recovery.tracer import execute_traced_recovery
from backend.app.scoring.explainer import explain_artifact
from backend.app.recovery.adapter import extract_recovered_bytes
from backend.app.recovery.artifact_integrity import verify_artifact_download_integrity


def sanitize_filename(filename: Optional[str], default: str = "recovered_file.bin") -> str:
    """Sanitize user-provided filename to prevent path traversal, control characters, and header injection."""
    if not filename or not isinstance(filename, str):
        return default

    # Normalize backslashes to forward slashes first to handle Windows paths on all platforms
    cleaned = filename.replace("\\", "/").strip()

    # Extract basename to strip directories / path traversal
    base = PurePath(cleaned).name.strip()
    if not base:
        base = os.path.basename(cleaned).strip()

    # Remove CRLF and control characters (ASCII 0-31 and 127)
    base = re.sub(r"[\x00-\x1f\x7f]", "", base)

    # Replace double quotes, backslashes, colons, semicolons, and angle brackets
    base = re.sub(r'["\'\\/:;<>|?*]', "_", base)

    # Collapse multiple whitespace
    base = re.sub(r"\s+", " ", base).strip()

    # If empty after sanitization, or solely dots/underscores
    if not base or set(base).issubset({".", "_", " "}):
        return default

    # Enforce safe length limit (preserving extension if possible)
    if len(base) > 128:
        stem, ext = os.path.splitext(base)
        max_stem = 128 - len(ext)
        if max_stem > 0:
            base = stem[:max_stem] + ext
        else:
            base = base[:128]

    return base


def format_content_disposition(filename: str) -> str:
    """Format RFC 6266 / RFC 5987 compliant Content-Disposition header value."""
    safe_ascii = re.sub(r"[^a-zA-Z0-9._-]", "_", filename) or "file.bin"
    encoded_utf8 = urllib.parse.quote(filename, encoding="utf-8")
    return f'attachment; filename="{safe_ascii}"; filename*=UTF-8\'\'{encoded_utf8}'



class FileRecoveryResponse(BaseModel):
    """Structured response model for single-file recovery."""

    file_id: str
    run_id: Optional[str] = None
    original_filename: str
    recovered_filename: str
    format: str
    status: str
    confidence_score: float
    verified_bytes: int
    reconstructed_bytes: int
    missing_bytes: int
    reconstruction_method: str
    validation_status: str
    is_downloadable: bool
    download_url: str
    content_preview: Optional[str] = None
    score_breakdown: Dict[str, float]
    validation_details: Dict[str, Any]
    fragments: Optional[List[Dict[str, Any]]] = None
    damage_regions: Optional[List[Dict[str, Any]]] = None
    reconstruction_steps: Optional[List[Dict[str, Any]]] = None
    total_input_bytes: Optional[int] = None
    provenance: Optional[Dict[str, Any]] = None
    case_name: Optional[str] = None
    investigator: Optional[str] = None
    notes: Optional[str] = None
    sha256: Optional[str] = None
    session_id: Optional[str] = None


router = APIRouter(tags=["file_recovery"])
from backend.app.session import get_session_id, get_or_create_session


@router.post("/recover-file", response_model=FileRecoveryResponse, status_code=status.HTTP_200_OK, operation_id="recover_single_file")
@router.post("/recover/file", response_model=FileRecoveryResponse, status_code=status.HTTP_200_OK, operation_id="recover_single_file_alias")
async def recover_single_file(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    case_name: Optional[str] = Form(None),
    investigator: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
) -> FileRecoveryResponse:
    """Upload a single evidence file for deterministic byte recovery and validation."""
    session_id, _ = get_or_create_session(request, response)
    cl_header = request.headers.get("content-length")
    if cl_header and cl_header.strip().isdigit():
        content_len = int(cl_header.strip())
        content_type = request.headers.get("content-type", "").lower()
        max_allowed = MAX_EVIDENCE_SIZE + 65536 if "multipart" in content_type else MAX_EVIDENCE_SIZE
        if content_len > max_allowed:
            await file.close()
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="FILE_TOO_LARGE",
            )

    try:
        content = await read_upload_bounded(file, max_size=MAX_EVIDENCE_SIZE)
    except UploadTooLargeError:
        await file.close()
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="FILE_TOO_LARGE",
        )
    finally:
        await file.close()

    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="EMPTY_FILE",
        )

    if len(content) > MAX_EVIDENCE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="FILE_TOO_LARGE",
        )

    orig_filename = sanitize_filename(file.filename, default="uploaded_file.bin")
    file_id = f"rec_file_{uuid.uuid4().hex}"

    # Sanitize optional investigation metadata
    clean_case_name = re.sub(r"[\x00-\x1f\x7f]", "", case_name).strip()[:128] if case_name else None
    if clean_case_name == "":
        clean_case_name = None
    clean_investigator = (
        re.sub(r"[\x00-\x1f\x7f]", "", investigator).strip()[:128]
        if investigator
        else None
    )
    if clean_investigator == "":
        clean_investigator = None
    clean_notes = (
        re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", notes).strip()[:1000]
        if notes
        else None
    )
    if clean_notes == "":
        clean_notes = None

    # Execute and trace recovery
    recovery_run = execute_traced_recovery(
        filename=orig_filename,
        content=content,
        artifact_id=file_id,
        case_name=clean_case_name,
        investigator=clean_investigator,
        notes=clean_notes,
    )
    recovery_run.session_id = session_id
    if session_id:
        store.set_recovery_run_session(recovery_run.run_id, session_id)

    # Re-map from recovery_run
    fmt = recovery_run.format
    status_val = recovery_run.status
    conf_score = float(recovery_run.confidence.get("total", 0.0))
    ver_bytes = recovery_run.total_verified_bytes
    rec_byte_cnt = recovery_run.total_reconstructed_bytes
    miss_bytes = recovery_run.total_missing_bytes
    method = recovery_run.reconstruction_steps[0].method if recovery_run.reconstruction_steps else "NONE"

    # Fallback to existing logic for mapping remaining fields to keep response model happy
    # Note: Much of this was previously computed directly in the tracer or duplicated.
    # We should trust recovery_run more, but to minimize scope change while adding tracing:

    # ... mapping logic ...

    rec_filename = f"recovered_{orig_filename}"
    val_details = recovery_run.validation or {}
    val_is_valid = bool(val_details.get("valid", False)) if "valid" in val_details else (status_val in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED"))
    val_status = "PASSED" if val_is_valid else "FAILED"

    # Keep response matching
    score_breakdown = recovery_run.confidence

    recovered_content = extract_recovered_bytes(recovery_run)
    is_downloadable = (
        status_val in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")
        and val_status == "PASSED"
        and len(recovered_content) > 0
    )
    download_url = f"/api/recover-file/{file_id}/download"

    content_preview = None
    if recovered_content:
        if fmt in ("txt", "csv", "json", "xml"):
            try:
                content_preview = recovered_content.decode("utf-8", errors="replace")[:300]
            except Exception:
                content_preview = recovered_content[:100].hex()
        elif fmt in ("png", "jpeg", "jpg"):
            dims = ""
            if "width" in val_details and "height" in val_details:
                dims = f" ({val_details['width']}x{val_details['height']}px)"
            content_preview = f"Image ({fmt.upper()}){dims}, {len(recovered_content)} bytes"
        elif fmt == "pdf":
            content_preview = f"PDF Document, {len(recovered_content)} bytes"
        elif fmt == "zip":
            fc = val_details.get("file_count", 0)
            content_preview = f"ZIP Archive, {len(recovered_content)} bytes, {fc} file(s)"
        else:
            try:
                content_preview = recovered_content.decode("utf-8", errors="replace")[:300]
            except Exception:
                content_preview = recovered_content[:100].hex()

    meta_dict = {
        "file_id": file_id,
        "run_id": recovery_run.run_id,
        "original_filename": orig_filename,
        "recovered_filename": rec_filename,
        "format": fmt,
        "status": status_val,
        "confidence_score": conf_score,
        "verified_bytes": ver_bytes,
        "reconstructed_bytes": rec_byte_cnt,
        "missing_bytes": miss_bytes,
        "reconstruction_method": method,
        "validation_status": val_status,
        "is_downloadable": is_downloadable,
        "download_url": download_url,
        "content_preview": content_preview,
        "score_breakdown": score_breakdown,
        "validation_details": val_details,
        "fragments": [f.model_dump() for f in recovery_run.fragments],
        "damage_regions": [d.model_dump() for d in recovery_run.damage_regions],
        "reconstruction_steps": [s.model_dump() for s in recovery_run.reconstruction_steps],
        "total_input_bytes": recovery_run.total_input_bytes,
        "provenance": recovery_run.provenance,
    }

    meta_dict["case_name"] = clean_case_name
    meta_dict["investigator"] = clean_investigator
    meta_dict["notes"] = clean_notes
    meta_dict["session_id"] = session_id

    content_sha = hashlib.sha256(recovered_content).hexdigest() if recovered_content else None
    if content_sha:
        meta_dict["sha256"] = content_sha

    store.store_recovered_file(file_id, meta_dict, recovered_content, session_id=session_id)

    return FileRecoveryResponse(**meta_dict)


@router.get("/recover-file/{file_id}", response_model=FileRecoveryResponse, status_code=status.HTTP_200_OK, operation_id="get_recovered_file_metadata")
@router.get("/recover/file/{file_id}", response_model=FileRecoveryResponse, status_code=status.HTTP_200_OK, operation_id="get_recovered_file_metadata_alias")
def get_recovered_file_metadata(file_id: str, request: Request) -> FileRecoveryResponse:
    """Retrieve metadata and real forensic fragments of a previously recovered file."""
    session_id = get_session_id(request)
    meta = store.get_recovered_file_metadata(file_id)
    if meta is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovered file '{file_id}' not found",
        )
    meta_session = meta.get("session_id")
    if meta_session is not None and (session_id is None or meta_session != session_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovered file '{file_id}' not found",
        )
    if meta.get("case_name") is None or meta.get("investigator") is None or meta.get("notes") is None:
        run = store.get_recovery_run(file_id) or store.get_recovery_run_by_artifact(file_id)
        if run is not None:
            if meta.get("case_name") is None:
                meta["case_name"] = run.case_name
            if meta.get("investigator") is None:
                meta["investigator"] = run.investigator
            if meta.get("notes") is None:
                meta["notes"] = run.notes
    return FileRecoveryResponse(**meta)


@router.get("/recover-file/{file_id}/download", status_code=status.HTTP_200_OK, operation_id="download_recovered_file")
@router.get("/recover/file/{file_id}/download", status_code=status.HTTP_200_OK, operation_id="download_recovered_file_alias")
def download_recovered_file(file_id: str, request: Request) -> Response:
    """Download raw byte buffer of a recovered single file with strict SHA-256 integrity verification."""
    session_id = get_session_id(request)
    record = store.get_artifact_record(file_id)
    if record is None:
        run = store.get_recovery_run(file_id) or store.get_recovery_run_by_artifact(file_id)
        if run and run.artifact_id:
            record = store.get_artifact_record(run.artifact_id)

    if record is not None and record.session_id is not None and (session_id is None or record.session_id != session_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovered file '{file_id}' not found or unrecoverable",
        )

    content = store.get_recovered_file_bytes(file_id)
    if content is None and record is not None:
        content = store.get_artifact_bytes(record.artifact_id)

    verified_bytes = verify_artifact_download_integrity(record, content, file_id, context="file")

    raw_rec_name = (record.recovered_filename if record else None) or "recovered_file.bin"
    rec_name = sanitize_filename(raw_rec_name, default="recovered_file.bin")
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
            "Content-Disposition": format_content_disposition(rec_name),
            "ETag": f'"{sha_val}"',
            "X-Artifact-SHA256": sha_val,
        },
    )


@router.post("/recover-file/{file_id}/explain", response_model=Dict[str, Any], status_code=status.HTTP_200_OK, operation_id="explain_recovered_file")
@router.post("/recover/file/{file_id}/explain", response_model=Dict[str, Any], status_code=status.HTTP_200_OK, operation_id="explain_recovered_file_alias")
def explain_recovered_file(file_id: str, request: Request, body: Optional[Dict[str, Any]] = Body(None)) -> Dict[str, Any]:
    """Generate or retrieve a cached grounded evidence interpretation for a single recovered file."""
    session_id = get_session_id(request)
    meta = store.get_recovered_file_metadata(file_id)
    if meta is not None:
        meta_session = meta.get("session_id")
        if meta_session is not None and (session_id is None or meta_session != session_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Recovered file '{file_id}' not found",
            )
        explanation = explain_artifact(file_id, meta)
        try:
            exp_str = json.dumps(explanation) if isinstance(explanation, dict) else str(explanation)
            store.update_artifact_ai_summary(file_id, exp_str)
        except Exception:
            pass
        return explanation

    run = store.get_recovery_run(file_id) or store.get_recovery_run_by_artifact(file_id)
    if run is not None:
        if run.session_id is not None and (session_id is None or run.session_id != session_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Recovered file '{file_id}' not found",
            )
        explanation = explain_artifact(file_id, run)
        try:
            exp_str = json.dumps(explanation) if isinstance(explanation, dict) else str(explanation)
            target_id = run.artifact_id or file_id
            store.update_artifact_ai_summary(target_id, exp_str)
        except Exception:
            pass
        return explanation

    artifact = store.get_artifact(file_id)
    if artifact is not None:
        if artifact.session_id is not None and (session_id is None or artifact.session_id != session_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Recovered file '{file_id}' not found",
            )
        return explain_artifact(file_id, artifact)

    if body and isinstance(body, dict):
        return explain_artifact(file_id, body)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Recovered file '{file_id}' not found",
    )


@router.delete("/recover-file/{file_id}", status_code=status.HTTP_200_OK, operation_id="delete_recovered_file")
@router.delete("/recover/file/{file_id}", status_code=status.HTTP_200_OK, operation_id="delete_recovered_file_alias")
def delete_recovered_file_route(file_id: str, request: Request) -> Dict[str, Any]:
    """Delete a recovered single file, its blobs, and execution trace immediately."""
    session_id = get_session_id(request)
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovered file '{file_id}' not found",
        )
    deleted = store.delete_recovered_file(file_id, session_id=session_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recovered file '{file_id}' not found",
        )
    return {"status": "DELETED", "file_id": file_id}
