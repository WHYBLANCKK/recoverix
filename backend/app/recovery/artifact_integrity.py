"""
artifact_integrity.py — Cryptographic integrity verification for recovered artifacts.

Enforces fail-closed SHA-256 verification on all recovered artifact downloads.
Guarantees that persisted digests strictly match recomputed digests over the exact
retrieved payload bytes before serving.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
from typing import Optional

from fastapi import HTTPException, status

from backend.app.models.artifact import ArtifactRecord

logger = logging.getLogger(__name__)

_SHA256_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def compute_sha256(data: bytes) -> str:
    """Compute standard lowercase hexadecimal SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest().lower()


def is_valid_sha256_hex(val: object) -> bool:
    """Validate whether an object is a valid 64-character hex SHA-256 string."""
    if not isinstance(val, str) or len(val) != 64:
        return False
    return bool(_SHA256_HEX_PATTERN.fullmatch(val))


def verify_artifact_download_integrity(
    record: Optional[ArtifactRecord],
    payload_bytes: Optional[bytes],
    requested_id: str,
    context: str = "artifact",
) -> bytes:
    """Enforce cryptographic integrity invariant before serving recovered artifact for download.

    Guarantees:
    1. The artifact record must exist, be downloadable, and have passed validation.
    2. The requested ID must match the record's artifact_id or linked run_id.
    3. The payload bytes must be present and non-empty.
    4. The record must have a valid 64-char hex SHA-256 digest persisted.
    5. The constant-time digest comparison (via hmac.compare_digest) between persisted
       SHA-256 hex digest and recomputed SHA-256 hex digest of exact payload bytes must strictly succeed.
    6. On any violation, fails closed immediately with HTTP 404 without leaking server
       paths, database keys, or payload contents.

    Args:
        record: Stored internal ArtifactRecord.
        payload_bytes: Retrieved raw bytes from storage.
        requested_id: The ID string from the request URL path.
        context: "artifact" for Pipeline A (/api/artifacts/...) or "file" for Pipeline B (/api/recover-file/...).

    Returns:
        The verified raw bytes.

    Raises:
        HTTPException(status_code=404): On any missing, ineligible, unvalidated,
        mismatched, or tampered state.
    """
    is_file_ctx = (context == "file")

    if record is None:
        detail = (
            f"Recovered file '{requested_id}' not found or unrecoverable"
            if is_file_ctx
            else f"Artifact '{requested_id}' not found"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
        )

    # 1. Status & validation eligibility gate
    if (
        record.status not in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")
        or record.validation_status != "PASSED"
        or not record.is_downloadable
    ):
        detail = (
            f"Recovered file '{requested_id}' not found or unrecoverable"
            if is_file_ctx
            else f"Artifact '{requested_id}' is unrecoverable or unvalidated and cannot be downloaded"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
        )

    # 2. Identity binding gate
    valid_ids = {record.artifact_id}
    if record.run_id:
        valid_ids.add(record.run_id)
    if requested_id not in valid_ids:
        logger.warning(
            "Artifact identity mismatch: requested '%s', record artifact_id '%s', run_id '%s'",
            requested_id,
            record.artifact_id,
            record.run_id,
        )
        detail = (
            f"Recovered file '{requested_id}' not found or unrecoverable"
            if is_file_ctx
            else f"Artifact '{requested_id}' not found"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
        )

    # 3. Payload presence gate
    if payload_bytes is None or len(payload_bytes) == 0:
        logger.warning(
            "Artifact payload missing or empty for '%s' (requested '%s')",
            record.artifact_id,
            requested_id,
        )
        detail = (
            f"Recovered file '{requested_id}' not found or unrecoverable"
            if is_file_ctx
            else f"Recovered payload for artifact '{requested_id}' is unavailable"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
        )

    # 4. Persisted digest existence & format gate
    stored_sha = record.sha256
    if not stored_sha and record.metadata and isinstance(record.metadata, dict):
        stored_sha = record.metadata.get("sha256")

    if not stored_sha or not isinstance(stored_sha, str):
        logger.error(
            "Integrity failure: artifact '%s' has no persisted sha256 digest",
            record.artifact_id,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integrity verification failed for artifact '{requested_id}'",
        )

    stored_sha_clean = stored_sha.strip().lower()
    if not is_valid_sha256_hex(stored_sha_clean):
        logger.error(
            "Integrity failure: artifact '%s' has malformed sha256 digest '%s'",
            record.artifact_id,
            stored_sha,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integrity verification failed for artifact '{requested_id}'",
        )

    # 5. Cryptographic verification (constant-time SHA-256 comparison via hmac.compare_digest)
    actual_sha = hashlib.sha256(payload_bytes).hexdigest().lower()
    if not hmac.compare_digest(stored_sha_clean, actual_sha):
        logger.error(
            "Integrity failure: payload tampering or corruption detected for artifact '%s'. "
            "Persisted digest=%s, actual digest=%s",
            record.artifact_id,
            stored_sha_clean,
            actual_sha,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integrity verification failed for artifact '{requested_id}'",
        )

    return payload_bytes
