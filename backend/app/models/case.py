"""
case.py — Case data models for Recoverix API contract.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel


class CaseCreate(BaseModel):
    """Payload for creating a new forensic recovery case."""

    name: str
    description: Optional[str] = None


class EvidenceMetadata(BaseModel):
    """Metadata describing uploaded evidence for a case."""

    filename: str
    file_size: int
    uploaded_at: str
    sha256: str


class CaseResponse(BaseModel):
    """API model representing a forensic case."""

    case_id: str
    name: str
    description: Optional[str] = None
    created_at: str
    evidence: Optional[EvidenceMetadata] = None
    artifact_count: int = 0
    session_id: Optional[str] = None
