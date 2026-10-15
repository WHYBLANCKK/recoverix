"""
recovery_run.py — Pydantic models for the Recovery Run forensic trace.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator
from datetime import datetime


class FragmentRelationship(BaseModel):
    source_fragment_id: str
    target_fragment_id: str
    relationship_type: str  # PRECEDES, FOLLOWS, BOUNDED_GAP, RECONSTRUCTED_FROM
    details: Optional[Dict[str, Any]] = None


class Fragment(BaseModel):
    fragment_id: str
    offset: int
    length: int
    end_offset: int  # Invariant: end_offset - offset == length
    status: str  # VERIFIED, CORRUPTED, RECONSTRUCTED, MISSING, PARTIAL
    source: str  # synthetic_boundary, magic_bytes, carved, bifragment_a, bifragment_b
    format: str
    verified_bytes: int
    reconstructed_bytes: int
    missing_bytes: int
    validation_status: str  # PASSED, FAILED, UNTESTED, PARTIAL
    relationships: List[FragmentRelationship] = Field(default_factory=list)

    @model_validator(mode="after")
    def verify_offsets_and_length(self) -> "Fragment":
        if self.end_offset < self.offset:
            raise ValueError(
                f"Fragment end_offset ({self.end_offset}) cannot be less than offset ({self.offset})"
            )
        computed = self.end_offset - self.offset
        if self.length != computed:
            raise ValueError(
                f"Fragment length {self.length} does not match end_offset - offset ({computed})"
            )
        return self


class DamageRegion(BaseModel):
    region_id: str
    start_offset: int
    end_offset: int
    length: int  # Invariant: end_offset - start_offset == length
    type: str  # CORRUPTED, MISSING, TRUNCATED, RECONSTRUCTABLE
    status: str  # UNRESOLVED, RECONSTRUCTED, UNRECOVERABLE, DETECTED
    affected_fragment_ids: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def verify_offsets_and_length(self) -> "DamageRegion":
        if self.end_offset < self.start_offset:
            raise ValueError(
                f"DamageRegion end_offset ({self.end_offset}) cannot be less than start_offset ({self.start_offset})"
            )
        computed = self.end_offset - self.start_offset
        if self.length != computed:
            raise ValueError(
                f"DamageRegion length {self.length} does not match end_offset - start_offset ({computed})"
            )
        return self


class ReconstructionStep(BaseModel):
    step_id: str
    method: str  # BIFRAGMENT_GAP, XREF_RECONSTRUCTION, NONE
    input_fragment_ids: List[str] = Field(default_factory=list)
    gap_start: Optional[int] = None
    gap_end: Optional[int] = None
    gap_size: Optional[int] = None  # Actual missing gap size in evidence
    validated_gap_size: Optional[int] = None  # Structurally validated placeholder gap size
    result: str  # SUCCESS, FAILED, SKIPPED
    verified_bytes: int
    reconstructed_bytes: int  # Recovered evidence bytes (0 for placeholder gaps)
    missing_bytes: int = 0  # Unobserved bytes remaining missing
    validation_status: str  # PASSED, FAILED
    confidence: Optional[float] = None


class PipelineEvent(BaseModel):
    event_id: str
    run_id: str
    sequence: int
    event_type: str
    timestamp: datetime
    message: str
    relevant_fragment_ids: List[str] = Field(default_factory=list)
    relevant_artifact_info: Optional[Dict[str, Any]] = None


class RecoveryRun(BaseModel):
    run_id: str
    case_id: Optional[str] = None
    artifact_id: Optional[str] = None
    candidate_id: Optional[str] = None
    filename: str
    format: str
    status: str  # FULLY_RECOVERED, PARTIALLY_RECOVERED, CORRUPTED, UNRECOVERABLE
    started_at: datetime
    completed_at: Optional[datetime] = None
    total_input_bytes: int
    total_verified_bytes: int
    total_reconstructed_bytes: int
    total_missing_bytes: int
    fragments: List[Fragment] = Field(default_factory=list)
    damage_regions: List[DamageRegion] = Field(default_factory=list)
    reconstruction_steps: List[ReconstructionStep] = Field(default_factory=list)
    events: List[PipelineEvent] = Field(default_factory=list)
    validation: Optional[Dict[str, Any]] = None
    confidence: Optional[Dict[str, Any]] = None
    provenance: Optional[Dict[str, Any]] = None
    output: Optional[Dict[str, Any]] = None
    detection_mode: Optional[str] = "known_file"
