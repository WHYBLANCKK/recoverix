"""benchmark/models.py — Data contracts for Recoverix Benchmark Harness.

Defines Pydantic models for:
- Physical ground-truth manifests with strict coordinate half-open intervals [start, end)
- Observed recovery results with three distinct coordinate spaces:
    E: Evidence space
    O: Original artifact space
    R: Recovered payload space
- Observable segments mapping verified, reconstructed, and missing intervals across spaces.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import List, Literal, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


# ── COORDINATE SEGMENT MODEL ───────────────────────────────────────────────

class ObservedRecoverySegment(BaseModel):
    """Explicit mapping of one recovery segment across the three coordinate spaces.

    Coordinates are half-open intervals [start, end):
      - evidence_start, evidence_end: [E_s, E_e) in the raw evidence buffer
      - original_start, original_end: [O_s, O_e) in original uncorrupted artifact
      - recovered_start, recovered_end: [R_s, R_e) in recovered output payload

    None indicates that the segment does not exist in that coordinate space
    (e.g., missing intervals do not exist in recovered payload or evidence).
    """

    segment_id: str
    category: Literal["VERIFIED", "RECONSTRUCTED", "MISSING"]

    # Evidence Space Coordinates
    evidence_start: Optional[int] = None
    evidence_end: Optional[int] = None

    # Original Artifact Space Coordinates
    original_start: Optional[int] = None
    original_end: Optional[int] = None

    # Recovered Payload Space Coordinates
    recovered_start: Optional[int] = None
    recovered_end: Optional[int] = None

    observed_sha256: Optional[str] = None
    expected_sha256: Optional[str] = None

    @model_validator(mode="after")
    def validate_intervals_and_lengths(self) -> "ObservedRecoverySegment":
        # Validate interval integrity in each coordinate space
        for prefix in ("evidence", "original", "recovered"):
            start = getattr(self, f"{prefix}_start")
            end = getattr(self, f"{prefix}_end")
            if start is not None and end is not None:
                if start < 0:
                    raise ValueError(f"{prefix}_start must be non-negative, got {start}")
                if end < start:
                    raise ValueError(f"{prefix}_end ({end}) must be >= {prefix}_start ({start})")
                if end == start:
                    raise ValueError(f"{prefix}_end ({end}) must be > {prefix}_start ({start}) (empty interval)")
            elif start is not None or end is not None:
                raise ValueError(f"Both {prefix}_start and {prefix}_end must be provided together")

        o_start = self.original_start
        o_end = self.original_end
        r_start = self.recovered_start
        r_end = self.recovered_end
        e_start = self.evidence_start
        e_end = self.evidence_end

        o_len = (o_end - o_start) if (o_start is not None and o_end is not None) else None
        r_len = (r_end - r_start) if (r_start is not None and r_end is not None) else None
        e_len = (e_end - e_start) if (e_start is not None and e_end is not None) else None

        if self.category == "VERIFIED":
            if r_len is None and e_len is None:
                raise ValueError("VERIFIED segments must define recovered or evidence interval")
            if o_len is not None and r_len is not None and o_len != r_len:
                raise ValueError(
                    f"VERIFIED segment length mismatch: original {o_len} != recovered {r_len}"
                )
            if e_len is not None and o_len is not None and e_len != o_len:
                raise ValueError(
                    f"VERIFIED segment length mismatch: evidence {e_len} != original {o_len}"
                )

        elif self.category == "MISSING":
            if r_len is not None or r_start is not None:
                raise ValueError("MISSING segments cannot have recovered payload coordinates")

        elif self.category == "RECONSTRUCTED":
            if r_len is None and e_len is None:
                raise ValueError("RECONSTRUCTED segments must define recovered or evidence interval")
            if o_len is not None and r_len is not None and o_len != r_len:
                raise ValueError(
                    f"RECONSTRUCTED segment length mismatch: original {o_len} != recovered {r_len}"
                )

        return self


# ── PHYSICAL GROUND TRUTH MODELS ───────────────────────────────────────────

class PhysicalPlacement(BaseModel):
    """Where a fragment of the original artifact physically resides in evidence."""

    fragment_index: int
    evidence_offset: int
    evidence_length: int
    original_offset: int

    @model_validator(mode="after")
    def validate_offsets(self) -> "PhysicalPlacement":
        if self.fragment_index < 0:
            raise ValueError(f"fragment_index must be non-negative: {self.fragment_index}")
        if self.evidence_offset < 0:
            raise ValueError(f"evidence_offset must be non-negative: {self.evidence_offset}")
        if self.evidence_length <= 0:
            raise ValueError(f"evidence_length must be positive: {self.evidence_length}")
        if self.original_offset < 0:
            raise ValueError(f"original_offset must be non-negative: {self.original_offset}")
        return self


class PhysicalDamageInterval(BaseModel):
    """Damage region in original artifact coordinates with deterministic reconstruction expectation."""

    original_start: int
    original_end: int
    length: int
    damage_type: Literal["PHYSICAL_GAP", "ZERO_FILL", "RANDOM_OVERWRITE", "BIT_FLIP"]

    reconstruction_mode: Literal[
        "RECONSTRUCTION_NONE",
        "RECONSTRUCTION_DETERMINISTIC",
        "RECONSTRUCTION_UNKNOWN",
    ] = "RECONSTRUCTION_NONE"

    expected_reconstructed_bytes_b64: Optional[str] = None
    expected_reconstructed_sha256: Optional[str] = None

    @model_validator(mode="after")
    def validate_damage(self) -> "PhysicalDamageInterval":
        if self.original_start < 0:
            raise ValueError(f"original_start must be non-negative: {self.original_start}")
        if self.original_end < self.original_start:
            raise ValueError(
                f"original_end ({self.original_end}) must be >= original_start ({self.original_start})"
            )
        if self.length != (self.original_end - self.original_start):
            raise ValueError(
                f"length ({self.length}) does not match end - start ({self.original_end - self.original_start})"
            )

        if self.reconstruction_mode == "RECONSTRUCTION_DETERMINISTIC":
            if not self.expected_reconstructed_bytes_b64 and not self.expected_reconstructed_sha256:
                raise ValueError(
                    "RECONSTRUCTION_DETERMINISTIC requires expected_reconstructed_bytes_b64 "
                    "or expected_reconstructed_sha256"
                )
            if self.expected_reconstructed_bytes_b64:
                try:
                    raw = base64.b64decode(self.expected_reconstructed_bytes_b64)
                    computed_sha = hashlib.sha256(raw).hexdigest()
                    if not self.expected_reconstructed_sha256:
                        object.__setattr__(self, "expected_reconstructed_sha256", computed_sha)
                except Exception as exc:
                    raise ValueError(f"Invalid base64 in expected_reconstructed_bytes_b64: {exc}")

        return self


class PhysicalArtifactRecord(BaseModel):
    """Physical definition of one ground-truth artifact placed in evidence."""

    artifact_id: str
    original_filename: str
    format: Literal["txt", "csv", "json", "xml", "png", "jpeg", "pdf"]
    original_size_bytes: int
    original_sha256: str
    original_bytes_b64: str

    header_evidence_offset: int
    header_original_offset: int = 0

    placements: List[PhysicalPlacement]
    damage_intervals: List[PhysicalDamageInterval] = Field(default_factory=list)

    is_unrecoverable: bool = False
    unrecoverable_reason: Optional[str] = None

    is_deterministic_recovery: bool = True
    non_deterministic_reason: Optional[str] = None

    @field_validator("original_sha256")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", v):
            raise ValueError("original_sha256 must be a 64-character hex string")
        return v.lower()

    @model_validator(mode="after")
    def validate_placements_and_bytes(self) -> "PhysicalArtifactRecord":
        # 1. Base64 & original byte integrity
        try:
            raw_bytes = base64.b64decode(self.original_bytes_b64)
        except Exception as exc:
            raise ValueError(f"Invalid original_bytes_b64: {exc}")

        if len(raw_bytes) != self.original_size_bytes:
            raise ValueError(
                f"original_size_bytes ({self.original_size_bytes}) != decoded byte length ({len(raw_bytes)})"
            )

        computed_sha = hashlib.sha256(raw_bytes).hexdigest()
        if computed_sha != self.original_sha256:
            raise ValueError(
                f"SHA-256 mismatch for original bytes: {computed_sha} != {self.original_sha256}"
            )

        # 2. Placement ordering invariant
        if not self.placements:
            raise ValueError("Artifact must have at least one placement")

        for i in range(len(self.placements) - 1):
            curr = self.placements[i]
            nxt = self.placements[i + 1]
            if curr.original_offset >= nxt.original_offset:
                raise ValueError(
                    f"Placements must be strictly sorted by original_offset: "
                    f"index {i} ({curr.original_offset}) >= index {i+1} ({nxt.original_offset})"
                )
            if curr.original_offset + curr.evidence_length > nxt.original_offset:
                raise ValueError(
                    f"Overlapping original intervals in placements: "
                    f"[{curr.original_offset}, {curr.original_offset + curr.evidence_length}) "
                    f"overlaps [{nxt.original_offset}, ...)"
                )

        # 3. Header placement invariant
        first = self.placements[0]
        if first.original_offset != 0:
            raise ValueError(f"First placement must start at original_offset 0, got {first.original_offset}")
        if first.evidence_offset != self.header_evidence_offset:
            raise ValueError(
                f"header_evidence_offset ({self.header_evidence_offset}) must match first placement evidence_offset ({first.evidence_offset})"
            )

        return self

    @property
    def original_bytes(self) -> bytes:
        """Decode and return the ground-truth original bytes."""
        return base64.b64decode(self.original_bytes_b64)


class PhysicalRelationshipRecord(BaseModel):
    """Directional spatial relationship between two artifacts within the same evidence buffer."""

    evidence_buffer_id: str
    source_artifact_id: str
    target_artifact_id: str
    relationship_type: Literal["COEXTENSIVE", "CONTAINS", "CONTAINED_BY", "OVERLAPS"]

    @model_validator(mode="after")
    def validate_different_artifacts(self) -> "PhysicalRelationshipRecord":
        if self.source_artifact_id == self.target_artifact_id:
            raise ValueError("source_artifact_id and target_artifact_id must be distinct")
        return self


class BenchmarkGroundTruthManifest(BaseModel):
    """Self-contained, machine-readable physical ground truth manifest."""

    manifest_version: str = "1.0.0"
    scenario_id: str
    evidence_buffer_id: str
    evidence_size_bytes: int
    evidence_sha256: str
    seed: int
    artifacts: List[PhysicalArtifactRecord]
    spatial_relationships: List[PhysicalRelationshipRecord] = Field(default_factory=list)

    @field_validator("evidence_sha256")
    @classmethod
    def validate_sha(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", v):
            raise ValueError("evidence_sha256 must be a 64-character hex string")
        return v.lower()

    @model_validator(mode="after")
    def validate_manifest_integrity(self) -> "BenchmarkGroundTruthManifest":
        if self.evidence_size_bytes <= 0:
            raise ValueError(f"evidence_size_bytes must be positive: {self.evidence_size_bytes}")

        art_ids = set()
        for art in self.artifacts:
            if art.artifact_id in art_ids:
                raise ValueError(f"Duplicate artifact_id: {art.artifact_id}")
            art_ids.add(art.artifact_id)

        for rel in self.spatial_relationships:
            if rel.evidence_buffer_id != self.evidence_buffer_id:
                raise ValueError(
                    f"Relationship evidence_buffer_id ({rel.evidence_buffer_id}) "
                    f"does not match manifest ({self.evidence_buffer_id})"
                )
            if rel.source_artifact_id not in art_ids:
                raise ValueError(f"Unknown source_artifact_id in relationship: {rel.source_artifact_id}")
            if rel.target_artifact_id not in art_ids:
                raise ValueError(f"Unknown target_artifact_id in relationship: {rel.target_artifact_id}")

        return self


# ── OBSERVED RESULT MODELS ────────────────────────────────────────────────

class ObservedCandidateResult(BaseModel):
    """Candidate detection result observed from recovery scanner."""

    candidate_id: str
    evidence_buffer_id: str
    format: str
    offset: int
    detected_header_length: int
    estimated_end_offset: Optional[int] = None
    is_unbounded: bool = False

    @model_validator(mode="after")
    def validate_candidate(self) -> "ObservedCandidateResult":
        if self.offset < 0:
            raise ValueError(f"offset must be non-negative: {self.offset}")
        if self.detected_header_length <= 0:
            raise ValueError(f"detected_header_length must be positive: {self.detected_header_length}")
        if self.estimated_end_offset is not None:
            if self.estimated_end_offset < self.offset:
                raise ValueError(f"estimated_end_offset ({self.estimated_end_offset}) < offset ({self.offset})")
        else:
            object.__setattr__(self, "is_unbounded", True)
        return self

    @property
    def span(self) -> Optional[tuple[int, int]]:
        if self.estimated_end_offset is not None:
            return (self.offset, self.estimated_end_offset)
        return None


class ObservedRelationshipRecord(BaseModel):
    """Directed spatial relationship detected between candidates."""

    evidence_buffer_id: str
    source_candidate_id: str
    target_candidate_id: str
    relationship_type: Literal["COEXTENSIVE", "CONTAINS", "CONTAINED_BY", "OVERLAPS"]


class ObservedArtifactRecoveryResult(BaseModel):
    """Recovery result observed for one candidate/artifact."""

    observed_candidate_id: Optional[str] = None
    detected_format: str
    observed_status: str
    confidence_score: int

    total_input_bytes: int
    total_verified_bytes: int
    total_reconstructed_bytes: int
    total_missing_bytes: int

    recovered_payload_bytes: bytes = b""
    recovered_payload_sha256: str = ""

    verified_segments: List[ObservedRecoverySegment] = Field(default_factory=list)
    reconstructed_segments: List[ObservedRecoverySegment] = Field(default_factory=list)
    missing_segments: List[ObservedRecoverySegment] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_payload_hash(self) -> "ObservedArtifactRecoveryResult":
        computed = hashlib.sha256(self.recovered_payload_bytes).hexdigest()
        if not self.recovered_payload_sha256:
            object.__setattr__(self, "recovered_payload_sha256", computed)
        elif self.recovered_payload_sha256.lower() != computed:
            raise ValueError(
                f"recovered_payload_sha256 mismatch: {self.recovered_payload_sha256} != {computed}"
            )
        return self


class BenchmarkObservedManifest(BaseModel):
    """Complete observed run outputs for one benchmark scenario."""

    manifest_version: str = "1.0.0"
    scenario_id: str
    evidence_buffer_id: str
    candidates: List[ObservedCandidateResult] = Field(default_factory=list)
    recoveries: List[ObservedArtifactRecoveryResult] = Field(default_factory=list)
    observed_relationships: List[ObservedRelationshipRecord] = Field(default_factory=list)
