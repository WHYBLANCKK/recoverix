"""
artifact.py — Artifact API and storage models for Recoverix platform.
"""

from __future__ import annotations

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, model_validator


class ConfidenceBreakdownSchema(BaseModel):
    """Confidence score breakdown across 5 component dimensions."""

    header_validity: int
    footer_validity: int
    structural_validation: int
    size_plausibility: int
    reconstruction_integrity: int
    total: int


class ArtifactProvenanceSchema(BaseModel):
    """Forensic provenance byte accounting and status metadata."""

    verified_bytes: int
    reconstructed_bytes: int
    missing_bytes: int
    reconstruction_method: str
    validation_status: str


class ArtifactResponse(BaseModel):
    """API-facing representation of a recovered artifact."""

    artifact_id: str
    case_id: str
    format: str
    size_bytes: int
    confidence_score: int
    score_breakdown: ConfidenceBreakdownSchema
    status: str
    provenance: ArtifactProvenanceSchema
    category: Optional[str] = None
    priority: Optional[str] = None
    ai_summary: Optional[str] = None
    content_preview: Optional[str] = None
    sha256: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ArtifactRecord(BaseModel):
    """Authoritative internal storage model for recovered artifacts.

    Unifies case-associated recovery artifacts (Pipeline A) and standalone
    file recovery artifacts (Pipeline B) into a single persistence contract.
    """

    artifact_id: str
    case_id: Optional[str] = None
    run_id: Optional[str] = None
    original_filename: Optional[str] = None
    recovered_filename: Optional[str] = None
    format: str
    status: str
    confidence_score: float
    verified_bytes: int = 0
    reconstructed_bytes: int = 0
    missing_bytes: int = 0
    total_input_bytes: Optional[int] = None
    reconstruction_method: str = "NONE"
    validation_status: str = "PASSED"
    is_downloadable: bool = True
    download_url: Optional[str] = None
    content_preview: Optional[str] = None
    score_breakdown: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    validation_details: Dict[str, Any] = Field(default_factory=dict)
    fragments: Optional[List[Dict[str, Any]]] = None
    damage_regions: Optional[List[Dict[str, Any]]] = None
    reconstruction_steps: Optional[List[Dict[str, Any]]] = None
    category: Optional[str] = None
    priority: Optional[str] = None
    ai_summary: Optional[str] = None
    sha256: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    corrupted_fields: Optional[List[str]] = None

    @model_validator(mode="after")
    def verify_status_and_download_invariants(self) -> "ArtifactRecord":
        if self.status == "FULLY_RECOVERED" and (self.reconstructed_bytes > 0 or self.missing_bytes > 0):
            self.status = "PARTIALLY_RECOVERED"

        if (
            self.status not in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED")
            or self.validation_status != "PASSED"
            or not self.is_downloadable
            or self.verified_bytes < 0
        ):
            self.is_downloadable = False
        return self

    def to_artifact_response(self) -> ArtifactResponse:
        """Convert internal ArtifactRecord to API ArtifactResponse."""
        sb = self.score_breakdown or {}
        sb_schema = ConfidenceBreakdownSchema(
            header_validity=int(round(float(sb.get("header_validity", 0)))),
            footer_validity=int(round(float(sb.get("footer_validity", 0)))),
            structural_validation=int(round(float(sb.get("structural_validation", 0)))),
            size_plausibility=int(round(float(sb.get("size_plausibility", 0)))),
            reconstruction_integrity=int(round(float(sb.get("reconstruction_integrity", 0)))),
            total=int(round(float(sb.get("total", self.confidence_score)))),
        )
        prov = self.provenance or {}
        prov_schema = ArtifactProvenanceSchema(
            verified_bytes=int(prov.get("verified_bytes", self.verified_bytes)),
            reconstructed_bytes=int(prov.get("reconstructed_bytes", self.reconstructed_bytes)),
            missing_bytes=int(prov.get("missing_bytes", self.missing_bytes)),
            reconstruction_method=str(prov.get("reconstruction_method", self.reconstruction_method)),
            validation_status=str(prov.get("validation_status", self.validation_status)),
        )
        meta = dict(self.metadata)
        if self.corrupted_fields:
            meta["_corrupted_fields"] = list(self.corrupted_fields)
        if self.run_id and "run_id" not in meta:
            meta["run_id"] = self.run_id
        if self.sha256 and "sha256" not in meta:
            meta["sha256"] = self.sha256

        eff_total_input = (
            self.total_input_bytes
            if self.total_input_bytes is not None
            else (self.verified_bytes + self.missing_bytes)
        )
        meta["total_input_bytes"] = eff_total_input
        meta["is_downloadable"] = self.is_downloadable

        # Actual recovered payload size in bytes. If unrecoverable or not downloadable, size is 0.
        if self.status == "UNRECOVERABLE" or not self.is_downloadable:
            size_bytes = 0
        else:
            size_bytes = self.verified_bytes + self.reconstructed_bytes

        return ArtifactResponse(
            artifact_id=self.artifact_id,
            case_id=self.case_id or "",
            format=self.format,
            size_bytes=size_bytes,
            confidence_score=int(round(self.confidence_score)),
            score_breakdown=sb_schema,
            status=self.status,
            provenance=prov_schema,
            category=self.category,
            priority=self.priority,
            ai_summary=self.ai_summary,
            content_preview=self.content_preview,
            sha256=self.sha256,
            metadata=meta,
        )

    to_response = to_artifact_response

    def to_file_recovery_dict(self) -> Dict[str, Any]:
        """Convert internal ArtifactRecord to flat dictionary representation for FileRecoveryResponse."""
        return {
            "file_id": self.artifact_id,
            "run_id": self.run_id,
            "original_filename": self.original_filename or "uploaded_file.bin",
            "recovered_filename": self.recovered_filename or f"recovered_{self.original_filename or 'uploaded_file.bin'}",
            "format": self.format,
            "status": self.status,
            "confidence_score": float(self.confidence_score),
            "verified_bytes": self.verified_bytes,
            "reconstructed_bytes": self.reconstructed_bytes,
            "missing_bytes": self.missing_bytes,
            "reconstruction_method": self.reconstruction_method,
            "validation_status": self.validation_status,
            "is_downloadable": self.is_downloadable,
            "download_url": self.download_url or f"/api/recover-file/{self.artifact_id}/download",
            "content_preview": self.content_preview,
            "sha256": self.sha256,
            "score_breakdown": {k: float(v) for k, v in self.score_breakdown.items()} if self.score_breakdown else {},
            "validation_details": self.validation_details,
            "fragments": self.fragments,
            "damage_regions": self.damage_regions,
            "reconstruction_steps": self.reconstruction_steps,
            "total_input_bytes": self.total_input_bytes,
            "provenance": self.provenance,
            "corrupted_fields": self.corrupted_fields,
        }

    @classmethod
    def from_artifact_response(cls, art: ArtifactResponse) -> ArtifactRecord:
        """Construct internal ArtifactRecord from API ArtifactResponse."""
        run_id = art.metadata.get("run_id") if art.metadata else None
        orig_fn = (
            art.metadata.get("original_filename")
            or art.metadata.get("evidence_filename")
            or art.metadata.get("filename")
            if art.metadata
            else None
        )
        total_inp = None
        if art.metadata and art.metadata.get("total_input_bytes") is not None:
            try:
                total_inp = int(art.metadata["total_input_bytes"])
            except (ValueError, TypeError):
                total_inp = None
        if total_inp is None:
            total_inp = (
                art.provenance.verified_bytes
                + art.provenance.missing_bytes
            )

        if (
            art.status in ("UNRECOVERABLE", "CORRUPTED")
            or art.provenance.validation_status == "FAILED"
        ):
            is_dl = False
        elif art.metadata and "is_downloadable" in art.metadata:
            is_dl = bool(art.metadata["is_downloadable"])
        else:
            is_dl = True

        corrupted_fields = (
            list(art.metadata.get("_corrupted_fields", []))
            if (art.metadata and "_corrupted_fields" in art.metadata)
            else None
        )

        return cls(
            artifact_id=art.artifact_id,
            case_id=art.case_id,
            run_id=run_id,
            original_filename=orig_fn,
            format=art.format,
            status=art.status,
            confidence_score=float(art.confidence_score),
            verified_bytes=art.provenance.verified_bytes,
            reconstructed_bytes=art.provenance.reconstructed_bytes,
            missing_bytes=art.provenance.missing_bytes,
            total_input_bytes=total_inp,
            reconstruction_method=art.provenance.reconstruction_method,
            validation_status=art.provenance.validation_status,
            is_downloadable=is_dl,
            download_url=f"/api/artifacts/{art.artifact_id}/download",
            content_preview=art.content_preview,
            score_breakdown=art.score_breakdown.model_dump(),
            provenance=art.provenance.model_dump(),
            category=art.category,
            priority=art.priority,
            ai_summary=art.ai_summary,
            sha256=art.sha256 or (art.metadata.get("sha256") if art.metadata else None),
            metadata=dict(art.metadata),
            corrupted_fields=corrupted_fields,
        )

    @classmethod
    def from_file_recovery_dict(cls, meta: Dict[str, Any]) -> ArtifactRecord:
        """Construct internal ArtifactRecord from single-file recovery dictionary."""
        f_id = meta.get("file_id") or meta.get("artifact_id", "")
        run_id = meta.get("run_id")
        ver = int(meta.get("verified_bytes", 0))
        rec = int(meta.get("reconstructed_bytes", 0))
        miss = int(meta.get("missing_bytes", 0))
        status_val = meta.get("status", "UNRECOVERABLE")

        total_inp = meta.get("total_input_bytes")
        if total_inp is not None:
            try:
                total_inp = int(total_inp)
            except (ValueError, TypeError):
                total_inp = ver + miss
        else:
            total_inp = ver + miss

        val_status_in = meta.get("validation_status", "PASSED")
        if (
            status_val in ("UNRECOVERABLE", "CORRUPTED")
            or val_status_in == "FAILED"
        ):
            is_dl = False
        elif "is_downloadable" in meta:
            is_dl = bool(meta["is_downloadable"])
        else:
            is_dl = True

        corrupted_fields = meta.get("corrupted_fields") or (
            list(meta["metadata"].get("_corrupted_fields", []))
            if isinstance(meta.get("metadata"), dict) and "_corrupted_fields" in meta["metadata"]
            else None
        )

        metadata_dict = dict(meta.get("metadata") or {})
        if run_id and "run_id" not in metadata_dict:
            metadata_dict["run_id"] = run_id
        if "created_at" in meta and "created_at" not in metadata_dict:
            metadata_dict["created_at"] = meta["created_at"]
        for extra_key in ("case_name", "investigator", "notes"):
            if extra_key in meta and extra_key not in metadata_dict:
                metadata_dict[extra_key] = meta[extra_key]

        return cls(
            artifact_id=f_id,
            case_id=None,
            run_id=run_id,
            original_filename=meta.get("original_filename"),
            recovered_filename=meta.get("recovered_filename"),
            format=meta.get("format", "unknown"),
            status=status_val,
            confidence_score=float(meta.get("confidence_score", 0.0)),
            verified_bytes=ver,
            reconstructed_bytes=rec,
            missing_bytes=miss,
            total_input_bytes=total_inp,
            reconstruction_method=meta.get("reconstruction_method", "NONE"),
            validation_status=meta.get("validation_status", "PASSED"),
            is_downloadable=is_dl,
            download_url=meta.get("download_url"),
            content_preview=meta.get("content_preview"),
            score_breakdown=dict(meta.get("score_breakdown") or {}),
            provenance=dict(meta.get("provenance") or {"detection_mode": "known_file"}),
            validation_details=dict(meta.get("validation_details") or {}),
            fragments=meta.get("fragments"),
            damage_regions=meta.get("damage_regions"),
            reconstruction_steps=meta.get("reconstruction_steps"),
            sha256=meta.get("sha256") or (meta.get("metadata", {}).get("sha256") if isinstance(meta.get("metadata"), dict) else None),
            metadata=metadata_dict,
            corrupted_fields=corrupted_fields,
        )
