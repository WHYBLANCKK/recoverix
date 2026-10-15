"""
Recoverix — Evidence Ingestion Layer

Safely accepts a raw evidence image from disk and produces deterministic
metadata plus fixed-size chunks for downstream forensic processing.

This layer does NOT perform recovery, carving, reconstruction,
classification, or AI work.
"""

from backend.app.ingestion.reader import (
    EvidenceReader,
    UploadTooLargeError,
    read_upload_bounded,
    read_request_stream_bounded,
)
from backend.app.ingestion.metadata import EvidenceMetadata, compute_metadata
from backend.app.ingestion.chunker import Chunk, chunk_evidence

__all__ = [
    "EvidenceReader",
    "EvidenceMetadata",
    "compute_metadata",
    "Chunk",
    "chunk_evidence",
    "UploadTooLargeError",
    "read_upload_bounded",
    "read_request_stream_bounded",
]
