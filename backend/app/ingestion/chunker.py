"""
chunker.py — Fixed-size evidence chunking.

Splits raw evidence bytes into sequential fixed-size chunks.  The final
chunk may be shorter than the chunk size (a truncated tail).  Every chunk
carries its index, byte offset, byte length, and raw bytes.

Chunking never reads beyond the evidence boundary.

This module does NOT perform recovery, carving, reconstruction,
classification, or AI work.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from backend.app.generator.disk import MAX_EVIDENCE_SIZE

# Default chunk size — 4096 bytes (one standard disk sector / memory page).
DEFAULT_CHUNK_SIZE: int = 4096


@dataclass(frozen=True)
class Chunk:
    """One fixed-size (or final partial) chunk of evidence."""

    index: int
    offset: int
    length: int
    data: bytes

    def validate(self, evidence_size: int) -> None:
        """Raise ValueError if this chunk is structurally invalid.

        Args:
            evidence_size: Total evidence image size in bytes.
        """
        if self.index < 0:
            raise ValueError(f"Chunk index must be non-negative, got {self.index}")
        if self.offset < 0:
            raise ValueError(f"Chunk offset must be non-negative, got {self.offset}")
        if self.length <= 0:
            raise ValueError(f"Chunk length must be positive, got {self.length}")
        if self.offset + self.length > evidence_size:
            raise ValueError(
                f"Chunk {self.index}: end {self.offset + self.length} "
                f"exceeds evidence size {evidence_size}"
            )
        if len(self.data) != self.length:
            raise ValueError(
                f"Chunk {self.index}: data length {len(self.data)} "
                f"!= declared length {self.length}"
            )


def chunk_evidence(
    data: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> List[Chunk]:
    """Split *data* into sequential fixed-size chunks.

    The final chunk may be shorter than *chunk_size* when the evidence
    size is not an exact multiple.

    Args:
        data: Raw evidence bytes.
        chunk_size: Size of each chunk in bytes.

    Returns:
        An ordered list of Chunk objects covering the entire evidence.

    Raises:
        ValueError: If *data* is empty or *chunk_size* is invalid.
    """
    if len(data) == 0:
        raise ValueError("Cannot chunk empty evidence")
    if len(data) > MAX_EVIDENCE_SIZE:
        raise ValueError(
            f"Evidence size ({len(data)} bytes) exceeds limit of {MAX_EVIDENCE_SIZE} bytes"
        )
    if chunk_size <= 0:
        raise ValueError(f"Chunk size must be positive, got {chunk_size}")

    evidence_size = len(data)
    chunks: List[Chunk] = []
    offset = 0
    index = 0

    while offset < evidence_size:
        # Never read beyond the evidence boundary.
        end = min(offset + chunk_size, evidence_size)
        length = end - offset

        chunk = Chunk(
            index=index,
            offset=offset,
            length=length,
            data=data[offset:end],
        )
        chunks.append(chunk)

        offset = end
        index += 1

    return chunks
