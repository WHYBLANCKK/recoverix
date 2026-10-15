"""
reader.py — Safe evidence file reader.

Accepts a filesystem path, validates it, and reads the raw bytes into
memory with strict size and type checks.  Returns an immutable bytes
object suitable for deterministic downstream processing.

This module does NOT perform recovery, carving, reconstruction,
classification, or AI work.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Optional

from backend.app.generator.disk import MAX_EVIDENCE_SIZE


class EvidenceReader:
    """Read and validate a raw evidence image from disk.

    Usage::

        reader = EvidenceReader(Path("backend/generated/damaged.img"))
        raw: bytes = reader.data
        filename: str = reader.filename
    """

    def __init__(self, path: Path | str) -> None:
        """Load and validate the evidence file at *path*.

        Args:
            path: Filesystem path to the evidence image.

        Raises:
            FileNotFoundError: If *path* does not exist.
            IsADirectoryError: If *path* is a directory.
            ValueError: If the file is empty or exceeds MAX_EVIDENCE_SIZE.
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Evidence file not found: {path}")

        if path.is_dir():
            raise IsADirectoryError(
                f"Expected a regular file, got a directory: {path}"
            )

        # Check size before reading to avoid loading unbounded input.
        file_size = path.stat().st_size

        if file_size == 0:
            raise ValueError(f"Evidence file is empty: {path}")

        if file_size > MAX_EVIDENCE_SIZE:
            raise ValueError(
                f"Evidence file size {file_size:,} bytes exceeds "
                f"hard limit ({MAX_EVIDENCE_SIZE:,} bytes / "
                f"{MAX_EVIDENCE_SIZE / 1024 / 1024:.0f} MiB): {path}"
            )

        self._data: bytes = path.read_bytes()
        self._filename: str = path.name
        self._path: Path = path.resolve()

    # ── properties ──────────────────────────────────────────────────

    @property
    def data(self) -> bytes:
        """Raw evidence bytes (immutable)."""
        return self._data

    @property
    def filename(self) -> str:
        """Original filename of the evidence image."""
        return self._filename

    @property
    def size(self) -> int:
        """Evidence size in bytes."""
        return len(self._data)

    @property
    def path(self) -> Path:
        """Resolved absolute path to the evidence file."""
        return self._path


class UploadTooLargeError(ValueError):
    """Raised when an incoming upload stream exceeds MAX_EVIDENCE_SIZE."""

    def __init__(
        self,
        message: str = "Upload exceeds maximum allowed size",
        actual_size: int | None = None,
        max_size: int = MAX_EVIDENCE_SIZE,
    ) -> None:
        super().__init__(message)
        self.actual_size = actual_size
        self.max_size = max_size


async def read_upload_bounded(
    file: Any,
    max_size: int = MAX_EVIDENCE_SIZE,
    chunk_size: int = 65536,
) -> bytes:
    """Read bytes from an UploadFile up to max_size in bounded chunks.

    If spooled size or total read bytes exceed max_size at any point,
    immediately closes the file to release underlying resources and
    raises UploadTooLargeError without unbounded memory buffering.
    """
    import io

    underlying = getattr(file, "file", None)
    if underlying is not None:
        try:
            curr_pos = underlying.tell()
            underlying.seek(0, io.SEEK_END)
            total_spooled = underlying.tell()
            underlying.seek(curr_pos)
            if total_spooled > max_size:
                if hasattr(file, "close") and callable(file.close):
                    close_res = file.close()
                    if hasattr(close_res, "__await__"):
                        await close_res
                raise UploadTooLargeError(
                    f"Upload size ({total_spooled} bytes) exceeds limit of {max_size} bytes",
                    actual_size=total_spooled,
                    max_size=max_size,
                )
        except (AttributeError, io.UnsupportedOperation, OSError):
            pass

    chunks: list[bytes] = []
    total_bytes = 0
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > max_size:
            if hasattr(file, "close") and callable(file.close):
                close_res = file.close()
                if hasattr(close_res, "__await__"):
                    await close_res
            raise UploadTooLargeError(
                f"Upload size ({total_bytes} bytes) exceeds limit of {max_size} bytes",
                actual_size=total_bytes,
                max_size=max_size,
            )
        chunks.append(chunk)

    return b"".join(chunks)


async def read_request_stream_bounded(
    request: Any,
    max_size: int = MAX_EVIDENCE_SIZE,
) -> bytes:
    """Read bytes from an ASGI request stream up to max_size in bounded chunks.

    If total bytes exceed max_size, aborts stream consumption immediately
    and raises UploadTooLargeError.
    """
    chunks: list[bytes] = []
    total_bytes = 0
    async for chunk in request.stream():
        if not chunk:
            continue
        total_bytes += len(chunk)
        if total_bytes > max_size:
            raise UploadTooLargeError(
                f"Upload size ({total_bytes} bytes) exceeds limit of {max_size} bytes",
                actual_size=total_bytes,
                max_size=max_size,
            )
        chunks.append(chunk)

    return b"".join(chunks)
