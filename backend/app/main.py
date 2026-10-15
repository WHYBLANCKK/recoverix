"""
main.py — FastAPI application entrypoint for Recoverix platform.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.cases import router as cases_router
from backend.app.api.analysis import router as analysis_router
from backend.app.api.artifacts import router as artifacts_router
from backend.app.api.file_recovery import router as file_recovery_router
from backend.app.api.recovery_runs import router as recovery_runs_router
from backend.app.api.evidence_graph import router as evidence_graph_router
from backend.app.api.interpretation import router as interpretation_router
from backend.app.store import store, MAX_EVIDENCE_SIZE


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    if hasattr(store, "close") and callable(store.close):
        store.close()


app = FastAPI(
    title="Recoverix Forensic Recovery API",
    description="Deterministic forensic artifact recovery, analysis, confidence scoring, and provenance platform.",
    version="1.0.0",
    lifespan=lifespan,
)

# Default allowed CORS origins for local single-user forensic workstation usage
DEFAULT_ALLOWED_ORIGINS: list[str] = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]


def is_valid_origin(origin: str) -> bool:
    """Validate that an origin has the correct scheme://host[:port] format with no path/query.

    Wildcard origins ('*') are strictly rejected to enforce origin isolation.
    """
    if not origin or "*" in origin:
        return False
    try:
        parsed = urlsplit(origin)
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False
        # Origin must not have path, query, or fragment
        if parsed.path and parsed.path != "/":
            return False
        if parsed.query or parsed.fragment:
            return False
        return True
    except Exception:
        return False


def get_allowed_origins(raw_env: str | None = None) -> list[str]:
    """Resolve, validate, and normalize allowed CORS origins from environment or safe defaults.

    Controlled via the RECOVERIX_CORS_ORIGINS environment variable.
    Supports comma-separated strings or JSON arrays.
    Rejects wildcard '*' origins to protect unauthenticated endpoints.
    Falls back to safe local development origins if unset or if all entries are malformed.
    Setting to 'none' or 'disabled' completely disables cross-origin requests.
    """
    raw = os.getenv("RECOVERIX_CORS_ORIGINS") if raw_env is None else raw_env
    if raw is None or not raw.strip():
        return list(DEFAULT_ALLOWED_ORIGINS)

    raw = raw.strip()

    # Explicit disable
    if raw.lower() in ("none", "disabled", "false", "0"):
        return []

    candidates: list[str] = []
    if raw.startswith("[") and raw.endswith("]"):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                candidates = [str(x) for x in parsed]
        except Exception:
            candidates = []

    if not candidates:
        candidates = [x.strip() for x in raw.split(",") if x.strip()]

    valid_origins: list[str] = []
    for item in candidates:
        cleaned = item.strip().rstrip("/")
        if not cleaned:
            continue
        if is_valid_origin(cleaned):
            valid_origins.append(cleaned)

    # Deduplicate while preserving order
    deduped = list(dict.fromkeys(valid_origins))

    # If configuration was provided but all entries were malformed, fall back safely to defaults
    return deduped if deduped else list(DEFAULT_ALLOWED_ORIGINS)


@app.middleware("http")
async def enforce_upload_size_limit(request: Request, call_next):
    """Reject requests with an oversized Content-Length before parsing or buffering the body."""
    if request.method == "POST":
        path = request.url.path.rstrip("/")
        is_single_file = path in ("/api/recover-file", "/api/recover/file")
        is_case_evidence = path.startswith("/api/cases/") and path.endswith("/evidence")

        if is_single_file or is_case_evidence:
            cl_header = request.headers.get("content-length")
            if cl_header and cl_header.strip().isdigit():
                content_len = int(cl_header.strip())
                content_type = request.headers.get("content-type", "").lower()
                is_multipart = "multipart/form-data" in content_type
                # Allow 64 KiB framing margin for multipart headers, boundary delimiters, and field names
                max_allowed = MAX_EVIDENCE_SIZE + 65536 if is_multipart else MAX_EVIDENCE_SIZE
                if content_len > max_allowed:
                    if is_single_file:
                        return JSONResponse(
                            status_code=413,
                            content={"detail": "FILE_TOO_LARGE"},
                        )
                    else:
                        return JSONResponse(
                            status_code=413,
                            content={
                                "detail": f"Evidence file size ({content_len} bytes) exceeds maximum limit of 5 MiB ({MAX_EVIDENCE_SIZE} bytes)"
                            },
                        )

    return await call_next(request)


# Configure CORS middleware outermost so preflight requests and error responses
# (e.g. 413 rejections) include appropriate CORS headers for allowed origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

# Include routers matching locked API contract
app.include_router(cases_router, prefix="/api")
app.include_router(analysis_router, prefix="/api")
app.include_router(artifacts_router, prefix="/api")
app.include_router(file_recovery_router, prefix="/api")
app.include_router(recovery_runs_router, prefix="/api")
app.include_router(evidence_graph_router, prefix="/api")
app.include_router(interpretation_router, prefix="/api")


@app.get("/health", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "recoverix-api"}

# startup event removed
