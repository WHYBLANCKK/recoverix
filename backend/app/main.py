"""
main.py — FastAPI application entrypoint for Recoverix platform.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
