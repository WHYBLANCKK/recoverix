"""
main.py — FastAPI application entrypoint for Recoverix platform.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import time
from collections import defaultdict
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
    # Purge standalone recovered files older than 24 hours on startup
    if hasattr(store, "purge_expired_recovered_files") and callable(store.purge_expired_recovered_files):
        try:
            store.purge_expired_recovered_files(ttl_hours=24)
        except Exception:
            pass

    # Start periodic background task for continuous 24h TTL enforcement during server operation
    async def periodic_purge():
        while True:
            try:
                await asyncio.sleep(3600)  # Check every hour
                if hasattr(store, "purge_expired_recovered_files") and callable(store.purge_expired_recovered_files):
                    store.purge_expired_recovered_files(ttl_hours=24)
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    purge_task = asyncio.create_task(periodic_purge())
    try:
        yield
    finally:
        purge_task.cancel()
        try:
            await purge_task
        except asyncio.CancelledError:
            pass
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
    "https://recoverix-staging.vercel.app",
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


RATE_LIMIT_WINDOW = 60.0  # seconds
RATE_LIMIT_MAX_REQUESTS = 60  # max requests per window
_ip_request_history: dict[str, list[float]] = defaultdict(list)


def reset_rate_limits() -> None:
    """Clear in-memory rate limit history (primarily for tests)."""
    _ip_request_history.clear()


RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
)


def is_trusted_proxy(ip: str, trusted_set: set[str]) -> bool:
    """Check if an IP address is an explicitly trusted proxy or matches private/CIDR rules."""
    if not ip:
        return False
    if "*" in trusted_set or ip in trusted_set:
        return True
    if "private" in trusted_set or "rfc1918" in trusted_set:
        try:
            addr = ipaddress.ip_address(ip)
            if any(addr in net for net in RFC1918_NETWORKS):
                return True
        except ValueError:
            pass
    for item in trusted_set:
        if "/" in item:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(item, strict=False):
                    return True
            except ValueError:
                pass
    return False


def resolve_client_ip(request: Request) -> str:
    """Resolve client IP safely without blindly trusting client-supplied headers.

    Only respects forwarding headers if the direct peer (request.client.host) matches
    an explicitly configured trusted reverse proxy in RECOVERIX_TRUSTED_PROXIES
    (e.g., explicit IPs, 'private' for cloud load balancers, or CIDR blocks).

    Defends against IP spoofing:
    - If direct peer is not trusted, all forwarded headers are ignored.
    - Inspects tamper-proof edge headers ('cf-connecting-ip', 'true-client-ip') first.
    - Walks 'x-forwarded-for' from right to left, discarding trusted proxy hops and selecting
      the first non-trusted IP, preventing attackers from prepending fake IP addresses.
    """
    direct_peer = request.client.host if (request.client and request.client.host) else "127.0.0.1"
    trusted_proxies_env = os.getenv("RECOVERIX_TRUSTED_PROXIES", "").strip()
    if not trusted_proxies_env:
        return direct_peer

    trusted_set = {p.strip() for p in trusted_proxies_env.split(",") if p.strip()}
    if not is_trusted_proxy(direct_peer, trusted_set):
        return direct_peer

    # 1. Prefer tamper-proof provider edge headers (Cloudflare / Render edge network)
    for header in ("cf-connecting-ip", "true-client-ip"):
        val = request.headers.get(header)
        if val and val.strip():
            candidate = val.strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass

    # 2. Walk X-Forwarded-For from right to left, stripping trusted proxy hops
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        parts = [p.strip() for p in forwarded_for.split(",") if p.strip()]
        for p in reversed(parts):
            if not is_trusted_proxy(p, trusted_set):
                try:
                    ipaddress.ip_address(p)
                    return p
                except ValueError:
                    pass
        if parts:
            return parts[0]

    return direct_peer


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Enforce rate limiting on file recovery endpoints (60 req/min per IP)."""
    if os.getenv("RECOVERIX_DISABLE_RATE_LIMIT") == "1":
        return await call_next(request)

    path = request.url.path.rstrip("/")
    if request.method == "POST" and path in ("/api/recover-file", "/api/recover/file"):
        now = time.time()
        client_ip = resolve_client_ip(request)

        history = _ip_request_history[client_ip]
        cutoff = now - RATE_LIMIT_WINDOW
        _ip_request_history[client_ip] = [t for t in history if t > cutoff]
        history = _ip_request_history[client_ip]

        if len(history) >= RATE_LIMIT_MAX_REQUESTS:
            oldest = history[0]
            retry_after = max(1, int(oldest + RATE_LIMIT_WINDOW - now + 0.999))
            return JSONResponse(
                status_code=429,
                content={"detail": "RATE_LIMIT_EXCEEDED", "retry_after": retry_after},
                headers={"Retry-After": str(retry_after)},
            )

        history.append(now)

    return await call_next(request)


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
