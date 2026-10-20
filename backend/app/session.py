"""
session.py — Cryptographically signed session ownership and access control for Recoverix.

Provides secure HTTP-only cookie and header token management to isolate file
recovery runs, artifacts, and cases between browser sessions and API clients.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from typing import Optional, Tuple
from fastapi import Request, Response

SESSION_COOKIE_NAME = "recoverix_session"
SESSION_HEADER_NAME = "x-session-token"

# Configurable secret key for HMAC-SHA256 token signing
_DEFAULT_SECRET = "recoverix_forensic_session_secret_deterministic_2026"


def get_session_secret() -> str:
    """Retrieve the session signing secret.

    Fails closed with a RuntimeError if strict security is enabled
    (RECOVERIX_REQUIRE_SESSION_SECRET=1 or RECOVERIX_ENV=production) and no explicit
    secret is configured.
    Falls back to the deterministic default for local single-user forensic development.
    """
    secret = os.environ.get("RECOVERIX_SESSION_SECRET", "").strip()
    if secret:
        return secret

    is_strict = (
        os.environ.get("RECOVERIX_REQUIRE_SESSION_SECRET", "0").strip() in ("1", "true", "True")
        or os.environ.get("RECOVERIX_ENV", "").strip().lower() == "production"
    )
    if is_strict:
        raise RuntimeError(
            "RECOVERIX_SESSION_SECRET must be configured with a high-entropy secret in production or strict mode."
        )

    return _DEFAULT_SECRET


# Backwards compatibility alias for module-level access
SESSION_SECRET = _DEFAULT_SECRET


def sign_session_token(session_id: str) -> str:
    """Generate an HMAC-SHA256 signature for a session_id and return a combined token."""
    secret = get_session_secret()
    signature = hmac.new(
        secret.encode("utf-8"),
        session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{session_id}.{signature}"


def verify_session_token(token: Optional[str]) -> Optional[str]:
    """Validate a signed session token using constant-time comparison.

    Returns the verified session_id if valid, or None if invalid/missing.
    """
    if not token or not isinstance(token, str) or "." not in token:
        return None

    parts = token.split(".", 1)
    if len(parts) != 2:
        return None

    session_id, received_sig = parts
    if not session_id or not received_sig:
        return None

    secret = get_session_secret()
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if hmac.compare_digest(received_sig, expected_sig):
        return session_id

    return None


def generate_session_id() -> str:
    """Generate a high-entropy session identifier."""
    return f"sess_{uuid.uuid4().hex}"


def get_session_id(request: Request) -> Optional[str]:
    """Extract and verify session_id from request cookies, custom headers, or authorization header."""
    # 1. Check HTTP-only cookie first
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie_token:
        valid_id = verify_session_token(cookie_token)
        if valid_id:
            return valid_id

    # 2. Check X-Session-Token header (for automated API clients or cross-origin rewrites)
    header_token = request.headers.get(SESSION_HEADER_NAME)
    if header_token:
        valid_id = verify_session_token(header_token.strip())
        if valid_id:
            return valid_id

    # 3. Check Authorization header (e.g. Bearer <token>)
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.strip().lower().startswith("bearer "):
        bearer_token = auth_header.strip()[7:].strip()
        valid_id = verify_session_token(bearer_token)
        if valid_id:
            return valid_id

    return None


def attach_session_to_response(response: Response, token: str) -> None:
    """Attach the signed session token as an HTTP-only cookie and header to the HTTP response."""
    # Determine secure flag from environment or default (False for local development)
    is_secure = os.environ.get("RECOVERIX_COOKIE_SECURE", "0").strip() in ("1", "true", "True")

    # Set HTTP-only, SameSite=Lax cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=86400 * 7,  # 7-day session lifetime
        httponly=True,
        samesite="lax",
        secure=is_secure,
        path="/",
    )

    # Also expose token in X-Session-Token header for client state synchronization
    response.headers[SESSION_HEADER_NAME] = token


def get_or_create_session(
    request: Request,
    response: Optional[Response] = None,
) -> Tuple[str, str]:
    """Retrieve verified session from request, or generate and attach a new session.

    Returns:
        tuple[session_id, signed_token]
    """
    existing_id = get_session_id(request)
    if existing_id:
        token = sign_session_token(existing_id)
        if response is not None:
            attach_session_to_response(response, token)
        return existing_id, token

    new_session_id = generate_session_id()
    new_token = sign_session_token(new_session_id)
    if response is not None:
        attach_session_to_response(response, new_token)
    return new_session_id, new_token


def is_resource_accessible(
    resource_session_id: Optional[str],
    request: Request,
) -> bool:
    """Determine whether a resource is accessible by the current request.

    Rules:
    - If resource has a session_id, the request MUST provide a matching verified session_id.
    - If resource has no session_id (e.g. legacy records or direct unit test fixtures):
      accessible to preserve backward compatibility.
    - If request has a session_id that does not match resource_session_id:
      strictly NOT accessible (returns False).
    """
    if not resource_session_id:
        return True

    caller_session_id = get_session_id(request)
    if not caller_session_id:
        return False

    return hmac.compare_digest(caller_session_id, resource_session_id)
