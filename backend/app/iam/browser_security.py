"""Browser cookie and CSRF primitives for future IAM HTTP integration.

No routes are installed in Phase 2B. The helpers intentionally require an
explicit deployment configuration and fail closed on insecure cookie setup.
"""
import hashlib
import hmac
import os
import secrets
from urllib.parse import urlsplit

from starlette.responses import Response

SESSION_COOKIE_NAME = "__Host-aegis_session"
CSRF_HEADER_NAME = "x-aegis-csrf-token"
MAX_COOKIE_AGE_SECONDS = 24 * 60 * 60


def _cookie_settings(*, secure: bool | None, same_site: str, path: str) -> bool:
    selected_secure = (
        os.getenv("AEGIS_SESSION_COOKIE_SECURE", "true").casefold() == "true"
        if secure is None else secure
    )
    if not selected_secure:
        raise ValueError("session cookies must use the Secure attribute")
    if same_site not in {"lax", "strict"}:
        raise ValueError("SameSite must be 'lax' or 'strict'")
    if path != "/":
        raise ValueError("__Host- session cookies must use Path=/")
    return selected_secure


def set_session_cookie(
    response: Response,
    token: str,
    *,
    max_age: int,
    secure: bool | None = None,
    same_site: str = "lax",
) -> None:
    if not isinstance(token, str) or not token or len(token) > 128:
        raise ValueError("session token is invalid")
    if (
        isinstance(max_age, bool) or not isinstance(max_age, int)
        or not 1 <= max_age <= MAX_COOKIE_AGE_SECONDS
    ):
        raise ValueError("max_age must be between 1 second and 24 hours")
    selected_secure = _cookie_settings(secure=secure, same_site=same_site, path="/")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.set_cookie(
        key=SESSION_COOKIE_NAME, value=token, max_age=max_age, path="/",
        secure=selected_secure, httponly=True, samesite=same_site,
    )


def clear_session_cookie(
    response: Response, *, secure: bool | None = None, same_site: str = "lax"
) -> None:
    selected_secure = _cookie_settings(secure=secure, same_site=same_site, path="/")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.delete_cookie(
        key=SESSION_COOKIE_NAME, path="/", secure=selected_secure,
        httponly=True, samesite=same_site,
    )


def create_csrf_token(session_token: str, *, secret: str | bytes) -> str:
    """Derive a stable per-session CSRF token; do not persist it in the session DB."""
    if not isinstance(session_token, str) or not 40 <= len(session_token) <= 128:
        raise ValueError("session token is invalid")
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("CSRF signing secret must contain at least 32 bytes")
    return hmac.new(
        key, b"aegis-csrf-v1:" + session_token.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def verify_csrf_token(
    session_token: str, supplied_token: str | None, *, secret: str | bytes
) -> bool:
    if not isinstance(supplied_token, str) or len(supplied_token) != 64:
        return False
    try:
        expected = create_csrf_token(session_token, secret=secret)
    except (TypeError, ValueError, UnicodeError):
        return False
    return hmac.compare_digest(expected, supplied_token)


def validate_request_origin(
    origin: str | None, *, allowed_origins: set[str] | frozenset[str]
) -> bool:
    """Require an exact configured HTTPS origin; reject null, paths and wildcards."""
    if not isinstance(origin, str) or not origin or origin == "null":
        return False
    try:
        parsed = urlsplit(origin)
        # Accessing .port validates malformed and out-of-range port values.
        _ = parsed.port
        if (
            parsed.scheme != "https" or not parsed.netloc
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or parsed.hostname is None
        ):
            return False
        normalized = f"https://{parsed.netloc.lower()}"
    except ValueError:
        return False
    normalized_allowlist = {
        item.rstrip("/").lower()
        for item in allowed_origins
        if isinstance(item, str) and item.startswith("https://")
    }
    return normalized in normalized_allowlist


def generate_csrf_nonce() -> str:
    """Generate a random nonce for one-time flows that need a synchronizer token."""
    return secrets.token_urlsafe(32)
