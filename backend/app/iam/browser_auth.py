"""Cookie-session authentication for IAM-protected API routes.

Legacy bearer authentication remains authoritative whenever an Authorization
header is supplied. Browser sessions require Origin plus
CSRF validation on every unsafe HTTP method.
"""
import os

from fastapi import HTTPException, Request, status

from app.database import get_connection
from app.iam.browser_security import (
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    validate_request_origin,
    verify_csrf_token,
)
from app.iam.sessions import ValidatedSession, validate_session


def _required_secret(name: str) -> str:
    value = os.getenv(name, "")
    try:
        valid = len(value.encode("utf-8")) >= 32
    except UnicodeEncodeError:
        valid = False
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Browser authentication is not configured.",
        )
    return value


def _allowed_origins() -> set[str]:
    raw = os.getenv("AEGIS_IAM_ALLOWED_ORIGINS", "")
    origins = {item.strip() for item in raw.split(",") if item.strip()}
    if not origins or not all(item.startswith("https://") for item in origins):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Browser authentication is not configured.",
        )
    return origins


def authenticate_browser_session(request: Request) -> ValidatedSession | None:
    """Return a valid analyst session or None; reject unsafe requests lacking CSRF."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None

    if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        if not validate_request_origin(
            request.headers.get("origin"), allowed_origins=_allowed_origins()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Request origin is not allowed.",
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )
        csrf_key = _required_secret("AEGIS_CSRF_SIGNING_KEY")
        if not verify_csrf_token(
            token, request.headers.get(CSRF_HEADER_NAME), secret=csrf_key
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF validation failed.",
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )

    with get_connection() as connection:
        principal = validate_session(connection, token=token)

    if principal is None or principal.role not in {"analyst", "approver"}:
        return None
    return principal
