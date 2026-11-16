"""HTTP integration for analyst password login and browser sessions.

Approver sessions remain deliberately unavailable until MFA step-up is
implemented. Legacy bearer authentication is not modified by this router.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.database import get_connection
from app.iam import auth_throttling, mfa, repository, sessions
from app.iam.browser_security import (
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    clear_session_cookie,
    create_csrf_token,
    set_session_cookie,
    validate_request_origin,
    verify_csrf_token,
)
from app.iam.passwords import DEFAULT_PASSWORD_SERVICE
from app.iam.sessions import DEFAULT_ABSOLUTE_TTL_SECONDS
from app.iam.trusted_proxies import resolve_client_ip

router = APIRouter(prefix="/api/v1/iam", tags=["identity"])
_DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$c7CPD4o87cnw7TxFwZJO5g$"
    "gm9KYdMDFzunEZbY1V2fuLRZBLv+rCe2qoX045Ki7rM"
)
_GENERIC_LOGIN_ERROR = "Username or password is incorrect."
_MFA_CHALLENGE_COOKIE = "__Host-aegis_mfa_challenge"


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class MFAChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=6, max_length=300)

    @field_validator("password")
    @classmethod
    def enforce_password_byte_limit(cls, value: str) -> str:
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("password must be valid UTF-8 text") from exc
        if len(encoded) > 1024:
            raise ValueError("password exceeds the supported UTF-8 byte limit")
        return value


def _required_secret(name: str) -> str:
    value = os.getenv(name, "")
    try:
        valid_length = len(value.encode("utf-8")) >= 32
    except UnicodeEncodeError:
        valid_length = False
    if not valid_length:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is not configured.",
        )
    return value


def _allowed_origins() -> set[str]:
    raw = os.getenv("AEGIS_IAM_ALLOWED_ORIGINS", "")
    origins = {item.strip() for item in raw.split(",") if item.strip()}
    if not origins or not all(item.startswith("https://") for item in origins):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is not configured.",
        )
    return origins


def _require_origin(request: Request) -> None:
    if not validate_request_origin(
        request.headers.get("origin"), allowed_origins=_allowed_origins()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Request origin is not allowed.",
        )


def _client_ip(request: Request) -> str:
    if request.client is None or not request.client.host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Client connection information is unavailable.",
        )
    try:
        return resolve_client_ip(
            request.client.host,
            request.headers.get("x-forwarded-for"),
            os.getenv("AEGIS_TRUSTED_PROXY_CIDRS", ""),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is not configured.",
        ) from exc


def _throttle_settings() -> tuple[str, str]:
    return (
        _required_secret("AEGIS_AUTH_THROTTLE_HMAC_KEY"),
        _required_secret("AEGIS_CSRF_SIGNING_KEY"),
    )


def _throttle_identifiers(username: str, client_ip: str) -> tuple[str, str]:
    try:
        normalized = repository.normalize_username(username)
    except ValueError:
        # Invalid names still consume a bounded, privacy-preserving bucket.
        normalized = (
            username.encode("utf-8", errors="replace")
            .decode("utf-8")[:128].strip().casefold() or "<empty>"
        )
    return client_ip, f"{normalized}|{client_ip}"


def _check_login_throttle(connection, *, username: str, client_ip: str, key: str):
    ip_identifier, user_identifier = _throttle_identifiers(username, client_ip)
    ip_state = auth_throttling.is_authentication_blocked(
        connection, scope="login-ip", identifier=ip_identifier, secret=key
    )
    user_state = auth_throttling.is_authentication_blocked(
        connection, scope="login-user-ip", identifier=user_identifier, secret=key
    )
    return ip_state, user_state, ip_identifier, user_identifier


def _record_login_failure(connection, *, ip_identifier: str, user_identifier: str, key: str):
    ip_result = auth_throttling.record_authentication_failure(
        connection, scope="login-ip", identifier=ip_identifier, secret=key
    )
    user_result = auth_throttling.record_authentication_failure(
        connection, scope="login-user-ip", identifier=user_identifier, secret=key
    )
    return max(ip_result.retry_after_seconds, user_result.retry_after_seconds)


def _clear_login_failures(connection, *, ip_identifier: str, user_identifier: str, key: str):
    # A successful account login clears only that username+IP bucket. Keep
    # the shared IP bucket intact so one valid account cannot erase failures
    # accumulated by other usernames from the same source address.
    auth_throttling.authentication_succeeded(
        connection, scope="login-user-ip", identifier=user_identifier, secret=key
    )


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response):
    _require_origin(request)
    throttle_key, csrf_key = _throttle_settings()
    client_ip = _client_ip(request)
    ip_identifier, user_identifier = _throttle_identifiers(payload.username, client_ip)

    with get_connection() as connection:
        ip_state, user_state, _, _ = _check_login_throttle(
            connection, username=payload.username, client_ip=client_ip, key=throttle_key
        )
        if not ip_state.allowed or not user_state.allowed:
            retry_after = max(ip_state.retry_after_seconds, user_state.retry_after_seconds)
            blocked = True
            account = None
            password_valid = False
            has_factor = False
        else:
            blocked = False
            try:
                account = repository.get_account_by_username(connection, payload.username)
            except ValueError:
                account = None
            stored_hash = (
                account["password_hash"]
                if account is not None else _DUMMY_PASSWORD_HASH
            )
            password_valid = DEFAULT_PASSWORD_SERVICE.verify_password(
                stored_hash, payload.password
            )
            eligible = (
                account is not None
                and account["status"] == "active"
                and account["role"] in {"analyst", "approver"}
                and not account["must_change_password"]
            )
            has_factor = (
                account is not None
                and mfa.has_active_totp(connection, user_id=account["id"])
            )
            eligible = eligible and (account["role"] == "analyst" or has_factor)
            if not (password_valid and eligible):
                retry_after = _record_login_failure(
                    connection, ip_identifier=ip_identifier,
                    user_identifier=user_identifier, key=throttle_key,
                )
                has_factor = False
            else:
                _clear_login_failures(
                    connection, ip_identifier=ip_identifier,
                    user_identifier=user_identifier, key=throttle_key,
                )
                if has_factor:
                    challenge_token = mfa.create_login_challenge(
                        connection, user_id=account["id"]
                    )
                    issued = None
                else:
                    issued = sessions.issue_session(
                        connection, user_id=account["id"]
                    )
                from datetime import datetime, timezone
                login_at = issued.created_at if issued is not None else datetime.now(timezone.utc).isoformat(timespec="microseconds")
                connection.execute(
                    "UPDATE iam_users SET last_login_at = ? WHERE id = ?",
                    (login_at, account["id"]),
                )

    if blocked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many sign-in attempts. Try again later.",
            headers={
                "Retry-After": str(max(1, retry_after)),
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )
    if not (password_valid and account is not None
            and account["status"] == "active"
            and account["role"] in {"analyst", "approver"}
            and not account["must_change_password"]
            and (account["role"] == "analyst" or has_factor)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_GENERIC_LOGIN_ERROR,
            headers={
                "WWW-Authenticate": "Session",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )

    if has_factor:
        response.set_cookie(
            key=_MFA_CHALLENGE_COOKIE, value=challenge_token,
            max_age=5 * 60, path="/", secure=True, httponly=True,
            samesite="strict",
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return {
            "authenticated": False,
            "mfa_required": True,
            "user": {"username": account["username"], "role": account["role"]},
        }

    set_session_cookie(
        response, issued.token,
        max_age=DEFAULT_ABSOLUTE_TTL_SECONDS,
    )
    return {
        "authenticated": True,
        "user": {"id": account["id"], "username": account["username"], "role": "analyst"},
        "csrf_token": create_csrf_token(issued.token, secret=csrf_key),
        "expires_at": issued.absolute_expires_at,
    }


@router.post("/login/mfa")
def complete_mfa_login(
    payload: MFAChallengeRequest, request: Request, response: Response
):
    _require_origin(request)
    _, csrf_key = _throttle_settings()
    challenge_token = request.cookies.get(_MFA_CHALLENGE_COOKIE)
    if not challenge_token:
        raise HTTPException(
            status_code=401, detail="MFA challenge is invalid or expired.",
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
    with get_connection() as connection:
        user_id = mfa.verify_login_challenge(
            connection, challenge_token=challenge_token, code=payload.code
        )
        if user_id is None:
            raise HTTPException(
                status_code=401, detail="MFA verification failed.",
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )
        issued = mfa.issue_mfa_verified_session(connection, user_id=user_id)
        account = repository.get_account_by_id(connection, user_id)
    response.delete_cookie(
        key=_MFA_CHALLENGE_COOKIE, path="/", secure=True,
        httponly=True, samesite="strict",
    )
    set_session_cookie(response, issued.token, max_age=DEFAULT_ABSOLUTE_TTL_SECONDS)
    return {
        "authenticated": True,
        "user": {"id": account["id"], "username": account["username"], "role": account["role"]},
        "csrf_token": create_csrf_token(issued.token, secret=csrf_key),
        "expires_at": issued.absolute_expires_at,
        "mfa_verified": True,
    }


@router.get("/session")
def inspect_session(request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=401, detail="Authentication required.",
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
    _, csrf_key = _throttle_settings()
    with get_connection() as connection:
        principal = sessions.validate_session(connection, token=token)
    if principal is None or principal.role not in {"analyst", "approver"}:
        raise HTTPException(
            status_code=401, detail="Authentication required.",
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
    response = {
        "authenticated": True,
        "user": {"id": principal.user_id, "username": principal.username, "role": principal.role},
        "csrf_token": create_csrf_token(token, secret=csrf_key),
        "expires_at": principal.absolute_expires_at,
        "mfa_verified": principal.mfa_verified_at is not None,
    }
    return response


@router.post("/logout")
def logout(request: Request, response: Response):
    _require_origin(request)
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        _, csrf_key = _throttle_settings()
        if not verify_csrf_token(
            token, request.headers.get(CSRF_HEADER_NAME), secret=csrf_key
        ):
            raise HTTPException(
                status_code=403, detail="CSRF validation failed.",
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )
        with get_connection() as connection:
            sessions.revoke_session(connection, token=token)
    clear_session_cookie(response)
    return {"authenticated": False}
