import hmac
import os
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from app.iam.browser_auth import authenticate_browser_session
from app.iam.mfa import has_recent_mfa


bearer_scheme = HTTPBearer(auto_error=False)

ANALYST_ROLE = "analyst"
APPROVER_ROLE = "approver"


@dataclass(frozen=True)
class AuthenticatedActor:
    actor_id: str
    role: str
    auth_method: str = "bearer"
    mfa_verified_at: str | None = None


def _load_auth_configuration():
    analyst_token = os.getenv("AEGIS_ANALYST_TOKEN", "").strip()
    analyst_id = os.getenv("AEGIS_ANALYST_ID", "analyst").strip()

    if not analyst_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Response authentication is not configured.",
        )

    if len(analyst_token) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Response authentication credentials are too weak.",
        )

    if not analyst_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analyst identity is not configured.",
        )

    # The legacy approver bearer token has been retired. Approver identities
    # are issued only from IAM browser sessions after password + MFA login.
    return {
        analyst_token: AuthenticatedActor(
            actor_id=analyst_id,
            role=ANALYST_ROLE,
        ),
    }


def get_current_actor(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
) -> AuthenticatedActor:
    configured_credentials = _load_auth_configuration()

    if credentials is None:
        browser_session = authenticate_browser_session(request)
        if browser_session is not None:
            return AuthenticatedActor(
                actor_id=browser_session.user_id,
                role=browser_session.role,
                auth_method="browser_session",
                mfa_verified_at=browser_session.mfa_verified_at,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer or browser session authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unsupported authentication scheme.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    for configured_token, actor in configured_credentials.items():
        if hmac.compare_digest(
            credentials.credentials,
            configured_token,
        ):
            return actor

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_analyst_actor(
    actor: AuthenticatedActor = Depends(get_current_actor),
) -> AuthenticatedActor:
    if actor.role != ANALYST_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst permissions are required.",
        )

    return actor


def get_approver_actor(
    actor: AuthenticatedActor = Depends(get_current_actor),
) -> AuthenticatedActor:
    if actor.role != APPROVER_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Approver permissions are required.",
        )

    if actor.auth_method != "browser_session":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Approver actions require an MFA-authenticated browser session.",
        )

    if not has_recent_mfa(actor.mfa_verified_at):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Recent MFA verification is required for approver actions.",
        )

    return actor
