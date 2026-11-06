
import hmac
import os
from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)


bearer_scheme = HTTPBearer(auto_error=False)

ANALYST_ROLE = "analyst"
APPROVER_ROLE = "approver"


@dataclass(frozen=True)
class AuthenticatedActor:
    actor_id: str
    role: str


def _load_auth_configuration():
    analyst_token = os.getenv("AEGIS_ANALYST_TOKEN", "").strip()
    approver_token = os.getenv("AEGIS_APPROVER_TOKEN", "").strip()

    analyst_id = os.getenv("AEGIS_ANALYST_ID", "analyst").strip()
    approver_id = os.getenv("AEGIS_APPROVER_ID", "approver").strip()

    if not analyst_token or not approver_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Response authentication is not configured.",
        )

    if len(analyst_token) < 32 or len(approver_token) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Response authentication credentials are too weak.",
        )

    if hmac.compare_digest(analyst_token, approver_token):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analyst and approver credentials must be different.",
        )

    if (
        not analyst_id
        or not approver_id
        or analyst_id == approver_id
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analyst and approver identities must be distinct.",
        )

    return {
        analyst_token: AuthenticatedActor(
            actor_id=analyst_id,
            role=ANALYST_ROLE,
        ),
        approver_token: AuthenticatedActor(
            actor_id=approver_id,
            role=APPROVER_ROLE,
        ),
    }


def get_current_actor(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
) -> AuthenticatedActor:
    configured_credentials = _load_auth_configuration()

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer authentication is required.",
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

    return actor
