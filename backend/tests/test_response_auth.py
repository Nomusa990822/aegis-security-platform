
import pytest

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.auth import (
    AuthenticatedActor,
    get_analyst_actor,
    get_approver_actor,
)


ANALYST_TOKEN = "a" * 48
APPROVER_TOKEN = "b" * 48


@pytest.fixture
def auth_client(monkeypatch):
    monkeypatch.setenv("AEGIS_ANALYST_TOKEN", ANALYST_TOKEN)
    monkeypatch.setenv("AEGIS_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("AEGIS_ANALYST_ID", "analyst-alpha")
    monkeypatch.setenv("AEGIS_APPROVER_ID", "approver-beta")

    app = FastAPI()

    @app.get("/analyst")
    def analyst_endpoint(
        actor: AuthenticatedActor = Depends(get_analyst_actor),
    ):
        return {
            "actor_id": actor.actor_id,
            "role": actor.role,
        }

    @app.get("/approver")
    def approver_endpoint(
        actor: AuthenticatedActor = Depends(get_approver_actor),
    ):
        return {
            "actor_id": actor.actor_id,
            "role": actor.role,
        }

    return TestClient(app)


def test_analyst_token_authenticates_analyst(auth_client):
    response = auth_client.get(
        "/analyst",
        headers={"Authorization": f"Bearer {ANALYST_TOKEN}"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "actor_id": "analyst-alpha",
        "role": "analyst",
    }


def test_approver_token_authenticates_approver(auth_client):
    response = auth_client.get(
        "/approver",
        headers={"Authorization": f"Bearer {APPROVER_TOKEN}"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "actor_id": "approver-beta",
        "role": "approver",
    }


def test_missing_token_is_rejected(auth_client):
    response = auth_client.get("/analyst")

    assert response.status_code == 401


def test_invalid_token_is_rejected(auth_client):
    response = auth_client.get(
        "/analyst",
        headers={"Authorization": f"Bearer {'x' * 48}"},
    )

    assert response.status_code == 401


def test_approver_cannot_use_analyst_endpoint(auth_client):
    response = auth_client.get(
        "/analyst",
        headers={"Authorization": f"Bearer {APPROVER_TOKEN}"},
    )

    assert response.status_code == 403


def test_analyst_cannot_use_approver_endpoint(auth_client):
    response = auth_client.get(
        "/approver",
        headers={"Authorization": f"Bearer {ANALYST_TOKEN}"},
    )

    assert response.status_code == 403


def test_identical_role_tokens_are_rejected(
    auth_client,
    monkeypatch,
):
    monkeypatch.setenv("AEGIS_APPROVER_TOKEN", ANALYST_TOKEN)

    response = auth_client.get(
        "/analyst",
        headers={"Authorization": f"Bearer {ANALYST_TOKEN}"},
    )

    assert response.status_code == 503


@pytest.mark.parametrize(
    "variable,value",
    [
        ("AEGIS_ANALYST_TOKEN", "short"),
        ("AEGIS_APPROVER_TOKEN", "short"),
        ("AEGIS_ANALYST_ID", ""),
        ("AEGIS_APPROVER_ID", ""),
    ],
)
def test_unsafe_auth_configuration_is_rejected(
    auth_client,
    monkeypatch,
    variable,
    value,
):
    monkeypatch.setenv(variable, value)

    response = auth_client.get(
        "/analyst",
        headers={"Authorization": f"Bearer {ANALYST_TOKEN}"},
    )

    assert response.status_code == 503


def test_identical_actor_ids_are_rejected(
    auth_client,
    monkeypatch,
):
    monkeypatch.setenv("AEGIS_APPROVER_ID", "analyst-alpha")

    response = auth_client.get(
        "/approver",
        headers={"Authorization": f"Bearer {APPROVER_TOKEN}"},
    )

    assert response.status_code == 503
