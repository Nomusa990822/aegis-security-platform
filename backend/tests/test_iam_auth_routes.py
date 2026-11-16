from http.cookies import SimpleCookie

import pytest

from app import database
from app.iam import auth_routes
from app.iam.accounts import activate_account, create_invitation
from app.iam.migrations import apply_migrations
from app.iam.passwords import PasswordService

ORIGIN = "https://aegis.example.test"
TEST_PASSWORD = "a sufficiently long analyst passphrase"


@pytest.fixture
def iam_client(client, monkeypatch):
    monkeypatch.setenv("AEGIS_AUTH_THROTTLE_HMAC_KEY", "throttle-key-" + "t" * 40)
    monkeypatch.setenv("AEGIS_CSRF_SIGNING_KEY", "csrf-key-" + "c" * 40)
    monkeypatch.setenv("AEGIS_IAM_ALLOWED_ORIGINS", ORIGIN)
    fast_passwords = PasswordService(
        memory_cost=1024, time_cost=1, parallelism=1
    )
    monkeypatch.setattr(auth_routes, "DEFAULT_PASSWORD_SERVICE", fast_passwords)

    with database.get_connection() as connection:
        apply_migrations(
            connection, applied_at="2026-11-16T12:00:00+00:00"
        )
        analyst = create_invitation(
            connection, username="analyst.login", role="analyst",
            password_service=fast_passwords,
        )
        activate_account(
            connection, activation_token=analyst.activation_token,
            new_password=TEST_PASSWORD, password_service=fast_passwords,
        )
        approver = create_invitation(
            connection, username="approver.login", role="approver",
            password_service=fast_passwords,
        )
        activate_account(
            connection, activation_token=approver.activation_token,
            new_password=TEST_PASSWORD, password_service=fast_passwords,
        )
    return client


def _cookie(response):
    parsed = SimpleCookie()
    parsed.load(response.headers["set-cookie"])
    return parsed["__Host-aegis_session"].value


def test_analyst_login_sets_secure_http_only_cookie_and_session(iam_client):
    response = iam_client.post(
        "/api/v1/iam/login",
        json={"username": "analyst.login", "password": TEST_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "analyst"
    assert len(response.json()["csrf_token"]) == 64
    cookie = response.headers["set-cookie"].lower()
    assert "__host-aegis_session=" in cookie
    assert "secure" in cookie
    assert "httponly" in cookie
    assert "path=/" in cookie
    assert "samesite=lax" in cookie
    assert response.headers["cache-control"] == "no-store"

    token = _cookie(response)
    inspected = iam_client.get(
        "/api/v1/iam/session",
        headers={"Cookie": f"__Host-aegis_session={token}"},
    )
    assert inspected.status_code == 200
    assert inspected.headers["cache-control"] == "no-store"
    assert inspected.headers["pragma"] == "no-cache"
    assert inspected.json()["user"]["username"] == "analyst.login"
    assert inspected.json()["mfa_verified"] is False


def test_approver_password_login_is_rejected_generically(iam_client):
    response = iam_client.post(
        "/api/v1/iam/login",
        json={"username": "approver.login", "password": TEST_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["detail"] == "Username or password is incorrect."
    assert "__Host-aegis_session" not in response.headers.get("set-cookie", "")


def test_invalid_login_has_generic_error_and_unknown_user_path(iam_client):
    response = iam_client.post(
        "/api/v1/iam/login",
        json={"username": "unknown.login", "password": TEST_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Username or password is incorrect."


def test_login_rejects_untrusted_origin_before_authentication(iam_client):
    response = iam_client.post(
        "/api/v1/iam/login",
        json={"username": "analyst.login", "password": TEST_PASSWORD},
        headers={"Origin": "https://attacker.example"},
    )
    assert response.status_code == 403


def test_logout_requires_csrf_and_revokes_session(iam_client):
    login = iam_client.post(
        "/api/v1/iam/login",
        json={"username": "analyst.login", "password": TEST_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    token = _cookie(login)
    csrf = login.json()["csrf_token"]
    rejected = iam_client.post(
        "/api/v1/iam/logout",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"__Host-aegis_session={token}",
        },
    )
    assert rejected.status_code == 403

    logged_out = iam_client.post(
        "/api/v1/iam/logout",
        headers={
            "Origin": ORIGIN,
            "Cookie": f"__Host-aegis_session={token}",
            "X-Aegis-CSRF-Token": csrf,
        },
    )
    assert logged_out.status_code == 200
    assert logged_out.json() == {"authenticated": False}
    assert "max-age=0" in logged_out.headers["set-cookie"].lower()

    inspected = iam_client.get(
        "/api/v1/iam/session",
        headers={"Cookie": f"__Host-aegis_session={token}"},
    )
    assert inspected.status_code == 401


def test_login_fails_closed_when_required_secrets_are_missing(iam_client, monkeypatch):
    monkeypatch.delenv("AEGIS_CSRF_SIGNING_KEY")
    response = iam_client.post(
        "/api/v1/iam/login",
        json={"username": "analyst.login", "password": TEST_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 503
