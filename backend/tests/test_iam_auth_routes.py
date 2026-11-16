from http.cookies import SimpleCookie

import pytest
from fastapi.testclient import TestClient

from app import database
from app.main import app
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
    import base64
    monkeypatch.setenv(
        "AEGIS_MFA_ENCRYPTION_KEY",
        base64.urlsafe_b64encode(b"m" * 32).decode("ascii").rstrip("="),
    )
    monkeypatch.setenv("AEGIS_MFA_ENCRYPTION_KEY_ID", "test-key-v1")
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


def test_analyst_cookie_session_authenticates_api_and_enforces_csrf(iam_client, seeded_alert):
    # Use a client without the legacy bearer header so this exercises the
    # browser-session authentication path rather than bearer-token fallback.
    login = iam_client.post(
        "/api/v1/iam/login",
        json={"username": "analyst.login", "password": TEST_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    token = _cookie(login)
    csrf = login.json()["csrf_token"]

    with TestClient(app) as browser_client:
        cookie_header = {"Cookie": f"__Host-aegis_session={token}"}
        read_response = browser_client.get(
            "/api/v1/alerts", headers=cookie_header
        )
        assert read_response.status_code == 200

        blocked_write = browser_client.post(
            f"/api/v1/alerts/{seeded_alert}/notes",
            json={"content": "This write must require CSRF."},
            headers={**cookie_header, "Origin": ORIGIN},
        )
        assert blocked_write.status_code == 403

        accepted_write = browser_client.post(
            f"/api/v1/alerts/{seeded_alert}/notes",
            json={"content": "Cookie-authenticated analyst investigation."},
            headers={
                **cookie_header,
                "Origin": ORIGIN,
                "X-Aegis-CSRF-Token": csrf,
            },
        )
        assert accepted_write.status_code == 201
        assert accepted_write.json()["note"]["author"] != "analyst-alpha"


def test_analyst_cookie_session_cannot_access_approver_only_api(iam_client):
    login = iam_client.post(
        "/api/v1/iam/login",
        json={"username": "analyst.login", "password": TEST_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    token = _cookie(login)
    with TestClient(app) as browser_client:
        response = browser_client.get(
            "/api/v1/response/1/audit-integrity",
            headers={"Cookie": f"__Host-aegis_session={token}"},
        )
    assert response.status_code == 403



def _enable_totp_for_user(username):
    from datetime import datetime, timedelta, timezone
    from app.iam import mfa, repository, totp

    enrollment_time = datetime.now(timezone.utc) - timedelta(seconds=60)
    with database.get_connection() as connection:
        account = repository.get_account_by_username(connection, username)
        enrollment = mfa.begin_totp_enrollment(
            connection, user_id=account["id"], now=enrollment_time
        )
        mfa.confirm_totp_enrollment(
            connection, user_id=account["id"],
            factor_id=enrollment["factor_id"],
            code=totp.code_at(
                enrollment["secret"], at_time=enrollment_time.timestamp()
            ),
            now=enrollment_time,
            password_service=auth_routes.DEFAULT_PASSWORD_SERVICE,
        )
    return enrollment["secret"]


def test_mfa_enabled_approver_login_requires_second_factor(iam_client):
    from app.iam import totp

    secret = _enable_totp_for_user("approver.login")
    password_login = iam_client.post(
        "/api/v1/iam/login",
        json={"username": "approver.login", "password": TEST_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert password_login.status_code == 200
    assert password_login.json()["mfa_required"] is True
    assert password_login.json()["authenticated"] is False
    assert "__Host-aegis_mfa_challenge=" in password_login.headers["set-cookie"]
    assert "__Host-aegis_session=" not in password_login.headers["set-cookie"]

    challenge_cookie = SimpleCookie()
    challenge_cookie.load(password_login.headers["set-cookie"])
    challenge_token = challenge_cookie["__Host-aegis_mfa_challenge"].value
    completed = iam_client.post(
        "/api/v1/iam/login/mfa",
        json={"code": totp.code_at(secret)},
        headers={
            "Origin": ORIGIN,
            "Cookie": f"__Host-aegis_mfa_challenge={challenge_token}",
        },
    )
    assert completed.status_code == 200
    assert completed.json()["authenticated"] is True
    assert completed.json()["user"]["role"] == "approver"
    assert completed.json()["mfa_verified"] is True
    assert "__Host-aegis_session=" in completed.headers["set-cookie"]

    session_cookie = SimpleCookie()
    for set_cookie in completed.headers.get_list("set-cookie"):
        session_cookie.load(set_cookie)
    session_token = session_cookie["__Host-aegis_session"].value
    session = iam_client.get(
        "/api/v1/iam/session",
        headers={"Cookie": f"__Host-aegis_session={session_token}"},
    )
    assert session.status_code == 200
    assert session.json()["user"]["role"] == "approver"
    assert session.json()["mfa_verified"] is True


def test_mfa_challenge_rejects_wrong_code_and_does_not_issue_session(iam_client):
    _enable_totp_for_user("analyst.login")
    password_login = iam_client.post(
        "/api/v1/iam/login",
        json={"username": "analyst.login", "password": TEST_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert password_login.status_code == 200
    assert password_login.json()["mfa_required"] is True
    challenge_cookie = SimpleCookie()
    challenge_cookie.load(password_login.headers["set-cookie"])
    challenge_token = challenge_cookie["__Host-aegis_mfa_challenge"].value
    failed = iam_client.post(
        "/api/v1/iam/login/mfa",
        json={"code": "000000"},
        headers={
            "Origin": ORIGIN,
            "Cookie": f"__Host-aegis_mfa_challenge={challenge_token}",
        },
    )
    assert failed.status_code == 401
    assert "__Host-aegis_session=" not in failed.headers.get("set-cookie", "")
