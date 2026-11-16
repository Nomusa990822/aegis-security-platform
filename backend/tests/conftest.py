
import pytest

from fastapi.testclient import TestClient

from app import database
from app.main import app
from app.rate_limiting import APIRateLimitMiddleware


ANALYST_TEST_TOKEN = "a" * 48


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    """
    Give each test its own temporary SQLite database.
    The real backend database is never used.
    """
    test_database = tmp_path / "aegis_test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        test_database,
    )

    monkeypatch.setenv(
        "AEGIS_ANALYST_TOKEN",
        ANALYST_TEST_TOKEN,
    )
    monkeypatch.setenv(
        "AEGIS_ANALYST_ID",
        "analyst-alpha",
    )
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_KEY",
        "aegis-test-checkpoint-secret-" + ("x" * 32),
    )
    monkeypatch.setenv(
        "AEGIS_AUDIT_CHECKPOINT_DIR",
        str(tmp_path / "audit-checkpoints"),
    )

    database.initialize_database()

    return test_database


@pytest.fixture
def client(isolated_database):
    with TestClient(
        app,
        headers={
            "Authorization": f"Bearer {ANALYST_TEST_TOKEN}",
        },
    ) as test_client:
        # The FastAPI app is a module-level singleton, so its middleware
        # instance survives between TestClient instances. Each test already
        # receives an isolated database; reset rate-limit state as well.
        middleware = app.middleware_stack
        while middleware is not None:
            if isinstance(middleware, APIRateLimitMiddleware):
                middleware.reset()
                break
            middleware = getattr(middleware, "app", None)
        else:
            raise RuntimeError("API rate-limit middleware was not installed")

        yield test_client



@pytest.fixture
def approver_client(client, monkeypatch):
    """Create a real approver browser session completed with TOTP MFA."""
    import base64
    from datetime import datetime, timedelta, timezone
    from http.cookies import SimpleCookie

    from app.iam import auth_routes, mfa, repository, totp
    from app.iam.accounts import activate_account, create_invitation
    from app.iam.migrations import apply_migrations
    from app.iam.passwords import PasswordService

    origin = "https://aegis.example.test"
    password = "a sufficiently long approver test passphrase"
    fast_passwords = PasswordService(
        memory_cost=1024, time_cost=1, parallelism=1
    )
    monkeypatch.setattr(
        auth_routes, "DEFAULT_PASSWORD_SERVICE", fast_passwords
    )
    monkeypatch.setenv("AEGIS_AUTH_THROTTLE_HMAC_KEY", "throttle-key-" + "t" * 40)
    monkeypatch.setenv("AEGIS_CSRF_SIGNING_KEY", "csrf-key-" + "c" * 40)
    monkeypatch.setenv("AEGIS_IAM_ALLOWED_ORIGINS", origin)
    monkeypatch.setenv(
        "AEGIS_MFA_ENCRYPTION_KEY",
        base64.urlsafe_b64encode(b"m" * 32).decode("ascii").rstrip("="),
    )
    monkeypatch.setenv("AEGIS_MFA_ENCRYPTION_KEY_ID", "test-key-v1")

    with database.get_connection() as connection:
        apply_migrations(connection, applied_at="2026-11-16T12:00:00+00:00")
        invitation = create_invitation(
            connection,
            username="approver.test",
            role="approver",
            password_service=fast_passwords,
        )
        activate_account(
            connection,
            activation_token=invitation.activation_token,
            new_password=password,
            password_service=fast_passwords,
        )
        account = repository.get_account_by_username(
            connection, "approver.test"
        )
        enrollment_time = datetime.now(timezone.utc) - timedelta(seconds=60)
        enrollment = mfa.begin_totp_enrollment(
            connection, user_id=account["id"], now=enrollment_time
        )
        mfa.confirm_totp_enrollment(
            connection,
            user_id=account["id"],
            factor_id=enrollment["factor_id"],
            code=totp.code_at(
                enrollment["secret"], at_time=enrollment_time.timestamp()
            ),
            now=enrollment_time,
            password_service=fast_passwords,
        )

    with TestClient(app) as browser_client:
        password_login = browser_client.post(
            "/api/v1/iam/login",
            json={"username": "approver.test", "password": password},
            headers={"Origin": origin},
        )
        assert password_login.status_code == 200
        assert password_login.json()["mfa_required"] is True

        challenge_cookies = SimpleCookie()
        for value in password_login.headers.get_list("set-cookie"):
            challenge_cookies.load(value)
        challenge_token = challenge_cookies[
            "__Host-aegis_mfa_challenge"
        ].value

        completed = browser_client.post(
            "/api/v1/iam/login/mfa",
            json={"code": totp.code_at(enrollment["secret"])},
            headers={
                "Origin": origin,
                "Cookie": f"__Host-aegis_mfa_challenge={challenge_token}",
            },
        )
        assert completed.status_code == 200
        assert completed.json()["mfa_verified"] is True

        session_cookies = SimpleCookie()
        for value in completed.headers.get_list("set-cookie"):
            session_cookies.load(value)
        session_token = session_cookies["__Host-aegis_session"].value

        browser_client.headers.update({
            "Cookie": f"__Host-aegis_session={session_token}",
            "Origin": origin,
            "X-Aegis-CSRF-Token": completed.json()["csrf_token"],
        })
        yield browser_client


@pytest.fixture
def approver_id(approver_client):
    with database.get_connection() as connection:
        account = connection.execute(
            "SELECT id FROM iam_users WHERE username = ?",
            ("approver.test",),
        ).fetchone()
    return account["id"]


@pytest.fixture
def seeded_alert(isolated_database):
    with database.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO security_alerts (
                title,
                severity,
                description,
                source_ip,
                detection_rule,
                created_at,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "Integration Test Alert",
                "high",
                "Test authentication activity",
                "198.51.100.250",
                "AEGIS-AUTH-001",
                "2026-11-03T10:00:00+00:00",
                "open",
            ),
        )

        alert_id = cursor.lastrowid
        connection.commit()

    return alert_id


@pytest.fixture
def seeded_event(isolated_database):
    with database.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO security_events (
                event_type,
                source_ip,
                username,
                outcome,
                description,
                occurred_at,
                received_at,
                destination_ip,
                destination_port,
                protocol
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "authentication_failed",
                "198.51.100.250",
                "test-user",
                "failure",
                "Integration test event",
                "2026-11-03T10:00:00+00:00",
                "2026-11-03T10:00:00+00:00",
                None,
                None,
                None,
            ),
        )

        event_id = cursor.lastrowid
        connection.commit()

    return event_id


@pytest.fixture
def seeded_correlation(isolated_database, seeded_alert):
    with database.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO security_correlations (
                title,
                severity,
                source_ip,
                description,
                alert_count,
                status,
                created_at,
                updated_at,
                assigned_to
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "Integration Test Correlation",
                "high",
                "198.51.100.250",
                "Test correlated security activity",
                1,
                "open",
                "2026-11-03T10:00:00+00:00",
                "2026-11-03T10:00:00+00:00",
                None,
            ),
        )

        correlation_id = cursor.lastrowid

        connection.execute(
            """
            INSERT INTO security_correlation_alerts (
                correlation_id,
                alert_id,
                linked_at
            )
            VALUES (?, ?, ?)
            """,
            (
                correlation_id,
                seeded_alert,
                "2026-11-03T10:00:00+00:00",
            ),
        )

        connection.commit()

    return correlation_id
