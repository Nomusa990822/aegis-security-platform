import json
import sqlite3

import pytest

from app.iam.migrations import apply_migrations
from app.iam.security_events import record_security_event

NOW = "2026-11-12T10:00:00+00:00"


@pytest.fixture
def connection():
    db = sqlite3.connect(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    apply_migrations(db, applied_at=NOW)
    try:
        yield db
    finally:
        db.close()


def test_records_safe_security_event(connection):
    event_id = record_security_event(
        connection, event_type="account_invited", occurred_at=NOW,
        success=True, metadata={"role": "analyst"},
    )
    row = connection.execute(
        "SELECT id, event_type, success, metadata_json "
        "FROM iam_security_events WHERE id = ?", (event_id,)
    ).fetchone()
    assert row[:3] == (event_id, "account_invited", 1)
    assert json.loads(row[3]) == {"role": "analyst"}


@pytest.mark.parametrize(
    "metadata",
    [{"password": "do-not-log"}, {"nested": {"access_token": "do-not-log"}},
     {"recovery_code": "do-not-log"}],
)
def test_rejects_sensitive_metadata_keys(connection, metadata):
    with pytest.raises(ValueError, match="sensitive"):
        record_security_event(
            connection, event_type="account_invited", occurred_at=NOW,
            success=True, metadata=metadata,
        )


def test_rejects_invalid_event_type_and_non_boolean_success(connection):
    with pytest.raises(ValueError):
        record_security_event(
            connection, event_type="Bad Event", occurred_at=NOW, success=True
        )
    with pytest.raises(ValueError):
        record_security_event(
            connection, event_type="account_login", occurred_at=NOW, success=1
        )


def test_rejects_oversized_metadata(connection):
    with pytest.raises(ValueError, match="4096"):
        record_security_event(
            connection, event_type="account_invited", occurred_at=NOW,
            success=True, metadata={"detail": "x" * 5000},
        )
