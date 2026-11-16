import sqlite3

import pytest

from app.iam.migrations import apply_migrations
from app.iam import admin

NOW = "2026-11-12T10:00:00+00:00"


def make_database(path):
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    apply_migrations(connection, applied_at=NOW)
    connection.commit()
    connection.close()


def test_cli_refuses_missing_database_without_creating_it(monkeypatch, tmp_path):
    missing = tmp_path / "missing.db"
    monkeypatch.setattr(admin, "DATABASE_PATH", missing)
    with pytest.raises(FileNotFoundError):
        admin._open_existing_database(missing)
    assert not missing.exists()


def test_cli_refuses_symlink_database(monkeypatch, tmp_path):
    actual = tmp_path / "actual.db"
    make_database(actual)
    link = tmp_path / "linked.db"
    link.symlink_to(actual)
    monkeypatch.setattr(admin, "DATABASE_PATH", link)
    with pytest.raises(RuntimeError, match="symlink"):
        admin._open_existing_database(link)


def test_cli_invites_and_activates_without_passwords_in_arguments(
    monkeypatch, tmp_path, capsys
):
    database = tmp_path / "aegis.db"
    make_database(database)
    monkeypatch.setattr(admin, "DATABASE_PATH", database)

    assert admin.main([
        "invite", "--username", "analyst.one", "--role", "analyst"
    ]) == 0
    output = capsys.readouterr().out
    token = output.strip().splitlines()[-1]
    assert len(token) >= 40

    prompts = iter([token, "correct horse battery staple", "correct horse battery staple"])
    monkeypatch.setattr(admin, "getpass", lambda _prompt: next(prompts))
    assert admin.main(["activate"]) == 0
    assert "Account activated: analyst.one" in capsys.readouterr().out

    connection = sqlite3.connect(database)
    status = connection.execute(
        "SELECT status FROM iam_users WHERE username_normalized = 'analyst.one'"
    ).fetchone()[0]
    connection.close()
    assert status == "active"


def test_cli_rejects_password_confirmation_mismatch(
    monkeypatch, tmp_path, capsys
):
    database = tmp_path / "aegis.db"
    make_database(database)
    monkeypatch.setattr(admin, "DATABASE_PATH", database)
    prompts = iter(["a" * 43, "correct horse battery staple", "a different long passphrase"])
    monkeypatch.setattr(admin, "getpass", lambda _prompt: next(prompts))
    assert admin.main(["activate"]) == 1
    assert "confirmation does not match" in capsys.readouterr().err


def test_sensitive_operator_output_is_written_only_to_attached_terminal(monkeypatch):
    opened = []
    writes = []
    closed = []
    monkeypatch.setattr(
        admin.os, "open",
        lambda path, flags: opened.append((path, flags)) or 17,
    )
    monkeypatch.setattr(
        admin.os, "write",
        lambda descriptor, payload: writes.append((descriptor, payload)) or len(payload),
    )
    monkeypatch.setattr(admin.os, "close", lambda descriptor: closed.append(descriptor))

    admin._write_sensitive_terminal_output("provisioning-secret", "recovery-code")

    assert opened[0][0] == "/dev/tty"
    assert writes == [(17, b"provisioning-secret\\nrecovery-code\\n")]
    assert closed == [17]


def test_sensitive_operator_output_fails_closed_without_a_terminal(monkeypatch):
    def no_terminal(_path, _flags):
        raise OSError("no controlling terminal")

    monkeypatch.setattr(admin.os, "open", no_terminal)
    with pytest.raises(OSError, match="no controlling terminal"):
        admin._write_sensitive_terminal_output("provisioning-secret")
