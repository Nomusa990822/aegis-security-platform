from datetime import datetime

import pytest

from app.telemetry.cli import main as telemetry_cli_main

from app.telemetry.adapter import (
    parse_nginx_access_line,
    parse_sshd_line,
    stable_event_id,
)


def test_sshd_failed_password_maps_to_authentication_failure():
    line = "Nov  9 10:00:00 host sshd[123]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2"
    event = parse_sshd_line(line, external_event_id="ssh-1", year=2026)

    assert event["event_type"] == "authentication"
    assert event["source_system"] == "linux-sshd"
    assert event["source_ip"] == "203.0.113.5"
    assert event["username"] == "admin"
    assert event["outcome"] == "failure"
    assert event["external_event_id"] == "ssh-1"
    assert datetime.fromisoformat(event["occurred_at"]).year == 2026


def test_sshd_accepted_public_key_maps_to_success():
    line = "Nov  9 10:00:00 host sshd[123]: Accepted publickey for nomusa from 2001:db8::5 port 54321 ssh2"
    event = parse_sshd_line(line, year=2026)

    assert event["outcome"] == "success"
    assert event["source_ip"] == "2001:db8::5"
    assert event["username"] == "nomusa"


@pytest.mark.parametrize("line", [
    "Nov  9 10:00:00 host sshd[123]: Connection closed by authenticating user admin 203.0.113.5 port 22 [preauth]",
    "not a syslog line",
    "Nov  9 10:00:00 host sshd[123]: Failed password for admin from not-an-ip port 22 ssh2",
])
def test_sshd_unsupported_or_malformed_lines_are_ignored(line):
    assert parse_sshd_line(line, year=2026) is None


def test_nginx_access_line_maps_request_and_status():
    line = '198.51.100.24 - - [09/Nov/2026:10:15:30 +0200] "GET /login HTTP/1.1" 401 153 "-" "Mozilla/5.0"'
    event = parse_nginx_access_line(line, external_event_id="nginx-1")

    assert event["event_type"] == "web_request"
    assert event["source_system"] == "nginx-access"
    assert event["source_ip"] == "198.51.100.24"
    assert event["outcome"] == "failure"
    assert event["protocol"] == "http"
    assert "GET /login" in event["description"]
    assert datetime.fromisoformat(event["occurred_at"]).utcoffset().total_seconds() == 7200


def test_nginx_success_status_maps_to_success():
    line = '198.51.100.24 - - [09/Nov/2026:10:15:30 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/8"'
    event = parse_nginx_access_line(line)
    assert event["outcome"] == "success"


@pytest.mark.parametrize("line", [
    "not an access log",
    'not-an-ip - - [09/Nov/2026:10:15:30 +0000] "GET / HTTP/1.1" 200 1 "-" "x"',
    '198.51.100.24 - - [invalid] "GET / HTTP/1.1" 200 1 "-" "x"',
])
def test_nginx_malformed_lines_are_ignored(line):
    assert parse_nginx_access_line(line) is None


def test_external_event_identity_is_deterministic_per_file_line():
    first = stable_event_id("nginx-access", "/var/log/nginx/access.log", 4, "same line")
    replay = stable_event_id("nginx-access", "/var/log/nginx/access.log", 4, "same line")
    repeated_line = stable_event_id("nginx-access", "/var/log/nginx/access.log", 5, "same line")

    assert first == replay
    assert first != repeated_line
    assert len(first) == 64


def test_parsed_events_are_accepted_by_existing_ingestion_api(client):
    line = "Nov  9 10:00:00 host sshd[123]: Failed password for admin from 203.0.113.5 port 54321 ssh2"
    event = parse_sshd_line(line, external_event_id="adapter-integration-1", year=2026)

    response = client.post("/api/v1/events", json=event)

    assert response.status_code == 201
    assert response.json()["duplicate"] is False
    assert response.json()["event_id"] is not None

    replay = client.post("/api/v1/events", json=event)
    assert replay.status_code == 200
    assert replay.json()["duplicate"] is True
    assert replay.json()["event_id"] == response.json()["event_id"]


def test_parsed_nginx_event_is_accepted_by_existing_ingestion_api(client):
    line = '198.51.100.24 - - [09/Nov/2026:10:15:30 +0200] "GET /login HTTP/1.1" 404 153 "-" "Mozilla/5.0"'
    event = parse_nginx_access_line(line, external_event_id="adapter-nginx-1")
    response = client.post("/api/v1/events", json=event)

    assert response.status_code == 201
    assert response.json()["detection_count"] == 0



def test_cli_dry_run_parses_file_without_api_credentials(tmp_path, monkeypatch, capsys):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Nov  9 10:00:00 host sshd[123]: Failed password for admin from 203.0.113.5 port 54321 ssh2\\n"
        "Nov  9 10:00:01 host sshd[123]: Connection closed by authenticating user admin 203.0.113.5 port 22 [preauth]\\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("AEGIS_ANALYST_TOKEN", raising=False)

    result = telemetry_cli_main([
        str(log_file), "--format", "sshd", "--year", "2026", "--dry-run"
    ])

    output = capsys.readouterr().out
    assert result == 0
    assert '"event_type": "authentication"' in output
    assert "Parsed: 1; submitted: 0; duplicates: 0; ignored: 1; dry_run: true" in output


def test_cli_requires_analyst_token_for_submission(tmp_path, monkeypatch, capsys):
    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")
    monkeypatch.delenv("AEGIS_ANALYST_TOKEN", raising=False)

    result = telemetry_cli_main([str(log_file), "--format", "sshd"])

    assert result == 2
    assert "AEGIS_ANALYST_TOKEN is required" in capsys.readouterr().err
