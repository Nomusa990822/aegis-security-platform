"""Pure parsers for supported Linux SSH and Nginx access-log formats."""

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Optional


_SSH_FAILURE = re.compile(
    r"sshd\\[\\d+\\]:\\s+Failed password for (?:invalid user )?(?P<username>\\S+) from (?P<ip>\\S+) port \\d+\\b",
    re.IGNORECASE,
)
_SSH_SUCCESS = re.compile(
    r"sshd\\[\\d+\\]:\\s+Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<username>\\S+) from (?P<ip>\\S+) port \\d+\\b",
    re.IGNORECASE,
)
_SYSLOG_TIME = re.compile(r"^(?P<month>[A-Z][a-z]{2})\\s+(?P<day>\\d{1,2})\\s+(?P<time>\\d{2}:\\d{2}:\\d{2})")
_NGINX_ACCESS = re.compile(
    r'^(?P<ip>\\S+) \\S+ \\S+ \\[(?P<time>[^]]+)\\] "(?P<method>[A-Z]+) (?P<target>[^ ]+) (?P<protocol>HTTP/[^ ]+)" (?P<status>\\d{3}) (?P<size>\\S+)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)


def _normalise_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _syslog_timestamp(line: str, year: Optional[int] = None) -> Optional[str]:
    match = _SYSLOG_TIME.match(line)
    if not match:
        return None
    try:
        parsed = datetime.strptime(
            f"{year or datetime.now(timezone.utc).year} {match.group('month')} {match.group('day')} {match.group('time')}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
        return parsed.isoformat()
    except ValueError:
        return None


def parse_sshd_line(
    line: str,
    *,
    source_system: str = "linux-sshd",
    external_event_id: Optional[str] = None,
    year: Optional[int] = None,
) -> Optional[dict]:
    """Convert one OpenSSH syslog line; return None for unsupported lines.

    Syslog timestamps do not include a year or timezone. This adapter assumes
    the supplied/current year and UTC; provide year for archived log files.
    """
    match = _SSH_FAILURE.search(line)
    outcome = "failure"
    if match is None:
        match = _SSH_SUCCESS.search(line)
        outcome = "success"
    if match is None:
        return None

    source_ip = _normalise_ip(match.group("ip"))
    occurred_at = _syslog_timestamp(line, year)
    if source_ip is None or occurred_at is None:
        return None

    username = match.group("username")
    return {
        "event_type": "authentication",
        "source_system": source_system,
        "external_event_id": external_event_id,
        "source_ip": source_ip,
        "username": username,
        "outcome": outcome,
        "description": f"OpenSSH {outcome} login for {username}; original log: {line.strip()[:1500]}",
        "occurred_at": occurred_at,
    }


def parse_nginx_access_line(
    line: str,
    *,
    source_system: str = "nginx-access",
    external_event_id: Optional[str] = None,
) -> Optional[dict]:
    """Convert one Nginx combined access-log line into a web-request event."""
    match = _NGINX_ACCESS.match(line)
    if match is None:
        return None
    source_ip = _normalise_ip(match.group("ip"))
    if source_ip is None:
        return None
    try:
        occurred_at = datetime.strptime(
            match.group("time"), "%d/%b/%Y:%H:%M:%S %z"
        ).isoformat()
        status = int(match.group("status"))
    except ValueError:
        return None

    outcome = "success" if status < 400 else "failure"
    method = match.group("method")
    target = match.group("target")
    protocol = match.group("protocol")
    return {
        "event_type": "web_request",
        "source_system": source_system,
        "external_event_id": external_event_id,
        "source_ip": source_ip,
        "outcome": outcome,
        "protocol": "http",
        "description": (
            f"Nginx request {method} {target} returned HTTP {status} "
            f"({protocol}); response_bytes={match.group('size')}"
        )[:2000],
        "occurred_at": occurred_at,
    }


def stable_event_id(source_system: str, file_identity: str, line_number: int, line: str) -> str:
    """Create a deterministic, non-reversible ID for a particular file line."""
    material = f"{source_system}\\0{file_identity}\\0{line_number}\\0{line}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()
