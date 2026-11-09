"""Command-line importer for supported log files."""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.telemetry.adapter import (
    parse_nginx_access_line,
    parse_sshd_line,
    stable_event_id,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse Linux SSH or Nginx logs and submit events to AEGIS."
    )
    parser.add_argument("log_file", type=Path)
    parser.add_argument("--format", required=True, choices=("sshd", "nginx"))
    parser.add_argument("--source-system", default=None)
    parser.add_argument("--api-url", default=os.getenv("AEGIS_API_URL", "http://127.0.0.1:8000/api/v1/events"))
    parser.add_argument("--dry-run", action="store_true", help="Parse and print events without submitting them")
    parser.add_argument("--year", type=int, help="Year for yearless SSH syslog timestamps")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.log_file.is_file():
        print(f"Log file does not exist: {args.log_file}", file=sys.stderr)
        return 2

    source_system = args.source_system or ("linux-sshd" if args.format == "sshd" else "nginx-access")
    token = os.getenv("AEGIS_ANALYST_TOKEN")
    if not args.dry_run and not token:
        print("AEGIS_ANALYST_TOKEN is required unless --dry-run is used.", file=sys.stderr)
        return 2

    parser = parse_sshd_line if args.format == "sshd" else parse_nginx_access_line
    parsed_count = submitted_count = ignored_count = duplicate_count = 0
    file_identity = str(args.log_file.resolve())

    try:
        with args.log_file.open("r", encoding="utf-8", errors="replace") as stream:
            for line_number, line in enumerate(stream, start=1):
                event_id = stable_event_id(source_system, file_identity, line_number, line)
                options = {"source_system": source_system, "external_event_id": event_id}
                if args.format == "sshd":
                    options["year"] = args.year
                event = parser(line, **options)
                if event is None:
                    ignored_count += 1
                    continue
                parsed_count += 1

                if args.dry_run:
                    print(json.dumps(event, sort_keys=True))
                    continue

                request = Request(
                    args.api_url,
                    data=json.dumps(event).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                try:
                    with urlopen(request, timeout=15) as response:
                        result = json.loads(response.read().decode("utf-8"))
                except HTTPError as error:
                    detail = error.read(1000).decode("utf-8", errors="replace")
                    print(f"Ingestion failed at line {line_number}: HTTP {error.code}: {detail}", file=sys.stderr)
                    return 1
                except URLError as error:
                    print(f"Unable to reach AEGIS at line {line_number}: {error.reason}", file=sys.stderr)
                    return 1

                submitted_count += 1
                if result.get("duplicate"):
                    duplicate_count += 1

    except OSError as error:
        print(f"Unable to read log file: {error}", file=sys.stderr)
        return 2

    print(
        f"Parsed: {parsed_count}; submitted: {submitted_count}; "
        f"duplicates: {duplicate_count}; ignored: {ignored_count}; "
        f"dry_run: {str(args.dry_run).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
