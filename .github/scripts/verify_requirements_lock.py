#!/usr/bin/env python3
"""Validate the structure and direct-dependency coverage of AEGIS's pip lockfile."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / "backend" / "requirements.txt"
LOCK = ROOT / "backend" / "requirements.lock"

LOCK_ENTRY = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)$"
)
REQUIREMENT_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def read_lines(path: Path) -> list[str]:
    if not path.is_file():
        raise ValueError(f"Required file is missing: {path.relative_to(ROOT)}")
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def main() -> int:
    try:
        lock_lines = read_lines(LOCK)
        input_lines = read_lines(INPUT)

        if not lock_lines:
            raise ValueError("The dependency lockfile is empty.")

        locked: dict[str, str] = {}
        for line_number, line in enumerate(lock_lines, start=1):
            match = LOCK_ENTRY.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"Lockfile line {line_number} is not an exact name==version pin."
                )

            name = normalize(match.group("name"))
            if name in locked:
                raise ValueError(
                    f"Duplicate normalized package name in lockfile: {name}"
                )
            locked[name] = match.group("version")

        direct_names: set[str] = set()
        for line_number, line in enumerate(input_lines, start=1):
            match = REQUIREMENT_NAME.match(line)
            if match is None:
                raise ValueError(
                    f"Unsupported direct requirement on line {line_number}: "
                    "expected a named PyPI package requirement."
                )
            direct_names.add(normalize(match.group(1)))

        missing = sorted(direct_names - locked.keys())
        if missing:
            raise ValueError(
                "Direct requirements missing from lockfile: " + ", ".join(missing)
            )

        print(
            "Lockfile structure valid: "
            f"{len(locked)} exact package pins; "
            f"all {len(direct_names)} direct requirements are represented."
        )
        print(
            "Note: this lockfile has no artifact hashes; "
            "this check verifies pins and coverage, not downloaded-file identity."
        )
        return 0

    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Lockfile validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
