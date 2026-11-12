"""Controlled local-operator CLI for IAM invitations and account status.

This CLI is intentionally local-only. Do not expose its functions as public
HTTP endpoints. Invitation tokens are printed once for secure out-of-band
delivery; activation credentials and passwords are read with getpass.
"""
import argparse
from getpass import getpass
from pathlib import Path
import sqlite3
import sys

from app.database import DATABASE_PATH
from app.iam.accounts import (
    activate_account, change_account_status, create_invitation,
)
from app.iam.exceptions import IAMError
from app.iam.migrate import _check_database


def _open_existing_database(path: Path) -> sqlite3.Connection:
    if path.is_symlink():
        raise RuntimeError("Refusing to use a symlink database path")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise RuntimeError("IAM database must be an existing regular file")
    pending = _check_database(resolved)
    if pending:
        raise RuntimeError(
            "IAM schema is not current; apply guarded migrations before account administration"
        )
    connection = sqlite3.connect(
        f"{resolved.as_uri()}?mode=rw", uri=True, timeout=30
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Local AEGIS IAM operator commands (no public registration)"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    invite = commands.add_parser("invite", help="create an invited local account")
    invite.add_argument("--username", required=True)
    invite.add_argument("--role", required=True, choices=("analyst", "approver"))
    invite.add_argument("--expires-in", type=int, default=86400)
    commands.add_parser(
        "activate", help="activate an account using its one-time invitation"
    )
    for status in ("disable", "lock"):
        action = commands.add_parser(
            status, help=f"{status} an account and revoke sessions"
        )
        action.add_argument("--user-id", required=True)

    args = parser.parse_args(argv)
    try:
        connection = _open_existing_database(DATABASE_PATH)
        try:
            if args.command == "invite":
                invitation = create_invitation(
                    connection, username=args.username, role=args.role,
                    expires_in_seconds=args.expires_in,
                )
                connection.commit()
                print("Invitation created.")
                print(f"User ID: {invitation.user_id}")
                print(f"Username: {invitation.username}")
                print(f"Role: {invitation.role}")
                print(f"Expires at: {invitation.expires_at}")
                print(
                    "One-time activation token (deliver securely; "
                    "it will not be shown again):"
                )
                print(invitation.activation_token)
                return 0

            if args.command == "activate":
                token = getpass("One-time activation token: ")
                password = getpass("Choose a new password (15+ characters): ")
                confirmation = getpass("Confirm the new password: ")
                if password != confirmation:
                    raise ValueError("password confirmation does not match")
                account = activate_account(
                    connection, activation_token=token, new_password=password
                )
                connection.commit()
                print(
                    f"Account activated: {account['username']} "
                    f"({account['role']})."
                )
                return 0

            status = "disabled" if args.command == "disable" else "locked"
            account = change_account_status(
                connection, user_id=args.user_id, status=status
            )
            connection.commit()
            print(f"Account {account['username']} is now {account['status']}.")
            return 0
        finally:
            connection.close()
    except (
        IAMError, ValueError, LookupError, RuntimeError, OSError, sqlite3.Error
    ) as exc:
        print(f"IAM operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
