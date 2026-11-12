"""Argon2id password hashing and password policy for local IAM."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type

from app.iam.exceptions import InvalidPassword

MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_BYTES = 1024


def validate_password(password: str) -> None:
    """Enforce a long-passphrase policy without composition or trimming rules."""
    if not isinstance(password, str):
        raise InvalidPassword("password must be text")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise InvalidPassword(
            f"password must contain at least {MIN_PASSWORD_LENGTH} characters"
        )
    try:
        encoded = password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise InvalidPassword("password must be valid UTF-8 text") from exc
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise InvalidPassword(
            f"password must not exceed {MAX_PASSWORD_BYTES} UTF-8 bytes"
        )


class PasswordService:
    """Argon2id with an explicit, upgradeable production parameter profile."""

    def __init__(
        self, *, memory_cost: int = 19 * 1024, time_cost: int = 2,
        parallelism: int = 1, hash_len: int = 32, salt_len: int = 16,
    ) -> None:
        if min(memory_cost, time_cost, parallelism, hash_len, salt_len) < 1:
            raise ValueError("Argon2 parameters must be positive")
        self._hasher = PasswordHasher(
            time_cost=time_cost, memory_cost=memory_cost,
            parallelism=parallelism, hash_len=hash_len, salt_len=salt_len,
            type=Type.ID,
        )

    def hash_password(self, password: str) -> str:
        validate_password(password)
        encoded = self._hasher.hash(password)
        if not encoded.startswith("$argon2id$"):
            raise RuntimeError("PasswordHasher did not produce an Argon2id hash")
        return encoded

    def verify_password(self, encoded_hash: str, password: str) -> bool:
        """Return False for mismatch or malformed stored hashes."""
        if not isinstance(encoded_hash, str) or not isinstance(password, str):
            return False
        try:
            return bool(self._hasher.verify(encoded_hash, password))
        except (InvalidHashError, VerificationError, TypeError, ValueError):
            return False

    def needs_rehash(self, encoded_hash: str) -> bool:
        if not isinstance(encoded_hash, str):
            return True
        try:
            return self._hasher.check_needs_rehash(encoded_hash)
        except (InvalidHashError, TypeError, ValueError):
            return True

    def rehash_if_needed(self, encoded_hash: str, password: str) -> str | None:
        """Return an upgraded hash only after successful verification."""
        if not self.verify_password(encoded_hash, password):
            return None
        if not self.needs_rehash(encoded_hash):
            return None
        return self.hash_password(password)


DEFAULT_PASSWORD_SERVICE = PasswordService()
