"""RFC 6238 TOTP primitives with strict input and replay-window semantics."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import time

_DIGITS = 6
_PERIOD = 30
_CODE_RE = re.compile(r"^[0-9]{6}$")


def generate_secret(*, entropy: bytes | None = None) -> str:
    """Return a 160-bit TOTP secret encoded as unpadded Base32."""
    import secrets

    raw = secrets.token_bytes(20) if entropy is None else entropy
    if not isinstance(raw, bytes) or len(raw) != 20:
        raise ValueError("TOTP entropy must contain exactly 20 bytes")
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    if not isinstance(secret, str) or not 16 <= len(secret) <= 64:
        raise ValueError("TOTP secret is invalid")
    if not re.fullmatch(r"[A-Z2-7]+", secret):
        raise ValueError("TOTP secret is invalid")
    try:
        return base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=False)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("TOTP secret is invalid") from exc


def _counter(at_time: float | int) -> int:
    if isinstance(at_time, bool) or not isinstance(at_time, (int, float)):
        raise ValueError("TOTP time must be numeric")
    if at_time < 0:
        raise ValueError("TOTP time cannot be negative")
    return int(at_time // _PERIOD)


def code_at(secret: str, *, at_time: float | int | None = None) -> str:
    """Generate the six-digit RFC 6238 code for a timestamp."""
    key = _decode_secret(secret)
    timestamp = time.time() if at_time is None else at_time
    counter = _counter(timestamp)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** _DIGITS)).zfill(_DIGITS)


def matching_step(
    secret: str, supplied_code: str, *, at_time: float | int | None = None,
    allowed_drift_steps: int = 1,
) -> int | None:
    """Return the matching time-step, or None; callers must enforce monotonicity."""
    if not isinstance(supplied_code, str) or not _CODE_RE.fullmatch(supplied_code):
        return None
    if (
        isinstance(allowed_drift_steps, bool)
        or not isinstance(allowed_drift_steps, int)
        or not 0 <= allowed_drift_steps <= 2
    ):
        raise ValueError("allowed drift must be between zero and two steps")
    timestamp = time.time() if at_time is None else at_time
    current = _counter(timestamp)
    key = _decode_secret(secret)
    for step in range(current - allowed_drift_steps, current + allowed_drift_steps + 1):
        if step < 0:
            continue
        digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        expected = str(binary % (10 ** _DIGITS)).zfill(_DIGITS)
        if hmac.compare_digest(expected, supplied_code):
            return step
    return None
