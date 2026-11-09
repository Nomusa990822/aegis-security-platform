import hashlib
import math
import threading
import time
from collections import defaultdict, deque

from starlette.responses import JSONResponse


class APIRateLimitMiddleware:
    """
    Apply bounded, process-local sliding-window limits to API traffic.

    Client addresses come only from the ASGI connection scope. Forwarded
    headers are deliberately ignored unless a trusted-proxy design is added.
    Bearer credentials are SHA-256 fingerprinted; raw tokens are never stored.
    """

    def __init__(
        self,
        app,
        window_seconds=60,
        default_limit=300,
        auth_limit=20,
        ingestion_limit=120,
        clock=time.monotonic,
    ):
        values = (window_seconds, default_limit, auth_limit, ingestion_limit)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise TypeError("Rate-limit settings must be integers")
        if window_seconds <= 0 or any(value <= 0 for value in values[1:]):
            raise ValueError("Rate-limit settings must be positive")

        self.app = app
        self.window_seconds = window_seconds
        self.default_limit = default_limit
        self.auth_limit = auth_limit
        self.ingestion_limit = ingestion_limit
        self.clock = clock
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()
        self._checks = 0

    @staticmethod
    def _client_ip(scope):
        client = scope.get("client")
        return str(client[0]) if client else "unknown"

    @staticmethod
    def _bearer_fingerprint(scope):
        for name, value in scope.get("headers", []):
            if name.lower() == b"authorization":
                try:
                    scheme, token = value.decode("latin-1").split(None, 1)
                except ValueError:
                    return None
                if scheme.lower() == "bearer" and token:
                    return hashlib.sha256(token.encode("utf-8")).hexdigest()
        return None

    def _policy(self, scope):
        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()

        if not path.startswith("/api/v1/") or path == "/api/v1/health":
            return None

        if path == "/api/v1/auth/me":
            return "auth", self.auth_limit, self._client_ip(scope)

        if path == "/api/v1/events" and method == "POST":
            fingerprint = self._bearer_fingerprint(scope)
            identity = f"token:{fingerprint}" if fingerprint else f"ip:{self._client_ip(scope)}"
            return "event-ingestion", self.ingestion_limit, identity

        return "api", self.default_limit, self._client_ip(scope)

    def _consume(self, bucket, limit, now):
        cutoff = now - self.window_seconds
        hits = self._hits[bucket]
        while hits and hits[0] <= cutoff:
            hits.popleft()

        if len(hits) >= limit:
            retry_after = max(1, math.ceil(hits[0] + self.window_seconds - now))
            remaining = 0
            reset_after = retry_after
            allowed = False
        else:
            hits.append(now)
            remaining = limit - len(hits)
            reset_after = max(1, math.ceil(hits[0] + self.window_seconds - now))
            retry_after = 0
            allowed = True

        self._checks += 1
        if self._checks % 256 == 0:
            for key in list(self._hits):
                bucket_hits = self._hits[key]
                while bucket_hits and bucket_hits[0] <= cutoff:
                    bucket_hits.popleft()
                if not bucket_hits:
                    self._hits.pop(key, None)

        return allowed, remaining, reset_after, retry_after

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        policy = self._policy(scope)
        if policy is None:
            await self.app(scope, receive, send)
            return

        category, limit, identity = policy
        bucket = (category, identity)
        with self._lock:
            allowed, remaining, reset_after, retry_after = self._consume(
                bucket,
                limit,
                self.clock(),
            )

        headers = {
            "RateLimit-Limit": str(limit),
            "RateLimit-Remaining": str(remaining),
            "RateLimit-Reset": str(reset_after),
            "RateLimit-Policy": f"{limit};w={self.window_seconds}",
        }

        if not allowed:
            headers["Retry-After"] = str(retry_after)
            await JSONResponse(
                status_code=429,
                content={"detail": "API rate limit exceeded", "category": category},
                headers=headers,
            )(scope, receive, send)
            return

        async def send_with_rate_headers(message):
            if message["type"] == "http.response.start":
                response_headers = list(message.get("headers", []))
                response_headers.extend(
                    (name.lower().encode("ascii"), value.encode("ascii"))
                    for name, value in headers.items()
                )
                message = {**message, "headers": response_headers}
            await send(message)

        await self.app(scope, receive, send_with_rate_headers)
