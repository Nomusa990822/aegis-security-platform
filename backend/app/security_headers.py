"""Consistent defensive HTTP response headers for the AEGIS application."""


class SecurityHeadersMiddleware:
    """Add baseline browser security headers to every HTTP response."""

    SECURITY_HEADERS = (
        (b"x-content-type-options", b"nosniff"),
        (b"cross-origin-resource-policy", b"same-origin"),
    )

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {name.lower() for name, _ in headers}

                for name, value in self.SECURITY_HEADERS:
                    if name not in existing:
                        headers.append((name, value))

                message = {**message, "headers": headers}

            await send(message)

        await self.app(scope, receive, send_with_security_headers)
