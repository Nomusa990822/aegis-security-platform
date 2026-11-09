from starlette.responses import JSONResponse


MAX_REQUEST_BODY_BYTES = 1_048_576


class RequestBodyLimitMiddleware:
    """
    Enforce a bounded HTTP request body before application handlers run.

    Buffering is deliberately capped at max_body_bytes. This also covers
    chunked requests that do not provide a trustworthy Content-Length.
    """

    def __init__(self, app, max_body_bytes=MAX_REQUEST_BODY_BYTES):
        if isinstance(max_body_bytes, bool) or not isinstance(max_body_bytes, int):
            raise TypeError("max_body_bytes must be an integer")
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")

        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_lengths = [
            value
            for name, value in scope.get("headers", [])
            if name.lower() == b"content-length"
        ]

        if content_lengths:
            try:
                parsed_lengths = {
                    int(value.decode("ascii"))
                    for value in content_lengths
                }
            except (UnicodeDecodeError, ValueError):
                await JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length"},
                )(scope, receive, send)
                return

            if len(parsed_lengths) != 1 or next(iter(parsed_lengths)) < 0:
                await JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length"},
                )(scope, receive, send)
                return

            if next(iter(parsed_lengths)) > self.max_body_bytes:
                await JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                )(scope, receive, send)
                return

        body = bytearray()

        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                return

            if message["type"] != "http.request":
                continue

            body.extend(message.get("body", b""))

            if len(body) > self.max_body_bytes:
                await JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                )(scope, receive, send)
                return

            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_receive():
            nonlocal replayed

            if not replayed:
                replayed = True
                return {
                    "type": "http.request",
                    "body": bytes(body),
                    "more_body": False,
                }

            return await receive()

        await self.app(scope, replay_receive, send)
