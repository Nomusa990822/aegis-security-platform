from app.request_limits import MAX_REQUEST_BODY_BYTES


def test_request_body_at_limit_reaches_route(client):
    response = client.post(
        "/api/v1/health",
        content=b"x" * MAX_REQUEST_BODY_BYTES,
    )

    # The middleware permits the configured boundary; the endpoint
    # itself rejects POST because health is a GET route.
    assert response.status_code == 405


def test_request_body_over_limit_is_rejected(client):
    response = client.post(
        "/api/v1/health",
        content=b"x" * (MAX_REQUEST_BODY_BYTES + 1),
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}


def test_chunked_request_body_over_limit_is_rejected(client):
    chunk_size = 512 * 1024

    def chunks():
        yield b"x" * chunk_size
        yield b"y" * (MAX_REQUEST_BODY_BYTES - chunk_size + 1)

    response = client.post(
        "/api/v1/health",
        content=chunks(),
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}


def test_small_authenticated_event_request_still_works(client):
    response = client.post(
        "/api/v1/events",
        json={
            "event_type": "authentication",
            "source_ip": "192.0.2.80",
            "username": "body-limit-test",
            "outcome": "success",
        },
    )

    assert response.status_code == 201
