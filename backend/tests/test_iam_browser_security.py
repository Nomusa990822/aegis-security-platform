import pytest
from starlette.responses import Response

from app.iam.browser_security import (
    SESSION_COOKIE_NAME, clear_session_cookie, create_csrf_token,
    set_session_cookie, validate_request_origin, verify_csrf_token,
)

SESSION = "A" * 43
SECRET = "x" * 64


def test_session_cookie_is_secure_httponly_host_cookie():
    response = Response()
    set_session_cookie(response, SESSION, max_age=1800, secure=True)
    header = next(value.decode() for name, value in response.raw_headers if name == b"set-cookie")
    assert header.startswith(f"{SESSION_COOKIE_NAME}=")
    assert "httponly" in header.lower()
    assert "secure" in header.lower()
    assert "samesite=lax" in header.lower()
    assert "path=/" in header.lower()
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_session_cookie_refuses_insecure_configuration():
    with pytest.raises(ValueError, match="Secure"):
        set_session_cookie(Response(), SESSION, max_age=1800, secure=False)


def test_cookie_same_site_and_lifetime_are_validated():
    with pytest.raises(ValueError, match="SameSite"):
        set_session_cookie(Response(), SESSION, max_age=1800, secure=True, same_site="none")
    with pytest.raises(ValueError, match="max_age"):
        set_session_cookie(Response(), SESSION, max_age=0, secure=True)
    with pytest.raises(ValueError, match="24 hours"):
        set_session_cookie(Response(), SESSION, max_age=86401, secure=True)


def test_logout_cookie_deletion_uses_same_security_attributes():
    response = Response()
    clear_session_cookie(response, secure=True)
    header = next(value.decode() for name, value in response.raw_headers if name == b"set-cookie")
    assert f"{SESSION_COOKIE_NAME}=" in header
    assert "max-age=0" in header.lower()
    assert "httponly" in header.lower() and "secure" in header.lower()


def test_csrf_token_is_deterministic_per_session_and_secret():
    first = create_csrf_token(SESSION, secret=SECRET)
    assert first == create_csrf_token(SESSION, secret=SECRET)
    assert first != create_csrf_token("B" * 43, secret=SECRET)
    assert first != create_csrf_token(SESSION, secret=SECRET + "different")


def test_csrf_verification_fails_closed():
    token = create_csrf_token(SESSION, secret=SECRET)
    assert verify_csrf_token(SESSION, token, secret=SECRET)
    assert not verify_csrf_token(SESSION, token + "x", secret=SECRET)
    assert not verify_csrf_token(SESSION, None, secret=SECRET)
    assert not verify_csrf_token("bad", token, secret=SECRET)


@pytest.mark.parametrize("origin", [
    None, "", "null", "http://console.example.com",
    "https://console.example.com.attacker.test",
    "https://console.example.com/path",
    "https://user@console.example.com",
])
def test_origin_validation_rejects_untrusted_or_malformed_origins(origin):
    assert not validate_request_origin(
        origin, allowed_origins={"https://console.example.com"}
    )


def test_origin_validation_requires_exact_https_origin():
    assert validate_request_origin(
        "https://console.example.com",
        allowed_origins={"https://console.example.com/"},
    )
    assert not validate_request_origin(
        "https://console.example.com:444",
        allowed_origins={"https://console.example.com"},
    )
