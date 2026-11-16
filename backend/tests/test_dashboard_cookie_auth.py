from pathlib import Path


STATIC_DIR = Path(__file__).resolve().parents[1] / "app" / "static"


def test_dashboard_uses_analyst_password_login_and_cookie_sessions():
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    script = (STATIC_DIR / "app.js").read_text(encoding="utf-8")

    assert 'id="auth-username"' in html
    assert 'id="auth-password"' in html
    assert 'id="auth-token"' not in html
    assert "/api/v1/iam/login" in script
    assert "/api/v1/iam/session" in script
    assert "/api/v1/iam/logout" in script
    assert 'credentials: "same-origin"' in script


def test_dashboard_never_persists_bearer_or_csrf_credentials_in_web_storage():
    for filename in ("app.js", "response.js"):
        script = (STATIC_DIR / filename).read_text(encoding="utf-8")
        assert "sessionStorage" not in script
        assert "localStorage" not in script
        assert "Authorization" not in script

    app_script = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert '"X-Aegis-CSRF-Token": aegisCsrfToken' in app_script
    assert '"X-Aegis-CSRF-Token": aegisCsrfToken || ""' in app_script


def test_response_client_reuses_shared_cookie_and_csrf_fetch_wrapper():
    script = (STATIC_DIR / "response.js").read_text(encoding="utf-8")
    assert "return fetchJSON(url, options);" in script
