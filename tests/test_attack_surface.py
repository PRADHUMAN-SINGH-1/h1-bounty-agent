import httpx

from h1_agent.attack_surface import discover_from_html, discover_from_openapi, parse_openapi
from h1_agent.authorization import AuthorizationDifferentialTester, parse_header
from h1_agent.vulnerability_checks import cors_probe, reflection_probe, same_origin


def test_same_origin_respects_scheme_and_default_port():
    assert same_origin("https://example.com/a", "https://example.com/")
    assert not same_origin("http://example.com/a", "https://example.com/")


def test_reflection_probe_does_not_treat_not_reflected_as_reflected():
    def fake_get(url, **kwargs):
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            text="no marker here",
            headers={"content-type": "text/html"},
        )

    status, _ = reflection_probe(None, "https://example.com/search?q=test", fake_get)
    assert status == "no_reflection"


def test_cors_requires_credentialed_origin_reflection_for_security_candidate():
    def fake_get(url, **kwargs):
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            headers={
                "access-control-allow-origin": "https://h1-cors-canary.invalid",
                "access-control-allow-credentials": "true",
            },
        )

    status, _ = cors_probe(None, "https://example.com/", fake_get)
    assert status == "potential_credentialed_cors"


def test_attack_surface_discovers_same_origin_api():
    html = '<a href="/dashboard"></a><script src="/app.js"></script><script>fetch("/api/me")</script>'
    items = discover_from_html(html, "https://example.com/")
    urls = {item.url for item in items}
    assert "https://example.com/dashboard" in urls
    assert "https://example.com/api/me" in urls


def test_openapi_surface_extracts_get_operations():
    doc = {
        "openapi": "3.0.0",
        "paths": {
            "/api/me": {"get": {}},
            "/api/delete": {"delete": {}},
        },
    }
    items = discover_from_openapi(doc, "https://example.com/")
    assert [item.url for item in items] == ["https://example.com/api/me"]


def test_parse_openapi_rejects_non_spec_json():
    assert parse_openapi('{"hello":"world"}') is None


def test_parse_header():
    assert parse_header("Authorization: Bearer token") == ("Authorization", "Bearer token")
    assert parse_header("bad") is None


def test_authorization_differential_flags_b_denied_as_expected():
    assert AuthorizationDifferentialTester._classify(
        200, 403, "owner-data", "", "application/json", "text/html"
    )[0] is False


def test_authorization_differential_flags_reverse_access():
    suspicious, reason = AuthorizationDifferentialTester._classify(
        403, 200, "", "other-data", "text/html", "application/json"
    )
    assert suspicious is True
    assert "Account B" in reason
