import zipfile

import httpx

from h1_agent.cloud import analyze_cloud_text
from h1_agent.graphql import discover_graphql_endpoints, introspection_probe
from h1_agent.idor import ObjectAuthorizationTester
from h1_agent.mobile import analyze_mobile_package
from h1_agent.session_mapper import AuthenticatedSessionMapper
from h1_agent.websocket import discover_websocket_urls


def test_cloud_policy_analysis():
    result, evidence = analyze_cloud_text(
        '{"Statement":[{"Action":"*","Resource":"*"}]} arn:aws:s3:::example-bucket',
        "test",
    )
    assert result["aws_arns"]
    assert "wildcard_cloud_policy" in result["policy_observations"]
    assert evidence


def test_graphql_endpoint_discovery_is_scope_gated():
    class Scope:
        pass
    scope = Scope()
    scope.asset_type = "DOMAIN"
    scope.asset_identifier = "example.com"
    scope.eligible_for_submission = True
    scope.eligible_for_bounty = True
    scope.instruction = ""
    scope.id = "1"
    scope.max_severity = None
    scope.confidentiality_requirement = None
    scope.integrity_requirement = None
    scope.availability_requirement = None
    scope.reference = None

    urls = discover_graphql_endpoints(
        ["https://example.com/graphql", "https://evil.example.net/graphql"],
        [scope],
    )
    assert urls == ["https://example.com/graphql"]


def test_graphql_introspection_is_read_only_and_parsed():
    def fake_post(url, **kwargs):
        assert "IntrospectionQuery" in kwargs["json"]["query"]
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            headers={"content-type":"application/json"},
            json={"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[{"name":"User"}]}}},
        )

    class Scope:
        asset_type = "DOMAIN"
        asset_identifier = "example.com"
        eligible_for_submission = True
        eligible_for_bounty = True
        instruction = ""
        id = "1"
        max_severity = confidentiality_requirement = integrity_requirement = availability_requirement = reference = None

    status, evidence = introspection_probe(fake_post if False else type("C", (), {"post": fake_post})(), "https://example.com/graphql", [Scope()])
    assert status == "introspection_enabled"
    assert any(item.name == "graphql_introspection" for item in evidence)


def test_websocket_discovery_only_finds_ws_urls():
    class Scope:
        asset_type = "DOMAIN"
        asset_identifier = "example.com"
        eligible_for_submission = True
        eligible_for_bounty = True
        instruction = ""
        id = "1"
        max_severity = confidentiality_requirement = integrity_requirement = availability_requirement = reference = None

    urls = discover_websocket_urls(
        'new WebSocket("wss://example.com/socket"); "https://example.com/not-ws"',
        "https://example.com/",
        [Scope()],
    )
    assert urls == ["wss://example.com/socket"]


def test_mobile_analysis_reads_apk_zip(tmp_path):
    path = tmp_path / "test.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"dex")
        archive.writestr(
            "config.xml",
            b'<config android:debuggable="true">https://api.example.com</config>',
        )
    result, evidence = analyze_mobile_package(str(path))
    assert result["format"] == "apk"
    assert result["dex_files"] == ["classes.dex"]
    assert "android:debuggable" in result["security_flags"]
    assert evidence


def test_authz_header_is_validated():
    class Client:
        def get(self, *args, **kwargs):
            return httpx.Response(403, request=httpx.Request("GET", args[0]))

    try:
        ObjectAuthorizationTester(Client(), "Authorization: a", "Authorization: b")
    except Exception:
        assert False


def test_session_mapper_rejects_missing_header():
    class Client:
        pass

    try:
        AuthenticatedSessionMapper(Client(), "not-a-header")
    except ValueError:
        return
    raise AssertionError("expected invalid header to be rejected")
