from h1_agent.models import ScopeAsset
from h1_agent.scope import target_is_in_scope


def test_exact_domain():
    scopes = [ScopeAsset("1", "DOMAIN", "example.com", True, True)]
    ok, asset, _ = target_is_in_scope("https://example.com/a", scopes)
    assert ok and asset is not None


def test_wildcard():
    scopes = [ScopeAsset("1", "WILDCARD", "*.example.com", True, True)]
    ok, _, _ = target_is_in_scope("https://api.example.com", scopes)
    assert ok


def test_out_of_scope():
    scopes = [ScopeAsset("1", "DOMAIN", "example.com", True, True)]
    ok, _, _ = target_is_in_scope("https://example.org", scopes)
    assert not ok


def test_url_path_scope():
    scopes = [ScopeAsset("1", "URL", "https://example.com/api", True, True)]
    assert target_is_in_scope("https://example.com/api/users", scopes)[0]
    assert not target_is_in_scope("https://example.com/admin", scopes)[0]


def test_ineligible_scope_blocked():
    scopes = [ScopeAsset("1", "DOMAIN", "example.com", True, False)]
    assert not target_is_in_scope("https://example.com", scopes)[0]
