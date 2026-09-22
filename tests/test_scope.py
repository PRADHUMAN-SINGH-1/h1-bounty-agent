import pytest
from h1_agent.scope import ScopeGuard, ScopeRule

def test_unknown_host_is_blocked():
    guard = ScopeGuard([ScopeRule("example.com")])
    assert guard.is_allowed("https://not-example.com/a") is False

def test_explicit_host_is_allowed():
    guard = ScopeGuard([ScopeRule("example.com")])
    assert guard.is_allowed("https://example.com/a") is True

def test_http_and_https_supported():
    guard = ScopeGuard([ScopeRule("example.com")])
    assert guard.is_allowed("http://example.com")
    assert guard.is_allowed("https://example.com")

def test_invalid_url_is_blocked():
    guard = ScopeGuard([ScopeRule("example.com")])
    assert guard.is_allowed("javascript:alert(1)") is False

def test_require_allowed_raises():
    guard = ScopeGuard([ScopeRule("example.com")])
    with pytest.raises(PermissionError):
        guard.require_allowed("https://outside.example.org")
