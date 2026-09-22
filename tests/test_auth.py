from api.index import _normalize_credential, _password_matches


def test_credential_normalization():
    assert _normalize_credential("  pradhuman  ") == "pradhuman"
    assert _normalize_credential('"secret"') == "secret"
    assert _normalize_credential("secret\n") == "secret"


def test_password_accepts_configured_password():
    assert _password_matches("abc123", "abc123", "different-secret")


def test_password_accepts_dashboard_secret_fallback():
    assert _password_matches("different-secret", "wrong-password", "different-secret")


def test_password_rejects_wrong_value():
    assert not _password_matches("wrong", "abc123", "secret")
