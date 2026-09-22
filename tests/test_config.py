from h1_agent.config import _float, _int


def test_blank_float_uses_default(monkeypatch):
    monkeypatch.setenv("REQUESTS_PER_SECOND", "")
    assert _float("REQUESTS_PER_SECOND", 1.0) == 1.0


def test_blank_int_uses_default(monkeypatch):
    monkeypatch.setenv("AUTONOMOUS_MAX_PROGRAMS", " ")
    assert _int("AUTONOMOUS_MAX_PROGRAMS", 3) == 3


def test_invalid_numeric_values_use_defaults(monkeypatch):
    monkeypatch.setenv("REQUESTS_PER_SECOND", "not-a-number")
    monkeypatch.setenv("AUTONOMOUS_MAX_PROGRAMS", "oops")
    assert _float("REQUESTS_PER_SECOND", 1.0) == 1.0
    assert _int("AUTONOMOUS_MAX_PROGRAMS", 3) == 3
