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


def test_vercel_overrides_ollama_settings(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:11434")
    monkeypatch.setenv("LLM_MODEL", "llama3.1:8b")
    from h1_agent.config import Settings
    settings = Settings()
    assert settings.llm_provider == "vercel_gateway"
    assert settings.llm_base_url == "https://ai-gateway.vercel.sh/v1"
    assert settings.llm_model == "inclusionai/ling-3.0-flash-vl-free"
