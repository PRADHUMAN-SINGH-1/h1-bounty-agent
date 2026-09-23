from __future__ import annotations

import os
from dataclasses import dataclass


def _raw(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _int(name: str, default: int) -> int:
    try:
        return int(_raw(name, str(default)))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(_raw(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool = False) -> bool:
    return _raw(name, "true" if default else "false").lower() in {"1", "true", "yes", "on"}


def _csv(name: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in _raw(name).split(",") if item.strip())


def _llm_provider() -> str:
    return _raw("LLM_PROVIDER", "huggingface").lower()


def _llm_base_url(provider: str) -> str:
    defaults = {
        "openai": "https://api.openai.com/v1",
        "huggingface": "https://router.huggingface.co/v1",
    }
    return _raw("LLM_BASE_URL", defaults.get(provider, "https://router.huggingface.co/v1"))


def _llm_model(provider: str) -> str:
    defaults = {
        "openai": "gpt-4.1-mini",
        "huggingface": "Qwen/Qwen2.5-72B-Instruct",
    }
    return _raw("LLM_MODEL", defaults.get(provider, "Qwen/Qwen2.5-72B-Instruct"))


@dataclass(frozen=True)
class Settings:
    hackerone_username: str = _raw("HACKERONE_USERNAME")
    hackerone_api_token: str = _raw("HACKERONE_API_TOKEN")
    enable_submission: bool = _bool("H1_ENABLE_SUBMISSION", False)
    auto_submit_findings: bool = _bool("H1_AUTO_SUBMIT_FINDINGS", False)
    dry_run: bool = _bool("DRY_RUN", True)
    allow_active_tests: bool = _bool("ALLOW_ACTIVE_TESTS", False)
    autonomous_research: bool = _bool("AUTONOMOUS_RESEARCH", False)
    autonomous_passive_research: bool = _bool("AUTONOMOUS_PASSIVE_RESEARCH", False)
    autonomous_max_programs: int = max(_int("AUTONOMOUS_MAX_PROGRAMS", 3), 1)
    autonomous_max_targets_per_program: int = max(_int("AUTONOMOUS_MAX_TARGETS_PER_PROGRAM", 2), 1)
    full_research_max_targets_per_program: int = max(_int("FULL_RESEARCH_MAX_TARGETS_PER_PROGRAM", 50), 1)
    deep_max_scripts: int = max(_int("DEEP_MAX_SCRIPTS", 30), 1)
    deep_max_query_links: int = max(_int("DEEP_MAX_QUERY_LINKS", 20), 1)
    deep_max_api_candidates: int = max(_int("DEEP_MAX_API_CANDIDATES", 30), 1)
    deep_max_openapi_steps: int = max(_int("DEEP_MAX_OPENAPI_STEPS", 30), 1)
    deep_max_graphql_endpoints: int = max(_int("DEEP_MAX_GRAPHQL_ENDPOINTS", 10), 1)
    deep_max_websocket_endpoints: int = max(_int("DEEP_MAX_WEBSOCKET_ENDPOINTS", 10), 1)
    deep_max_cloud_text_bytes: int = max(_int("DEEP_MAX_CLOUD_TEXT_BYTES", 4_000_000), 100_000)
    deep_max_pages: int = max(_int("DEEP_MAX_PAGES", 30), 1)
    deep_max_page_links: int = max(_int("DEEP_MAX_PAGE_LINKS", 80), 10)
    research_target_timeout_seconds: int = max(_int("RESEARCH_TARGET_TIMEOUT_SECONDS", 180), 30)
    toolchain_enabled: bool = _bool("TOOLCHAIN_ENABLED", True)
    toolchain_max_roots: int = max(_int("TOOLCHAIN_MAX_ROOTS", 10), 1)
    toolchain_max_targets: int = max(_int("TOOLCHAIN_MAX_TARGETS", 50), 1)
    toolchain_httpx_timeout_seconds: int = max(_int("TOOLCHAIN_HTTPX_TIMEOUT_SECONDS", 120), 30)
    toolchain_katana_timeout_seconds: int = max(_int("TOOLCHAIN_KATANA_TIMEOUT_SECONDS", 180), 30)
    toolchain_nuclei_timeout_seconds: int = max(_int("TOOLCHAIN_NUCLEI_TIMEOUT_SECONDS", 180), 30)
    research_program_allowlist: tuple[str, ...] = _csv("RESEARCH_PROGRAM_ALLOWLIST")
    blob_token: str = _raw("BLOB_READ_WRITE_TOKEN")
    llm_provider: str = _llm_provider()
    llm_base_url: str = _llm_base_url(llm_provider)
    llm_model: str = _llm_model(llm_provider)
    hf_token: str = _raw("HF_TOKEN")
    llm_api_key: str = _raw("LLM_API_KEY")
    requests_per_second: float = max(_float("REQUESTS_PER_SECOND", 1.0), 0.1)
    user_agent: str = _raw("RESEARCH_USER_AGENT", "H1-Bounty-Agent/0.4")
    dashboard_user: str = _raw("DASHBOARD_USER")
    dashboard_password: str = _raw("DASHBOARD_PASSWORD")
    dashboard_secret: str = _raw("DASHBOARD_SECRET")

    def require_hackerone_credentials(self) -> None:
        missing = []
        if not self.hackerone_username:
            missing.append("HACKERONE_USERNAME")
        if not self.hackerone_api_token:
            missing.append("HACKERONE_API_TOKEN")
        if missing:
            raise RuntimeError("Missing HackerOne credential(s): " + ", ".join(missing) + ". HACKERONE_USERNAME must be the HackerOne API token Identifier; HACKERONE_API_TOKEN must be the token value.")

    def require_submission_enabled(self) -> None:
        if not self.enable_submission:
            raise RuntimeError("Submission is disabled. Set H1_ENABLE_SUBMISSION=true only after human validation.")

    def require_dashboard_credentials(self) -> None:
        if not self.dashboard_user or not self.dashboard_secret:
            raise RuntimeError("Dashboard authentication is not configured.")

    def require_autonomous_research(self) -> None:
        if not self.autonomous_research:
            raise RuntimeError("Autonomous research is disabled.")
        if not self.allow_active_tests:
            raise RuntimeError("Active testing is disabled. Review program rules before enabling it.")
        if not self.research_program_allowlist:
            raise RuntimeError("RESEARCH_PROGRAM_ALLOWLIST is empty. Review and explicitly allow programs first.")
