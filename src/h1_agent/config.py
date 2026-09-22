from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _raw(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def _bool(name: str, default: bool) -> bool:
    value = _raw(name, "true" if default else "false").lower()
    return value in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(_raw(name, str(default)))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(_raw(name, str(default)))
    except (TypeError, ValueError):
        return default


def _csv(name: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in _raw(name).split(",") if x.strip())


def _llm_provider() -> str:
    configured = _raw("LLM_PROVIDER", "")
    if os.getenv("VERCEL"):
        # Never let the local Ollama setting leak into a deployed Vercel worker.
        if configured in {"", "ollama"}:
            return "vercel_gateway"
    return configured or "ollama"


def _llm_base_url(provider: str) -> str:
    if provider in {"vercel_gateway", "ai_gateway"}:
        return _raw("LLM_BASE_URL", "https://ai-gateway.vercel.sh/v1")
    return _raw("LLM_BASE_URL", "http://127.0.0.1:11434")


def _llm_model(provider: str) -> str:
    if provider in {"vercel_gateway", "ai_gateway"}:
        return _raw("LLM_MODEL", "inclusionai/ling-3.0-flash-vl-free")
    return _raw("LLM_MODEL", "llama3.1:8b")


@dataclass(frozen=True)
class Settings:
    hackerone_username: str = _raw("HACKERONE_USERNAME")
    hackerone_api_token: str = _raw("HACKERONE_API_TOKEN")
    hackerone_base_url: str = _raw("HACKERONE_BASE_URL", "https://api.hackerone.com")
    database_path: str = _raw("DATABASE_PATH", "/tmp/h1-findings.json")

    dry_run: bool = _bool("DRY_RUN", True)
    allow_active_tests: bool = _bool("ALLOW_ACTIVE_TESTS", False)
    enable_submission: bool = _bool("H1_ENABLE_SUBMISSION", False)

    autonomous_research: bool = _bool("AUTONOMOUS_RESEARCH", False)
    autonomous_passive_research: bool = _bool("AUTONOMOUS_PASSIVE_RESEARCH", False)
    autonomous_max_programs: int = max(_int("AUTONOMOUS_MAX_PROGRAMS", 3), 1)
    autonomous_max_targets_per_program: int = max(
        _int("AUTONOMOUS_MAX_TARGETS_PER_PROGRAM", 2),
        1,
    )
    research_program_allowlist: tuple[str, ...] = _csv("RESEARCH_PROGRAM_ALLOWLIST")

    blob_token: str = _raw("BLOB_READ_WRITE_TOKEN")

    llm_provider: str = _raw("LLM_PROVIDER", "vercel_gateway" if os.getenv("VERCEL") else "ollama").lower()
    llm_base_url: str = _raw("LLM_BASE_URL", "https://ai-gateway.vercel.sh/v1" if os.getenv("VERCEL") else "http://127.0.0.1:11434")
    llm_model: str = _raw("LLM_MODEL", "inclusionai/ling-3.0-flash-vl-free" if os.getenv("VERCEL") else "llama3.1:8b")
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
            raise RuntimeError(
                "Missing HackerOne credential(s): " + ", ".join(missing)
                + ". HACKERONE_USERNAME must be the HackerOne API token Identifier; "
                  "HACKERONE_API_TOKEN must be the token value."
            )

    def require_submission_enabled(self) -> None:
        if not self.enable_submission:
            raise RuntimeError(
                "Submission is disabled. Set H1_ENABLE_SUBMISSION=true only after human validation."
            )

    def require_dashboard_credentials(self) -> None:
        if not self.dashboard_user or not self.dashboard_secret:
            raise RuntimeError("Dashboard authentication is not configured.")

    def require_autonomous_research(self) -> None:
        if not self.autonomous_research:
            raise RuntimeError("Autonomous research is disabled.")
        if not self.allow_active_tests:
            raise RuntimeError(
                "Active testing is disabled. Review program rules before enabling it."
            )
        if not self.research_program_allowlist:
            raise RuntimeError(
                "RESEARCH_PROGRAM_ALLOWLIST is empty. Review and explicitly allow programs first."
            )
