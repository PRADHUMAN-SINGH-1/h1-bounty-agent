from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _csv(name: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in os.getenv(name, "").split(",") if x.strip())


@dataclass(frozen=True)
class Settings:
    hackerone_username: str = os.getenv("HACKERONE_USERNAME", "")
    hackerone_api_token: str = os.getenv("HACKERONE_API_TOKEN", "")
    hackerone_base_url: str = os.getenv("HACKERONE_BASE_URL", "https://api.hackerone.com")
    database_path: str = os.getenv("DATABASE_PATH", "/tmp/h1_agent.sqlite3" if os.getenv("VERCEL") else "data/h1_agent.sqlite3")

    dry_run: bool = _bool("DRY_RUN", True)
    allow_active_tests: bool = _bool("ALLOW_ACTIVE_TESTS", False)
    enable_submission: bool = _bool("H1_ENABLE_SUBMISSION", False)

    autonomous_research: bool = _bool("AUTONOMOUS_RESEARCH", False)
    autonomous_max_programs: int = int(os.getenv("AUTONOMOUS_MAX_PROGRAMS", "3"))
    autonomous_max_targets_per_program: int = int(os.getenv("AUTONOMOUS_MAX_TARGETS_PER_PROGRAM", "2"))
    research_program_allowlist: tuple[str, ...] = _csv("RESEARCH_PROGRAM_ALLOWLIST")

    blob_token: str = os.getenv("BLOB_READ_WRITE_TOKEN", "")

    llm_provider: str = os.getenv("LLM_PROVIDER", "ollama")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "http://127.0.0.1:11434")
    llm_model: str = os.getenv("LLM_MODEL", "llama3.1:8b")
    hf_token: str = os.getenv("HF_TOKEN", "")
    llm_api_key: str = os.getenv("LLM_API_KEY", "")

    requests_per_second: float = float(os.getenv("REQUESTS_PER_SECOND", "1"))
    user_agent: str = os.getenv("RESEARCH_USER_AGENT", "H1-Bounty-Agent/0.4")

    dashboard_user: str = os.getenv("DASHBOARD_USER", "")
    dashboard_password: str = os.getenv("DASHBOARD_PASSWORD", "")
    dashboard_secret: str = os.getenv("DASHBOARD_SECRET", "")

    def require_hackerone_credentials(self) -> None:
        if not self.hackerone_username or not self.hackerone_api_token:
            raise RuntimeError("Set HACKERONE_USERNAME and HACKERONE_API_TOKEN in the deployment environment.")

    def require_submission_enabled(self) -> None:
        if not self.enable_submission:
            raise RuntimeError("Submission is disabled. Set H1_ENABLE_SUBMISSION=true only after human validation.")

    def require_dashboard_credentials(self) -> None:
        if not self.dashboard_user or not self.dashboard_password or not self.dashboard_secret:
            raise RuntimeError("Dashboard authentication is not configured.")

    def require_autonomous_research(self) -> None:
        if not self.autonomous_research:
            raise RuntimeError("Autonomous research is disabled.")
        if not self.allow_active_tests:
            raise RuntimeError("Active testing is disabled. Review program rules before enabling it.")
        if not self.research_program_allowlist:
            raise RuntimeError("RESEARCH_PROGRAM_ALLOWLIST is empty. Review and explicitly allow programs first.")
