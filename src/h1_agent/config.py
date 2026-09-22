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


@dataclass(frozen=True)
class Settings:
    hackerone_username: str = os.getenv("HACKERONE_USERNAME", "")
    hackerone_api_token: str = os.getenv("HACKERONE_API_TOKEN", "")
    hackerone_base_url: str = os.getenv("HACKERONE_BASE_URL", "https://api.hackerone.com")
    database_path: str = os.getenv("DATABASE_PATH", "data/h1_agent.sqlite3")
    dry_run: bool = _bool("DRY_RUN", True)
    allow_active_tests: bool = _bool("ALLOW_ACTIVE_TESTS", False)
    enable_submission: bool = _bool("H1_ENABLE_SUBMISSION", False)
    llm_provider: str = os.getenv("LLM_PROVIDER", "ollama")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "http://127.0.0.1:11434")
    llm_model: str = os.getenv("LLM_MODEL", "llama3.1:8b")
    requests_per_second: float = float(os.getenv("REQUESTS_PER_SECOND", "1"))
    user_agent: str = os.getenv("RESEARCH_USER_AGENT", "H1-Bounty-Agent/0.2")

    def require_hackerone_credentials(self) -> None:
        if not self.hackerone_username or not self.hackerone_api_token:
            raise RuntimeError("Set HACKERONE_USERNAME and HACKERONE_API_TOKEN in your local .env file.")

    def require_submission_enabled(self) -> None:
        if not self.enable_submission:
            raise RuntimeError("Submission is disabled. Set H1_ENABLE_SUBMISSION=true only after human validation.")
