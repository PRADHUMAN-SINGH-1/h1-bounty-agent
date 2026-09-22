from __future__ import annotations

import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass(frozen=True)
class Settings:
    hackerone_username: str = os.getenv("HACKERONE_USERNAME", "")
    hackerone_api_token: str = os.getenv("HACKERONE_API_TOKEN", "")
    hackerone_base_url: str = os.getenv("HACKERONE_BASE_URL", "https://api.hackerone.com")
    database_path: str = os.getenv("DATABASE_PATH", "data/h1_agent.sqlite3")
    dry_run: bool = os.getenv("DRY_RUN", "true").lower() not in {"0", "false", "no"}
    llm_provider: str = os.getenv("LLM_PROVIDER", "local")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "http://localhost:11434")
    llm_model: str = os.getenv("LLM_MODEL", "")

    def require_hackerone_credentials(self) -> None:
        if not self.hackerone_username or not self.hackerone_api_token:
            raise RuntimeError("HackerOne credentials are missing. Set HACKERONE_USERNAME and HACKERONE_API_TOKEN in .env")
