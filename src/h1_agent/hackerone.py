from __future__ import annotations

from typing import Any
import httpx

from .config import Settings


class HackerOneClient:
    def __init__(self, settings: Settings):
        settings.require_hackerone_credentials()
        self.client = httpx.Client(
            base_url=settings.hackerone_base_url.rstrip("/") + "/v1",
            auth=(settings.hackerone_username, settings.hackerone_api_token),
            headers={"Accept": "application/json", "User-Agent": settings.user_agent},
            timeout=30.0,
        )

    def close(self) -> None:
        self.client.close()

    def _get(self, path: str, **params: Any) -> dict[str, Any]:
        response = self.client.get(path, params=params or None)
        response.raise_for_status()
        return response.json()

    def programs(self, page: int = 1, page_size: int = 100) -> dict[str, Any]:
        return self._get("/hackers/programs", **{"page[number]": page, "page[size]": page_size})

    def program(self, handle: str) -> dict[str, Any]:
        return self._get(f"/hackers/programs/{handle}")

    def structured_scopes(self, handle: str) -> dict[str, Any]:
        return self._get(
            f"/hackers/programs/{handle}/structured_scopes",
            **{"page[number]": 1, "page[size]": 100},
        )

    def scope_exclusions(self, handle: str) -> dict[str, Any]:
        return self._get(f"/hackers/programs/{handle}/scope_exclusions")

    def weaknesses(self, handle: str) -> dict[str, Any]:
        return self._get(
            f"/hackers/programs/{handle}/weaknesses",
            **{"page[number]": 1, "page[size]": 100},
        )

    def reports(self, page: int = 1, page_size: int = 100) -> dict[str, Any]:
        return self._get("/hackers/me/reports", **{"page[number]": page, "page[size]": page_size})

    def create_report(
        self,
        *,
        team_handle: str,
        title: str,
        vulnerability_information: str,
        impact: str,
        severity_rating: str,
        weakness_id: int | None = None,
        structured_scope_id: int | None = None,
    ) -> dict[str, Any]:
        attributes: dict[str, Any] = {
            "team_handle": team_handle,
            "title": title,
            "vulnerability_information": vulnerability_information,
            "impact": impact,
            "severity_rating": severity_rating,
        }
        if weakness_id is not None:
            attributes["weakness_id"] = weakness_id
        if structured_scope_id is not None:
            attributes["structured_scope_id"] = structured_scope_id
        response = self.client.post(
            "/hackers/reports",
            json={"data": {"type": "report", "attributes": attributes}},
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        return response.json()
