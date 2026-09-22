from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class HackerOneAPIError(RuntimeError):
    def __init__(self, operation: str, message: str, status_code: int | None = None):
        self.operation = operation
        self.status_code = status_code
        super().__init__(message)


class HackerOneClient:
    def __init__(self, settings: Settings):
        settings.require_hackerone_credentials()

        base_url = settings.hackerone_base_url.strip().rstrip("/")
        if base_url.endswith("/v1"):
            base_url = base_url[:-3].rstrip("/")

        self.client = httpx.Client(
            base_url=base_url + "/v1",
            auth=(settings.hackerone_username, settings.hackerone_api_token),
            headers={
                "Accept": "application/json",
                "User-Agent": settings.user_agent,
            },
            timeout=30.0,
        )

    def close(self) -> None:
        self.client.close()

    def _get(self, path: str, operation: str, **params: Any) -> dict[str, Any]:
        try:
            response = self.client.get(path, params=params or None)
            if response.status_code in {401, 403}:
                raise HackerOneAPIError(
                    operation,
                    f"HackerOne authentication/authorization failed (HTTP {response.status_code}). "
                    "Verify HACKERONE_USERNAME is the API token identifier and HACKERONE_API_TOKEN is valid.",
                    response.status_code,
                )
            response.raise_for_status()
            return response.json()
        except HackerOneAPIError:
            raise
        except httpx.HTTPStatusError as exc:
            raise HackerOneAPIError(
                operation,
                f"HackerOne returned HTTP {exc.response.status_code}.",
                exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise HackerOneAPIError(
                operation,
                f"Could not reach HackerOne API: {exc.__class__.__name__}.",
            ) from exc

    def programs(self, page: int = 1, page_size: int = 25) -> dict[str, Any]:
        return self._get(
            "/hackers/programs",
            "program discovery",
            **{"page[number]": page, "page[size]": page_size},
        )

    def program(self, handle: str) -> dict[str, Any]:
        return self._get(f"/hackers/programs/{handle}", "program lookup")

    def structured_scopes(self, handle: str) -> dict[str, Any]:
        return self._get(
            f"/hackers/programs/{handle}/structured_scopes",
            "structured scope retrieval",
            **{"page[number]": 1, "page[size]": 100},
        )

    def scope_exclusions(self, handle: str) -> dict[str, Any]:
        return self._get(
            f"/hackers/programs/{handle}/scope_exclusions",
            "scope exclusion retrieval",
        )

    def weaknesses(self, handle: str) -> dict[str, Any]:
        return self._get(
            f"/hackers/programs/{handle}/weaknesses",
            "weakness retrieval",
            **{"page[number]": 1, "page[size]": 100},
        )

    def reports(self, page: int = 1, page_size: int = 100) -> dict[str, Any]:
        return self._get(
            "/hackers/me/reports",
            "report retrieval",
            **{"page[number]": page, "page[size]": page_size},
        )

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

        try:
            response = self.client.post(
                "/hackers/reports",
                json={"data": {"type": "report", "attributes": attributes}},
                headers={"Content-Type": "application/json"},
            )
            if response.status_code in {401, 403}:
                raise HackerOneAPIError(
                    "report submission",
                    f"HackerOne rejected the authenticated request (HTTP {response.status_code}).",
                    response.status_code,
                )
            response.raise_for_status()
            return response.json()
        except HackerOneAPIError:
            raise
        except httpx.HTTPStatusError as exc:
            raise HackerOneAPIError(
                "report submission",
                f"HackerOne returned HTTP {exc.response.status_code}.",
                exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise HackerOneAPIError(
                "report submission",
                f"Could not reach HackerOne API: {exc.__class__.__name__}.",
            ) from exc
