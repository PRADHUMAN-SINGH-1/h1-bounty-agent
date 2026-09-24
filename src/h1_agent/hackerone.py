from __future__ import annotations

from typing import Any
import time

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

        self._min_interval = 1.0 / max(float(settings.requests_per_second), 0.1)
        self._last_request = 0.0
        self._max_retries = 4
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
        for attempt in range(self._max_retries + 1):
            elapsed = time.monotonic() - self._last_request
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            try:
                response = self.client.get(path, params=params or None)
                self._last_request = time.monotonic()
                if response.status_code == 429:
                    if attempt >= self._max_retries:
                        raise HackerOneAPIError(
                            operation,
                            "HackerOne rate limit exceeded after retries (HTTP 429).",
                            429,
                        )
                    retry_after = response.headers.get("Retry-After", "")
                    try:
                        delay = max(float(retry_after), 0.0)
                    except ValueError:
                        delay = 0.0
                    if delay <= 0:
                        delay = min(8.0, 2.0 ** attempt)
                    time.sleep(delay)
                    continue
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
                if attempt >= self._max_retries:
                    raise HackerOneAPIError(
                        operation,
                        f"Could not reach HackerOne API: {exc.__class__.__name__}.",
                    ) from exc
                time.sleep(min(8.0, 2.0 ** attempt))
        raise HackerOneAPIError(operation, "HackerOne request failed after retries.")

    def _programs_page(self, page: int, page_size: int) -> dict[str, Any]:
        return self._get(
            "/hackers/programs",
            "program discovery",
            **{"page[number]": page, "page[size]": min(max(page_size, 1), 100)},
        )

    def programs(self, page: int = 1, page_size: int = 25) -> dict[str, Any]:
        """Return the requested page; page 1 is expanded for legacy callers that expected discovery."""
        page_size = min(max(page_size, 1), 100)
        if page != 1:
            return self._programs_page(page, page_size)
        return self.programs_all(page_size=page_size, max_pages=20)

    def programs_all(self, *, page_size: int = 100, max_pages: int = 20) -> dict[str, Any]:
        """Fetch the complete accessible program catalog, not just the first page."""
        data: list[dict[str, Any]] = []
        pages = 0
        effective_size = min(max(page_size, 1), 100)
        for page in range(1, max(max_pages, 1) + 1):
            payload = self._programs_page(page, effective_size)
            batch = payload.get("data") or []
            if not isinstance(batch, list):
                raise HackerOneAPIError("program discovery", "HackerOne returned an invalid program data shape.")
            data.extend(batch)
            pages += 1
            if len(batch) < effective_size:
                break
        return {"data": data, "meta": {"pages_fetched": pages, "count": len(data)}}

    def program(self, handle: str) -> dict[str, Any]:
        return self._get(f"/hackers/programs/{handle}", "program lookup")

    def _structured_scopes_page(self, handle: str, page: int, page_size: int) -> dict[str, Any]:
        return self._get(
            f"/hackers/programs/{handle}/structured_scopes",
            "structured scope retrieval",
            **{"page[number]": page, "page[size]": min(max(page_size, 1), 100)},
        )

    def structured_scopes(self, handle: str, page: int = 1, page_size: int = 100) -> dict[str, Any]:
        """Return all scope pages for the common page-1 caller; explicit pages remain available."""
        page_size = min(max(page_size, 1), 100)
        if page != 1:
            return self._structured_scopes_page(handle, page, page_size)
        return self.structured_scopes_all(handle, page_size=page_size, max_pages=20)

    def structured_scopes_all(self, handle: str, *, page_size: int = 100, max_pages: int = 20) -> dict[str, Any]:
        """Fetch every structured scope page so large programs are not silently truncated."""
        data: list[dict[str, Any]] = []
        effective_size = min(max(page_size, 1), 100)
        for page in range(1, max(max_pages, 1) + 1):
            payload = self._structured_scopes_page(handle, page, effective_size)
            batch = payload.get("data") or []
            if not isinstance(batch, list):
                raise HackerOneAPIError("structured scope retrieval", "HackerOne returned an invalid scope data shape.")
            data.extend(batch)
            if len(batch) < effective_size:
                break
        return {"data": data, "meta": {"count": len(data)}}

    def scope_exclusions(self, handle: str) -> dict[str, Any]:
        return self._get(
            f"/hackers/programs/{handle}/scope_exclusions",
            "scope exclusion retrieval",
        )

    def _weaknesses_page(self, handle: str, page: int, page_size: int) -> dict[str, Any]:
        return self._get(
            f"/hackers/programs/{handle}/weaknesses",
            "weakness retrieval",
            **{"page[number]": page, "page[size]": min(max(page_size, 1), 100)},
        )

    def weaknesses(self, handle: str, page: int = 1, page_size: int = 100) -> dict[str, Any]:
        page_size = min(max(page_size, 1), 100)
        if page != 1:
            return self._weaknesses_page(handle, page, page_size)
        return self.weaknesses_all(handle, page_size=page_size, max_pages=20)

    def weaknesses_all(self, handle: str, *, page_size: int = 100, max_pages: int = 20) -> dict[str, Any]:
        data: list[dict[str, Any]] = []
        effective_size = min(max(page_size, 1), 100)
        for page in range(1, max(max_pages, 1) + 1):
            payload = self._weaknesses_page(handle, page, effective_size)
            batch = payload.get("data") or []
            if not isinstance(batch, list):
                raise HackerOneAPIError("weakness retrieval", "HackerOne returned an invalid weakness data shape.")
            data.extend(batch)
            if len(batch) < effective_size:
                break
        return {"data": data, "meta": {"count": len(data)}}

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
            detail = exc.response.text.strip().replace("\n", " ")[:1000]
            message = f"HackerOne returned HTTP {exc.response.status_code}."
            if detail:
                message += f" Response: {detail}"
            raise HackerOneAPIError("report submission", message, exc.response.status_code) from exc
        except httpx.RequestError as exc:
            raise HackerOneAPIError(
                "report submission",
                f"Could not reach HackerOne API: {exc.__class__.__name__}.",
            ) from exc
