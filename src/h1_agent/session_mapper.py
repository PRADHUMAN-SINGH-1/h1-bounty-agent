from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .attack_surface import discover_from_html
from .models import Evidence
from .scope import target_is_in_scope


@dataclass(frozen=True)
class SessionPage:
    url: str
    status: int
    content_type: str
    depth: int
    links: int


def parse_header(value: str) -> tuple[str, str] | None:
    if not value or ":" not in value:
        return None
    name, raw = value.split(":", 1)
    name, raw = name.strip(), raw.strip()
    return (name, raw) if name and raw else None


class AuthenticatedSessionMapper:
    """Read-only authenticated mapper; it never submits forms or changes server state."""

    def __init__(self, client: httpx.Client, header: str, max_pages: int = 40, max_depth: int = 2):
        parsed = parse_header(header)
        if not parsed:
            raise ValueError("AUTHZ_HEADER_A must contain one HTTP header.")
        self.client = client
        self.header = parsed
        self.max_pages = max(1, max_pages)
        self.max_depth = max(0, max_depth)

    def crawl(self, start_url: str, scopes) -> tuple[list[SessionPage], list[Evidence]]:
        queue = deque([(start_url, 0)])
        seen = {start_url}
        pages: list[SessionPage] = []
        evidence: list[Evidence] = []

        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()
            if not target_is_in_scope(url, scopes)[0]:
                continue

            try:
                response = self.client.get(
                    url,
                    headers={self.header[0]: self.header[1]},
                    follow_redirects=False,
                )
            except httpx.HTTPError:
                continue

            content_type = response.headers.get("content-type", "")
            body = response.text[:1_000_000]
            links = discover_from_html(body, url)

            pages.append(
                SessionPage(url, response.status_code, content_type, depth, len(links))
            )
            evidence.extend(
                [
                    Evidence("authenticated_page", url, url),
                    Evidence("authenticated_status", str(response.status_code), url),
                    Evidence("authenticated_content_type", content_type, url),
                ]
            )

            if depth >= self.max_depth:
                continue

            for endpoint in links:
                if not target_is_in_scope(endpoint.url, scopes)[0]:
                    continue
                if endpoint.url not in seen:
                    seen.add(endpoint.url)
                    queue.append((endpoint.url, depth + 1))

        return pages, evidence
