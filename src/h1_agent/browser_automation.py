from __future__ import annotations

from dataclasses import dataclass

from .models import Evidence
from .scope import target_is_in_scope


@dataclass(frozen=True)
class BrowserAutomationResult:
    pages: list[str]
    requests: list[dict]
    storage_origins: list[str]


class AuthorizedBrowserMapper:
    """Optional local Playwright mapper for an already-authorized browser session.

    It never submits forms or performs mutations. The caller must provide an
    in-scope start URL and may supply an existing Playwright storage-state file.
    """

    def __init__(self, scopes, max_pages: int = 20):
        self.scopes = scopes
        self.max_pages = max(1, max_pages)

    def crawl(self, start_url: str, storage_state: str | None = None) -> tuple[BrowserAutomationResult, list[Evidence]]:
        if not target_is_in_scope(start_url, self.scopes)[0]:
            raise PermissionError("Start URL is outside the reviewed structured scope.")

        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError(
                "Playwright is not installed. Install the optional browser dependency with "
                "pip install -e '.[browser]' and run playwright install chromium locally."
            ) from exc

        pages: list[str] = []
        requests: list[dict] = []
        evidence: list[Evidence] = []

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context_kwargs = {}
            if storage_state:
                context_kwargs["storage_state"] = storage_state
            context = browser.new_context(**context_kwargs)
            page = context.new_page()

            def on_request(request):
                if target_is_in_scope(request.url, self.scopes)[0]:
                    requests.append(
                        {
                            "method": request.method,
                            "url": request.url,
                            "source": "playwright",
                            "status": None,
                            "resource_type": request.resource_type,
                        }
                    )

            page.on("request", on_request)
            page.goto(start_url, wait_until="networkidle", timeout=30_000)

            queue = [page.url]
            seen = set()
            while queue and len(pages) < self.max_pages:
                current = queue.pop(0)
                if current in seen or not target_is_in_scope(current, self.scopes)[0]:
                    continue
                seen.add(current)
                page.goto(current, wait_until="networkidle", timeout=30_000)
                pages.append(page.url)
                evidence.append(Evidence("browser_page", page.url, page.url))

                for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)"):
                    if isinstance(href, str) and target_is_in_scope(href, self.scopes)[0] and href not in seen:
                        queue.append(href)

            storage = context.storage_state()
            storage_origins = sorted(
                origin.get("origin", "")
                for origin in storage.get("origins", [])
                if isinstance(origin, dict)
            )
            evidence.append(
                Evidence(
                    "browser_storage_origins",
                    ", ".join(storage_origins),
                    start_url,
                )
            )
            browser.close()

        return BrowserAutomationResult(pages, requests, storage_origins), evidence
