from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlparse

@dataclass(frozen=True)
class ScopeRule:
    asset: str
    kind: str = "url"
    eligible: bool = True

class ScopeGuard:
    """Fail-closed authorization gate. Unknown assets are never considered in scope."""
    def __init__(self, rules: list[ScopeRule]):
        self.rules = rules

    def is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        host = parsed.hostname.lower()
        for rule in self.rules:
            if not rule.eligible or rule.kind != "url":
                continue
            pattern = rule.asset.lower().replace("https://", "").replace("http://", "").rstrip("/")
            if fnmatch(host, pattern) or fnmatch(host, pattern.removeprefix("*.")):
                return True
        return False

    def require_allowed(self, url: str) -> None:
        if not self.is_allowed(url):
            raise PermissionError(f"Target is not explicitly authorized by the loaded program scope: {url}")
