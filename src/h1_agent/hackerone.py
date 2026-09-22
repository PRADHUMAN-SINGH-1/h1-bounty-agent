from __future__ import annotations

import httpx

class HackerOneClient:
    def __init__(self, username: str, token: str, base_url: str = "https://api.hackerone.com"):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(auth=(username, token), headers={"Accept": "application/json", "User-Agent": "h1-bounty-agent/0.1"}, timeout=30)

    def close(self) -> None:
        self.client.close()

    def _get(self, path: str, **params):
        response = self.client.get(f"{self.base_url}{path}", params=params or None)
        response.raise_for_status()
        return response.json()

    def programs(self, page_size: int = 25):
        return self._get("/v1/hackers/programs", page_size=page_size)

    def structured_scopes(self, handle: str):
        return self._get(f"/v1/hackers/programs/{handle}/structured_scopes")
