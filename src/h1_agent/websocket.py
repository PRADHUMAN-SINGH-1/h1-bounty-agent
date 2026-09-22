from __future__ import annotations

import base64
import os
from urllib.parse import urlparse

from .models import Evidence
from .scope import target_is_in_scope


def discover_websocket_urls(text: str, base_url: str, scopes) -> list[str]:
    found = set()
    for match in __import__("re").finditer(r"""(?:wss?|https?)://[^"'\\s<>]+""", text, flags=__import__("re").I):
        url = match.group(0)
        if url.startswith("http://") or url.startswith("https://"):
            parsed = urlparse(url)
            url = ("wss://" if parsed.scheme == "https" else "ws://") + parsed.netloc + parsed.path
        if target_is_in_scope(url.replace("ws://", "https://").replace("wss://", "https://"), scopes)[0]:
            found.add(url)
    return sorted(found)[:8]


def websocket_handshake_probe(client, url: str, scopes) -> tuple[str, list[Evidence]]:
    scope_url = url.replace("ws://", "http://").replace("wss://", "https://")
    if not target_is_in_scope(scope_url, scopes)[0]:
        return "blocked_out_of_scope", []

    key = base64.b64encode(os.urandom(16)).decode()
    try:
        response = client.get(
            scope_url,
            headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": key,
            },
            follow_redirects=False,
        )
    except Exception as exc:
        return "error", [Evidence("websocket_error", str(exc), scope_url)]

    evidence = [
        Evidence("websocket_status", str(response.status_code), scope_url),
        Evidence("websocket_upgrade", response.headers.get("upgrade", ""), scope_url),
        Evidence("websocket_connection", response.headers.get("connection", ""), scope_url),
    ]
    if response.status_code == 101:
        return "websocket_endpoint", evidence
    return "no_websocket_upgrade", evidence
