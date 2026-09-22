from __future__ import annotations

from fnmatch import fnmatch
from urllib.parse import urlparse

from .models import ScopeAsset


def normalize_scopes(api_json: dict) -> list[ScopeAsset]:
    result: list[ScopeAsset] = []
    for item in api_json.get("data", []):
        attrs = item.get("attributes", {})
        result.append(
            ScopeAsset(
                id=item.get("id"),
                asset_type=str(attrs.get("asset_type", "")).upper(),
                asset_identifier=str(attrs.get("asset_identifier", "")),
                eligible_for_bounty=bool(attrs.get("eligible_for_bounty", False)),
                eligible_for_submission=bool(attrs.get("eligible_for_submission", True)),
                instruction=str(attrs.get("instruction") or ""),
            )
        )
    return result


def _host_path(identifier: str) -> tuple[str, str]:
    value = identifier.strip()
    if "://" in value:
        parsed = urlparse(value)
        return (parsed.hostname or "").lower().rstrip("."), parsed.path or "/"
    if "/" in value:
        host, _, path = value.partition("/")
        return host.lower().rstrip("."), "/" + path.lstrip("/")
    return value.lower().rstrip("."), "/"


def target_is_in_scope(target: str, scopes: list[ScopeAsset]) -> tuple[bool, ScopeAsset | None, str]:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False, None, "Target must be an HTTP(S) URL with a hostname"
    host = parsed.hostname.lower().rstrip(".")
    path = parsed.path or "/"

    for asset in scopes:
        if not asset.eligible_for_submission:
            continue
        if asset.asset_type not in {"URL", "DOMAIN", "WILDCARD"}:
            continue
        asset_host, asset_path = _host_path(asset.asset_identifier)
        if asset_host.startswith("*."):
            asset_host = asset_host[2:]
            host_match = host == asset_host or host.endswith("." + asset_host)
        else:
            host_match = host == asset_host or fnmatch(host, asset_host)
        if not host_match:
            continue
        if asset.asset_type == "URL" and asset_path not in {"", "/"}:
            prefix = asset_path.rstrip("/")
            if not (path == prefix or path.startswith(prefix + "/")):
                continue
        return True, asset, "Matched an explicit eligible structured scope"
    return False, None, "No explicit eligible structured scope matched"


def require_in_scope(target: str, scopes: list[ScopeAsset]) -> ScopeAsset:
    ok, asset, reason = target_is_in_scope(target, scopes)
    if not ok or asset is None:
        raise PermissionError(reason)
    return asset
