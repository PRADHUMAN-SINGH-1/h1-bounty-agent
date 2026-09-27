#!/usr/bin/env python3
"""
Files.com BUGBOUNTY API permission-boundary probe.

Purpose:
  Test whether a Files Only user API key can invoke endpoints documented as
  requiring Site Admin privileges. This is a read-only probe.

Authorization requirements:
  - Run only against the researcher-owned [BUGBOUNTY] trial site.
  - Use a Files Only user API key created on that trial site.
  - Do not point this at customer sites.
  - Requests are paced at <= 1 request/second.
  - No pagination, file reads, mutations, or customer-data collection.

Environment:
  FILES_BASE_URL=https://<your-assigned-subdomain>.files.com
  FILES_API_KEY=<your-files-only-test-key>

Usage:
  FILES_BASE_URL=https://example.files.com FILES_API_KEY='...' \
    python3 tools/files_api_permission_probe.py

A 2xx response from an endpoint whose current docs require Site Admin
privileges is a high-signal authorization-boundary candidate and should be
stopped and reported rather than explored further.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class Target:
    name: str
    path: str
    documentation: str


TARGETS = (
    Target(
        "ai_tasks",
        "/api/rest/v1/ai_tasks.json",
        "https://developers.files.com/rest/resources/automations/ai-tasks/",
    ),
    Target(
        "partner_channels",
        "/api/rest/v1/partner_channels.json",
        "https://developers.files.com/rest/resources/user-accounts/partner-channels/",
    ),
    Target(
        "usage_snapshots",
        "/api/rest/v1/usage_snapshots.json",
        "https://developers.files.com/javascript/resources/usage/usage-snapshots/",
    ),
    Target(
        "usage_daily_snapshots",
        "/api/rest/v1/usage_daily_snapshots.json",
        "https://developers.files.com/javascript/resources/usage/usage-daily-snapshots/",
    ),
    Target(
        "sftp_host_keys",
        "/api/rest/v1/sftp_host_keys.json",
        "https://developers.files.com/cli/resources/encryption/sftp-host-keys/",
    ),
    Target(
        "site_history",
        "/api/rest/v1/history.json",
        "https://developers.files.com/javascript/resources/logging/actions/",
    ),
)


def main() -> int:
    base = os.environ.get("FILES_BASE_URL", "").strip().rstrip("/")
    key = os.environ.get("FILES_API_KEY", "").strip()

    if not base.startswith("https://"):
        print("ERROR: FILES_BASE_URL must be an HTTPS URL", file=sys.stderr)
        return 2
    if not key:
        print("ERROR: FILES_API_KEY is required", file=sys.stderr)
        return 2

    out: dict[str, Any] = {
        "target": base,
        "key_fingerprint_sha256": hashlib.sha256(key.encode()).hexdigest()[:16],
        "requests": [],
        "candidate": None,
    }

    headers = {
        "X-FilesAPI-Key": key,
        "Accept": "application/json",
        "User-Agent": "H1-Bounty-Agent/FilesCom-API-Boundary-Probe",
    }

    timeout = httpx.Timeout(15.0)
    with httpx.Client(timeout=timeout, follow_redirects=False, headers=headers) as client:
        for idx, target in enumerate(TARGETS):
            if idx:
                time.sleep(1.05)

            url = base + target.path
            try:
                response = client.get(url)
                item = {
                    "name": target.name,
                    "url": url,
                    "method": "GET",
                    "status": response.status_code,
                    "documentation": target.documentation,
                    "content_type": response.headers.get("content-type", ""),
                    "response_length": len(response.content),
                }

                # Do not store response bodies. They may contain sensitive data.
                if response.content:
                    item["response_sha256"] = hashlib.sha256(response.content).hexdigest()

                out["requests"].append(item)

                if 200 <= response.status_code < 300:
                    out["candidate"] = item
                    print(json.dumps(out, indent=2))
                    print(
                        "\nSTOP: a documented Site-Admin endpoint returned 2xx "
                        "to the Files Only key. Do not perform additional requests.",
                        file=sys.stderr,
                    )
                    return 10

            except httpx.HTTPError as exc:
                out["requests"].append(
                    {
                        "name": target.name,
                        "url": url,
                        "method": "GET",
                        "error": exc.__class__.__name__,
                        "documentation": target.documentation,
                    }
                )

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
