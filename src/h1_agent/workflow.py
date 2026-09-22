from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urljoin

from .models import Evidence
from .scope import target_is_in_scope


@dataclass(frozen=True)
class WorkflowStep:
    url: str
    status: int | None
    content_type: str
    depth: int
    source: str


def _extract_ids(text: str) -> list[str]:
    result = []
    seen = set()
    for value in re.findall(
        r'"(?:id|uuid|user_id|account_id|object_id|resource_id)"\s*:\s*"?(%s)"?' %
        r"(?:\d{2,20}|[0-9a-f]{8}-[0-9a-f-]{27,36}|[0-9a-f]{24})",
        text[:500_000],
        flags=re.I,
    ):
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result[:20]


def _fill_template(path: str, values: list[str]) -> str | None:
    matches = re.findall(r"{([^{}]+)}", path)
    if not matches:
        return path
    if not values:
        return None
    result = path
    for index, match in enumerate(matches):
        result = result.replace("{" + match + "}", values[min(index, len(values) - 1)], 1)
    return result


def run_stateful_get_workflow(client, operations, base_url: str, scopes, max_steps: int = 20) -> tuple[list[WorkflowStep], list[Evidence]]:
    queue = [(operation.url, 0, operation.source) for operation in operations[:max_steps]]
    seen = set()
    steps = []
    evidence = []
    discovered_ids: list[str] = []

    while queue and len(steps) < max_steps:
        raw_url, depth, source = queue.pop(0)
        url = _fill_template(raw_url, discovered_ids)
        if not url:
            continue
        url = urljoin(base_url, url)
        if url in seen or not target_is_in_scope(url, scopes)[0]:
            continue
        seen.add(url)

        try:
            response = client.get(url, follow_redirects=False)
        except Exception:
            continue

        body = response.text[:500_000]
        discovered_ids.extend(x for x in _extract_ids(body) if x not in discovered_ids)
        step = WorkflowStep(
            url=url,
            status=response.status_code,
            content_type=response.headers.get("content-type", ""),
            depth=depth,
            source=source,
        )
        steps.append(step)
        evidence.extend(
            [
                Evidence("workflow_url", url, url),
                Evidence("workflow_status", str(response.status_code), url),
                Evidence("workflow_content_type", step.content_type, url),
            ]
        )

        if depth < 2:
            for operation in operations:
                candidate = _fill_template(operation.url, discovered_ids)
                if candidate and target_is_in_scope(urljoin(base_url, candidate), scopes)[0]:
                    if urljoin(base_url, candidate) not in seen:
                        queue.append((candidate, depth + 1, operation.source))

    return steps, evidence


def evidence_summary(steps: list[WorkflowStep]) -> list[Evidence]:
    return [
        Evidence(
            "workflow_step",
            json.dumps({
                "url": step.url,
                "status": step.status,
                "content_type": step.content_type,
                "depth": step.depth,
                "source": step.source,
            }),
            step.url,
        )
        for step in steps
    ]
