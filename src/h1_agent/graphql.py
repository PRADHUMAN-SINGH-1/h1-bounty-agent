from __future__ import annotations

import json
import re

from .models import Evidence
from .scope import target_is_in_scope


INTROSPECTION_QUERY = """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { name kind }
  }
}"""


def discover_graphql_endpoints(urls: list[str], scopes) -> list[str]:
    result = []
    seen = set()
    for url in urls:
        lower = url.lower()
        if "graphql" not in lower:
            continue
        if not target_is_in_scope(url, scopes)[0]:
            continue
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result[:8]


def introspection_probe(client, url: str, scopes) -> tuple[str, list[Evidence]]:
    if not target_is_in_scope(url, scopes)[0]:
        return "blocked_out_of_scope", []
    try:
        response = client.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
            follow_redirects=False,
        )
    except Exception as exc:
        return "error", [Evidence("graphql_error", str(exc), url)]

    evidence = [
        Evidence("graphql_status", str(response.status_code), url),
        Evidence("graphql_content_type", response.headers.get("content-type", ""), url),
    ]
    try:
        payload = response.json()
    except ValueError:
        return "no_json_response", evidence

    schema = (payload.get("data") or {}).get("__schema") or {}
    if schema:
        types = [item.get("name") for item in schema.get("types", []) if item.get("name")]
        query_name = (schema.get("queryType") or {}).get("name") or ""
        mutation_name = (schema.get("mutationType") or {}).get("name") or ""
        evidence.extend(
            [
                Evidence("graphql_introspection", "enabled", url),
                Evidence("graphql_query_type", query_name, url),
                Evidence("graphql_mutation_type", mutation_name, url),
                Evidence("graphql_type_count", str(len(types)), url),
            ]
        )
        return "introspection_enabled", evidence

    errors = payload.get("errors")
    if errors:
        evidence.append(Evidence("graphql_errors", json.dumps(errors)[:2000], url))
    return "introspection_not_enabled", evidence


def extract_graphql_operation_names(text: str) -> list[str]:
    return sorted(set(re.findall(r"\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)", text)))
