from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlparse

from .models import Evidence


_OBJECT_HINTS = (
    "id", "uuid", "owner", "user", "account", "tenant", "order", "invoice",
    "project", "team", "role", "permission", "status", "state", "amount",
    "quantity", "price", "coupon", "refund", "transfer", "membership",
)


@dataclass(frozen=True)
class BusinessObject:
    name: str
    identifier: str
    source: str
    owner_hint: str | None = None


@dataclass(frozen=True)
class WorkflowNode:
    key: str
    method: str
    path: str
    status: int | None
    observed_from: str


@dataclass(frozen=True)
class WorkflowEdge:
    before: str
    after: str
    relation: str


@dataclass(frozen=True)
class Invariant:
    name: str
    description: str
    evidence: str


@dataclass(frozen=True)
class BusinessLogicModel:
    objects: list[BusinessObject]
    nodes: list[WorkflowNode]
    edges: list[WorkflowEdge]
    invariants: list[Invariant]


def _tokenize_path(path: str) -> list[str]:
    return [token for token in path.strip("/").split("/") if token]


def infer_objects(urls: list[str]) -> list[BusinessObject]:
    result = []
    seen = set()
    for url in urls:
        parsed = urlparse(url)
        tokens = _tokenize_path(parsed.path)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        pairs = [(k, v) for k, v in query]
        for key, value in pairs + list(zip(tokens[:-1], tokens[1:])):
            key_l = key.lower()
            if not value:
                continue
            if any(hint in key_l for hint in _OBJECT_HINTS) or re.fullmatch(
                r"(?:\d{2,20}|[0-9a-f]{8}-[0-9a-f-]{27,36}|[0-9a-f]{24})",
                value,
                re.I,
            ):
                marker = (key_l, value, url)
                if marker in seen:
                    continue
                seen.add(marker)
                result.append(
                    BusinessObject(
                        name=key,
                        identifier=value,
                        source=url,
                        owner_hint=next(
                            (qv for qk, qv in pairs if qk.lower() in {"owner", "user_id", "account_id", "tenant_id"}),
                            None,
                        ),
                    )
                )
    return result[:200]


def build_workflow_model(requests: list[dict]) -> BusinessLogicModel:
    nodes = []
    for item in requests[:300]:
        url = item.get("url") or ""
        parsed = urlparse(url)
        key = f"{item.get('method','GET')} {parsed.path}"
        nodes.append(
            WorkflowNode(
                key=key,
                method=str(item.get("method") or "GET").upper(),
                path=parsed.path or "/",
                status=item.get("status"),
                observed_from=str(item.get("source") or "trace"),
            )
        )

    unique = []
    seen = set()
    for node in nodes:
        if node.key not in seen:
            seen.add(node.key)
            unique.append(node)

    edges = []
    for left, right in zip(unique, unique[1:]):
        relation = "observed-sequence"
        if left.method in {"POST", "PUT", "PATCH", "DELETE"}:
            relation = "state-transition"
        edges.append(WorkflowEdge(left.key, right.key, relation))

    objects = infer_objects([item.get("url", "") for item in requests if item.get("url")])

    invariants = []
    stateful_paths = [node.path for node in unique if node.method in {"POST", "PUT", "PATCH", "DELETE"}]
    if stateful_paths:
        invariants.append(
            Invariant(
                "state-transition-authorization",
                "State-changing operations should enforce the caller's role, ownership and workflow state.",
                ", ".join(stateful_paths[:20]),
            )
        )
    role_paths = [node.path for node in unique if any(word in node.path.lower() for word in ("admin", "role", "permission", "member"))]
    if role_paths:
        invariants.append(
            Invariant(
                "privilege-boundary",
                "Administrative or permission-changing operations should be restricted to the intended role.",
                ", ".join(role_paths[:20]),
            )
        )
    tenant_paths = [node.path for node in unique if any(word in node.path.lower() for word in ("tenant", "organization", "workspace", "project"))]
    if tenant_paths:
        invariants.append(
            Invariant(
                "tenant-isolation",
                "Objects must remain isolated across tenants, organizations or workspaces.",
                ", ".join(tenant_paths[:20]),
            )
        )

    return BusinessLogicModel(objects, unique, edges, invariants)


def model_evidence(model: BusinessLogicModel, source: str = "business-logic-engine") -> list[Evidence]:
    evidence = []
    for obj in model.objects[:100]:
        evidence.append(Evidence("business_object", f"{obj.name}={obj.identifier}", obj.source))
    for invariant in model.invariants:
        evidence.append(Evidence("business_invariant", f"{invariant.name}: {invariant.description}", invariant.evidence or source))
    for edge in model.edges[:100]:
        evidence.append(Evidence("workflow_edge", f"{edge.before} -> {edge.after} [{edge.relation}]", source))
    return evidence
