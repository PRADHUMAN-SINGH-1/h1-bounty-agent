from __future__ import annotations

from dataclasses import dataclass

from .models import Evidence


@dataclass(frozen=True)
class RoleObservation:
    account: str
    endpoint: str
    status: int
    allowed: bool
    reason: str


@dataclass(frozen=True)
class RoleGraph:
    accounts: list[str]
    permissions: dict[str, list[str]]
    anomalies: list[str]


def build_role_graph(observations: list[RoleObservation]) -> RoleGraph:
    permissions: dict[str, list[str]] = {}
    anomalies = []
    for observation in observations:
        if observation.allowed:
            permissions.setdefault(observation.account, []).append(observation.endpoint)
        if "denied" in observation.reason.lower() and observation.allowed:
            anomalies.append(
                f"{observation.account} received an allowed response despite a denied expectation for {observation.endpoint}."
            )
    permissions = {key: sorted(set(value)) for key, value in permissions.items()}
    return RoleGraph(sorted(permissions), permissions, sorted(set(anomalies)))


def role_graph_evidence(graph: RoleGraph, source: str = "role-model") -> list[Evidence]:
    evidence = []
    for account, endpoints in graph.permissions.items():
        evidence.append(Evidence("role_permission_set", f"{account}: {', '.join(endpoints[:50])}", source))
    for anomaly in graph.anomalies:
        evidence.append(Evidence("role_anomaly", anomaly, source))
    return evidence
