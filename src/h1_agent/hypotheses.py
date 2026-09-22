from __future__ import annotations

from dataclasses import dataclass

from .models import Evidence


@dataclass(frozen=True)
class Hypothesis:
    name: str
    class_name: str
    prerequisites: list[str]
    tests: list[str]
    confidence: str
    rationale: str


def generate_hypotheses(evidence: list[Evidence]) -> list[Hypothesis]:
    names = {item.name for item in evidence}
    hypotheses = []

    if "business_invariant" in names or "workflow_edge" in names:
        hypotheses.append(
            Hypothesis(
                "workflow-state-confusion",
                "business-logic",
                ["state-changing workflow endpoints"],
                ["compare legal and adjacent state transitions", "verify server-side state preconditions"],
                "medium",
                "The application exposes state transitions that may rely on client-visible workflow state.",
            )
        )
    if "business_object" in names:
        hypotheses.append(
            Hypothesis(
                "cross-object-authorization",
                "access-control",
                ["object identifiers", "two authorized accounts"],
                ["compare ownership boundary", "substitute a second authorized object's identifier"],
                "medium",
                "Object identifiers were observed; ownership must be verified server-side.",
            )
        )
    if "role_permission_set" in names or "authorization_differential" in names:
        hypotheses.append(
            Hypothesis(
                "role-boundary-bypass",
                "authorization",
                ["role/permission observations"],
                ["compare equivalent endpoint under lower-privileged account", "verify expected denial"],
                "medium",
                "A permission model can be inferred from differential responses.",
            )
        )
    if "potential_credentialed_cors" in names:
        hypotheses.append(
            Hypothesis(
                "cross-origin-authenticated-data",
                "cors",
                ["credentialed CORS signal"],
                ["reproduce with a controlled origin", "verify authenticated sensitive response"],
                "medium",
                "Credentialed CORS can become material only when sensitive authenticated data is actually readable.",
            )
        )
    if "graphql_introspection" in names:
        hypotheses.append(
            Hypothesis(
                "graphql-overprivileged-operation",
                "api",
                ["GraphQL schema exposure"],
                ["compare query/mutation authorization by role", "inspect object ownership controls"],
                "low",
                "Schema visibility alone is not proof; the schema can guide deeper authorized access-control checks.",
            )
        )
    if "websocket_endpoint" in names:
        hypotheses.append(
            Hypothesis(
                "websocket-authorization-boundary",
                "realtime",
                ["WebSocket endpoint"],
                ["compare authenticated roles", "verify channel/resource ownership"],
                "low",
                "Realtime channels often have a separate authorization boundary.",
            )
        )
    return hypotheses


def hypothesis_evidence(items: list[Hypothesis], source: str = "hypothesis-engine") -> list[Evidence]:
    return [
        Evidence(
            "attack_hypothesis",
            f"{item.name}: prerequisites={item.prerequisites}; tests={item.tests}; confidence={item.confidence}; {item.rationale}",
            source,
        )
        for item in items
    ]
