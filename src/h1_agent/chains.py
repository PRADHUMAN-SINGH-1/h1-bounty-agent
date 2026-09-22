from __future__ import annotations

from dataclasses import dataclass

from .models import Evidence


@dataclass(frozen=True)
class AttackChain:
    name: str
    stages: list[str]
    confidence: str
    rationale: str


def build_candidate_chains(evidence: list[Evidence]) -> list[AttackChain]:
    names = {item.name for item in evidence}
    chains: list[AttackChain] = []

    if "authorization_differential" in names or "authz_suspicious" in names:
        if "sensitive_field_names" in names or "potential_sensitive_data_exposure" in names:
            chains.append(
                AttackChain(
                    "authorization-bypass-to-data-exposure",
                    ["authorization differential", "sensitive response"],
                    "medium",
                    "Two independent evidence classes suggest an access-control boundary may expose sensitive data; human reproduction required.",
                )
            )

    if "potential_credentialed_cors" in {e.value for e in evidence if e.name == "check_result"}:
        chains.append(
            AttackChain(
                "credentialed-cross-origin-access",
                ["credentialed CORS reflection", "authenticated data access"],
                "medium",
                "Credentialed origin reflection is a prerequisite signal; actual sensitive-data access must be reproduced.",
            )
        )

    if not chains:
        chains.append(
            AttackChain(
                "no-validated-chain",
                [],
                "low",
                "No multi-stage chain can be established from the supplied evidence.",
            )
        )
    return chains
