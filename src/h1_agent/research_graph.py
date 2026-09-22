from __future__ import annotations

from dataclasses import dataclass

from .business_logic import BusinessLogicModel, build_workflow_model, model_evidence
from .hypotheses import generate_hypotheses, hypothesis_evidence
from .models import Evidence


@dataclass(frozen=True)
class ResearchGraph:
    business_model: BusinessLogicModel
    hypotheses: list
    evidence: list[Evidence]


def build_research_graph(requests: list[dict], seed_evidence: list[Evidence] | None = None) -> ResearchGraph:
    model = build_workflow_model(requests)
    evidence = list(seed_evidence or []) + model_evidence(model)
    hypotheses = generate_hypotheses(evidence)
    evidence.extend(hypothesis_evidence(hypotheses))
    return ResearchGraph(model, hypotheses, evidence)
