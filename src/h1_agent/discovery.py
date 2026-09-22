from __future__ import annotations

from dataclasses import dataclass

from .models import ScopeAsset


@dataclass(frozen=True)
class Opportunity:
    handle: str
    name: str
    state: str
    bounty_assets: int
    eligible_assets: int
    total_assets: int

    @property
    def score(self) -> float:
        # Triage signal only; not a prediction of bounty income.
        return self.bounty_assets * 5 + self.eligible_assets * 1.5 + (1 if self.state.lower() in {"public", "active"} else 0)


def rank(handle: str, name: str, state: str, scopes: list[ScopeAsset]) -> Opportunity:
    return Opportunity(
        handle=handle,
        name=name,
        state=state,
        bounty_assets=sum(a.eligible_for_bounty for a in scopes),
        eligible_assets=sum(a.eligible_for_submission for a in scopes),
        total_assets=len(scopes),
    )
