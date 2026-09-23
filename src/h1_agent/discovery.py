from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import ScopeAsset


@dataclass(frozen=True)
class Opportunity:
    handle: str
    name: str
    state: str
    bounty_assets: int
    eligible_assets: int
    total_assets: int
    web_assets: int = 0
    max_severity_assets: int = 0
    offers_bounties: bool = False
    open_scope: bool = False
    fast_payments: bool = False

    @property
    def score(self) -> float:
        # Triage signal only; this is not a prediction of bounty income.
        web_signal = min(self.web_assets, 20) * 1.5
        severity_signal = min(self.max_severity_assets, 20) * 1.0
        bounty_signal = self.bounty_assets * 5
        eligibility_signal = self.eligible_assets * 1.5
        program_signal = (
            (10 if self.offers_bounties else 0)
            + (2 if self.open_scope else 0)
            + (1 if self.fast_payments else 0)
            + (1 if self.state.lower() in {"public", "active"} else 0)
        )
        return bounty_signal + eligibility_signal + web_signal + severity_signal + program_signal


def rank(
    handle: str,
    name: str,
    state: str,
    scopes: list[ScopeAsset],
    program_attrs: dict[str, Any] | None = None,
) -> Opportunity:
    attrs = program_attrs or {}
    web_types = {"URL", "DOMAIN", "WILDCARD"}
    max_severity = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return Opportunity(
        handle=handle,
        name=name,
        state=state,
        bounty_assets=sum(a.eligible_for_bounty for a in scopes),
        eligible_assets=sum(a.eligible_for_submission for a in scopes),
        total_assets=len(scopes),
        web_assets=sum(
            a.eligible_for_bounty and a.eligible_for_submission and a.asset_type in web_types
            for a in scopes
        ),
        max_severity_assets=sum(
            1
            for a in scopes
            if a.eligible_for_bounty
            and a.eligible_for_submission
            and max_severity.get((a.max_severity or "").lower(), 0) >= 3
        ),
        offers_bounties=bool(attrs.get("offers_bounties", False)),
        open_scope=bool(attrs.get("open_scope", False)),
        fast_payments=bool(attrs.get("fast_payments", False)),
    )
