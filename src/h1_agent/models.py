from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ScopeAsset:
    id: str | None
    asset_type: str
    asset_identifier: str
    eligible_for_bounty: bool
    eligible_for_submission: bool
    instruction: str = ""
    max_severity: str | None = None
    confidentiality_requirement: str | None = None
    integrity_requirement: str | None = None
    availability_requirement: str | None = None
    reference: str | None = None


@dataclass(frozen=True)
class Evidence:
    name: str
    value: str
    source: str
    timestamp: str = field(default_factory=utc_now)


@dataclass
class Finding:
    program_handle: str
    target: str
    title: str
    severity: str | None
    state: str
    summary: str
    impact: str
    reproduction: list[str]
    evidence: list[Evidence]
    structured_scope_id: str | None = None
    weakness_id: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
