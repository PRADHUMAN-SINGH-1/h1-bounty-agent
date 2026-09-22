from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class ResearchMemoryItem:
    key: str
    value: str
    source: str
    recorded_at: str


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_memory(key: str, value: str, source: str) -> ResearchMemoryItem:
    return ResearchMemoryItem(key, value, source, now())


def merge_memory(items: list[ResearchMemoryItem], new_items: list[ResearchMemoryItem]) -> list[ResearchMemoryItem]:
    by_key = {item.key: item for item in items}
    for item in new_items:
        by_key[item.key] = item
    return sorted(by_key.values(), key=lambda item: item.recorded_at)
