from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SurfaceDelta:
    added: list[str]
    removed: list[str]
    changed: list[str]


def compare_surfaces(previous: list[str], current: list[str]) -> SurfaceDelta:
    previous_set = set(previous)
    current_set = set(current)
    added = sorted(current_set - previous_set)
    removed = sorted(previous_set - current_set)
    changed = sorted(
        current_set & previous_set
    )
    return SurfaceDelta(added, removed, changed)
