from __future__ import annotations

from dataclasses import asdict
from typing import Callable

from .config import Settings
from .discovery import rank
from .hackerone import HackerOneAPIError, HackerOneClient
from .scope import normalize_scopes
from .store import Store
from .worker import _research_program


ProgressCallback = Callable[[dict], None]


def run_autonomous_hunt(settings: Settings, on_progress: ProgressCallback | None = None) -> dict:
    """Discover paid public programs, rank real bounty scope, then run deep read-only research.

    This is intentionally separate from the legacy allowlist-gated active-research path.
    It never enables state-changing or active tests. Every target remains gated by the
    program's eligible structured scope, and findings stay in the human-review queue.
    """
    store = Store(settings)
    api = None
    summary = {
        "status": "ok",
        "mode": "autonomous-bounty-hunt",
        "discovered_programs": 0,
        "eligible_programs": 0,
        "selected_programs": 0,
        "researched_targets": 0,
        "created_findings": 0,
        "findings": [],
        "skipped": [],
        "program_results": [],
        "top_opportunities": [],
    }

    try:
        api = HackerOneClient(settings)
        catalog = api.programs_all(page_size=100, max_pages=20)
        programs = catalog.get("data") or []
        summary["discovered_programs"] = len(programs)

        ranked = []
        for index, item in enumerate(programs, start=1):
            attrs = item.get("attributes") or {}
            handle = str(attrs.get("handle") or "").strip()
            if not handle:
                continue
            state = str(attrs.get("state") or "").lower()
            if state not in {"public", "active"}:
                continue

            try:
                scopes_payload = api.structured_scopes_all(handle, page_size=100, max_pages=20)
                scopes = normalize_scopes(scopes_payload)
            except HackerOneAPIError as exc:
                summary["skipped"].append({"program": handle, "reason": str(exc)})
                continue
            except Exception as exc:
                summary["skipped"].append({"program": handle, "reason": f"scope discovery: {exc}"})
                continue

            store.save_program({
                "data": {
                    "id": item.get("id"),
                    "type": item.get("type", "program"),
                    "attributes": attrs,
                }
            })
            store.save_scopes(handle, scopes_payload)

            opportunity = rank(
                handle,
                str(attrs.get("name") or handle),
                state,
                scopes,
                attrs,
            )
            if opportunity.bounty_assets <= 0 or opportunity.eligible_assets <= 0:
                continue
            summary["eligible_programs"] += 1
            ranked.append((opportunity, scopes, attrs))

            if on_progress:
                on_progress({
                    "phase": "program_discovery",
                    "program": handle,
                    "completed_programs": index,
                    "planned_programs": len(programs),
                })

        ranked.sort(key=lambda row: (-row[0].score, row[0].handle))
        selected = ranked[: max(settings.autonomous_max_programs, 1)]
        summary["selected_programs"] = len(selected)
        summary["top_opportunities"] = [
            asdict(opportunity) | {"triage_score": opportunity.score}
            for opportunity, _scopes, _attrs in selected
        ]

        for index, (opportunity, scopes, attrs) in enumerate(selected, start=1):
            handle = opportunity.handle
            try:
                program_payload = api.program(handle)
                program_attrs = program_payload.get("data", {}).get("attributes", {}) or attrs
            except Exception:
                program_attrs = attrs

            try:
                exclusions = api.scope_exclusions(handle)
            except Exception as exc:
                exclusions = {"error": str(exc)}
            try:
                weaknesses = api.weaknesses_all(handle, page_size=100, max_pages=20)
            except Exception as exc:
                weaknesses = {"error": str(exc)}

            if on_progress:
                on_progress({
                    "phase": "research",
                    "program": handle,
                    "completed_programs": index - 1,
                    "planned_programs": len(selected),
                    "planned_targets": min(
                        len([a for a in scopes if a.eligible_for_bounty and a.eligible_for_submission]),
                        settings.full_research_max_targets_per_program,
                    ),
                    "completed_targets": 0,
                })

            result = _research_program(
                settings,
                api,
                store,
                handle,
                settings.full_research_max_targets_per_program,
                active=False,
                deep=True,
                on_progress=on_progress,
                program_context={
                    "handle": handle,
                    "name": program_attrs.get("name") or handle,
                    "state": program_attrs.get("state") or opportunity.state,
                    "offers_bounties": bool(program_attrs.get("offers_bounties", opportunity.offers_bounties)),
                    "open_scope": bool(program_attrs.get("open_scope", opportunity.open_scope)),
                    "fast_payments": bool(program_attrs.get("fast_payments", opportunity.fast_payments)),
                    "policy": program_attrs.get("policy") or program_attrs.get("description") or "",
                    "scope_exclusions": exclusions,
                    "weaknesses": weaknesses,
                    "toolchain_enabled": settings.toolchain_enabled,
                    "toolchain_max_roots": settings.toolchain_max_roots,
                },
            )
            summary["program_results"].append(result)
            summary["researched_targets"] += result.get("targets_checked", 0)
            summary["created_findings"] += result.get("created_findings", 0)
            summary["findings"].extend(result.get("findings", []))
            summary["skipped"].extend(
                {"program": handle, "reason": reason}
                for reason in result.get("skipped", [])
            )

        if any(result.get("status") == "error" for result in summary["program_results"]):
            summary["status"] = "partial"
        elif summary["created_findings"] == 0:
            summary["status"] = "completed_no_candidate"
            summary["message"] = (
                "Research completed without an evidence-grounded bounty candidate. "
                "This is a valid result; no vulnerability is fabricated from scanner noise."
            )
        return summary
    except HackerOneAPIError as exc:
        summary["status"] = "blocked"
        summary["error_type"] = "hackerone_api"
        summary["error"] = str(exc)
        return summary
    except Exception as exc:
        summary["status"] = "error"
        summary["error_type"] = "hunt"
        summary["error"] = f"{exc.__class__.__name__}: {exc}"
        return summary
    finally:
        if api is not None:
            api.close()
        store.close()
