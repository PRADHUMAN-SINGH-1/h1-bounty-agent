from __future__ import annotations

from dataclasses import asdict

from .config import Settings
from .discovery import rank
from .hackerone import HackerOneAPIError, HackerOneClient
from .llm import LLMClient
from .research import LowImpactResearch, flatten
from .scope import normalize_scopes
from .store import Store


def _target_for_asset(asset) -> str | None:
    kind = asset.asset_type.strip().lower()
    identifier = asset.asset_identifier.strip()
    if not identifier:
        return None
    if kind in {"url", "web", "website"}:
        return identifier if identifier.startswith(("http://", "https://")) else f"https://{identifier}"
    if kind in {"domain", "wildcard"}:
        host = identifier.replace("*.", "", 1)
        host = host.split("://", 1)[-1].split("/", 1)[0]
        return f"https://{host}"
    return None


def run_cycle(settings: Settings) -> dict:
    summary = {
        "status": "ok",
        "mode": "discovery",
        "checked_programs": 0,
        "researched_targets": 0,
        "created_findings": 0,
        "skipped": [],
        "findings": [],
    }

    store = Store(settings)
    api = None

    try:
        try:
            api = HackerOneClient(settings)
            payload = api.programs(page=1, page_size=25)
        except HackerOneAPIError as exc:
            summary["status"] = "blocked"
            summary["error"] = str(exc)
            summary["error_type"] = "hackerone_api"
            return summary
        except RuntimeError as exc:
            summary["status"] = "blocked"
            summary["error"] = str(exc)
            summary["error_type"] = "configuration"
            return summary

        ranked = []

        for item in payload.get("data", []):
            attrs = item.get("attributes", {})
            handle = attrs.get("handle")
            if not handle:
                continue

            try:
                scopes_payload = api.structured_scopes(handle)
                scopes = normalize_scopes(scopes_payload)
            except Exception as exc:
                summary["skipped"].append(
                    {"program": handle, "reason": f"scope fetch failed: {exc}"}
                )
                continue

            api_program = {
                "data": {
                    "attributes": attrs,
                    "id": item.get("id"),
                    "type": item.get("type", "program"),
                }
            }
            store.save_program(api_program)
            store.save_scopes(handle, scopes_payload)
            opportunity = rank(
                handle,
                attrs.get("name", handle),
                attrs.get("state", ""),
                scopes,
            )
            ranked.append((opportunity, scopes))

        ranked.sort(key=lambda pair: (-pair[0].score, pair[0].handle))
        summary["checked_programs"] = len(ranked)

        if not settings.autonomous_research:
            summary["top_opportunities"] = [
                asdict(item[0]) | {"triage_score": item[0].score}
                for item in ranked[:10]
            ]
            return summary

        settings.require_autonomous_research()
        allowlist = set(settings.research_program_allowlist)
        llm = LLMClient(settings)

        if not llm.available():
            summary["status"] = "blocked"
            summary["error"] = "LLM provider is not configured/available."
            summary["error_type"] = "llm"
            return summary

        research_ranked = ranked[: settings.autonomous_max_programs]

        for opportunity, scopes in research_ranked:
            if opportunity.handle not in allowlist:
                continue

            targets = []
            for asset in scopes:
                if not asset.eligible_for_submission or not asset.eligible_for_bounty:
                    continue
                if asset.instruction:
                    continue
                target = _target_for_asset(asset)
                if target:
                    targets.append((asset, target))
                if len(targets) >= settings.autonomous_max_targets_per_program:
                    break

            for asset, target in targets:
                existing = store.list_findings()
                if any(
                    row.get("program_handle") == opportunity.handle
                    and row.get("target") == target
                    and row.get("state") in {"needs_review", "approved", "submitted"}
                    for row in existing
                ):
                    continue

                engine = LowImpactResearch(settings, scopes)
                try:
                    results = engine.run(target)
                except Exception as exc:
                    summary["skipped"].append(
                        {
                            "program": opportunity.handle,
                            "target": target,
                            "reason": str(exc),
                        }
                    )
                    continue
                finally:
                    engine.close()

                summary["researched_targets"] += 1
                evidence = flatten(results)
                evidence_json = [item.__dict__ for item in evidence]

                try:
                    draft = llm.draft_finding(
                        opportunity.handle,
                        target,
                        evidence_json,
                    )
                except Exception as exc:
                    summary["skipped"].append(
                        {
                            "program": opportunity.handle,
                            "target": target,
                            "reason": f"LLM analysis failed: {exc}",
                        }
                    )
                    continue

                if draft.get("status") != "candidate":
                    continue

                try:
                    confidence = float(draft.get("confidence") or 0)
                except (TypeError, ValueError):
                    confidence = 0

                if confidence < 0.70:
                    summary["skipped"].append(
                        {
                            "program": opportunity.handle,
                            "target": target,
                            "reason": f"LLM confidence below threshold: {confidence:.2f}",
                        }
                    )
                    continue

                finding_id = store.create_finding(
                    {
                        "program_handle": opportunity.handle,
                        "target": target,
                        "title": draft.get("title", ""),
                        "severity": draft.get("severity"),
                        "state": "needs_review",
                        "summary": draft.get("summary", ""),
                        "impact": draft.get("impact", ""),
                        "reproduction": draft.get("reproduction", []),
                        "evidence": evidence_json,
                        "structured_scope_id": asset.id,
                    }
                )

                summary["created_findings"] += 1
                summary["findings"].append(
                    {
                        "id": finding_id,
                        "program": opportunity.handle,
                        "target": target,
                        "title": draft.get("title", ""),
                        "severity": draft.get("severity"),
                        "confidence": confidence,
                    }
                )

        summary["mode"] = "autonomous-authorized-research"
        return summary

    except Exception as exc:
        summary["status"] = "error"
        summary["error"] = f"{exc.__class__.__name__}: {exc}"
        summary["error_type"] = "worker"
        return summary
    finally:
        if api is not None:
            api.close()
        store.close()
