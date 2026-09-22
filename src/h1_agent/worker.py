from __future__ import annotations

from dataclasses import asdict
from urllib.parse import urlparse

from .config import Settings
from .discovery import rank
from .hackerone import HackerOneAPIError, HackerOneClient
from .llm import LLMClient
from .research import LowImpactResearch, flatten
from .scope import normalize_scopes
from .store import Store
from .models import Evidence
from .asset_intelligence import analyze_asset
from .toolchain import run_deep_toolchain
from .recon_diff import compare_surfaces
from .research_memory import make_memory


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


def _select_targets(scopes, max_targets: int, *, exhaustive: bool = False):
    seen: set[str] = set()
    targets = []
    ordered = sorted(
        scopes,
        key=lambda asset: (
            0 if asset.eligible_for_bounty else 1,
            0 if str(asset.asset_type).upper() == "URL" else 1,
            str(asset.asset_identifier).lower(),
        ),
    )
    for asset in ordered:
        if not asset.eligible_for_submission or not asset.eligible_for_bounty:
            continue
        if asset.instruction:
            continue
        target = _target_for_asset(asset)
        if not target or target in seen:
            continue
        seen.add(target)
        targets.append((asset, target))
        if not exhaustive and len(targets) >= max_targets:
            break
        if exhaustive and len(targets) >= max_targets:
            break
    return targets


def _select_research_assets(scopes, max_assets: int, *, exhaustive: bool = False):
    seen: set[str] = set()
    assets = []
    ordered = sorted(
        scopes,
        key=lambda asset: (
            0 if asset.eligible_for_bounty else 1,
            str(asset.asset_type).upper(),
            str(asset.asset_identifier).lower(),
        ),
    )
    for asset in ordered:
        if not asset.eligible_for_submission or not asset.eligible_for_bounty:
            continue
        if asset.instruction:
            continue
        identifier = asset.asset_identifier.strip()
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        assets.append(asset)
        if len(assets) >= max_assets:
            break
    return assets


def _select_targets(scopes, max_targets: int, *, exhaustive: bool = False):
    return [
        (asset, target)
        for asset in _select_research_assets(scopes, max_targets, exhaustive=exhaustive)
        if (target := _target_for_asset(asset))
    ]


def _research_program(
    settings: Settings,
    api: HackerOneClient,
    store: Store,
    handle: str,
    max_targets: int,
    *,
    active: bool = False,
    deep: bool = False,
    on_progress=None,
    program_context: dict | None = None,
) -> dict:
    result = {
        "program": handle,
        "targets_checked": 0,
        "created_findings": 0,
        "evidence_collected": 0,
        "checks_run": 0,
        "findings": [],
        "skipped": [],
        "asset_types": {},
        "status": "ok",
    }

    scopes_payload = api.structured_scopes(handle)
    scopes = normalize_scopes(scopes_payload)
    store.save_scopes(handle, scopes_payload)

    selected_assets = _select_research_assets(
        scopes,
        max_targets,
        exhaustive=deep and not active,
    )

    program_tool_evidence: list[Evidence] = []
    toolchain_runs = []
    if deep and settings.toolchain_enabled:
        roots = []
        for scoped_asset in selected_assets:
            candidate = _target_for_asset(scoped_asset)
            if candidate and candidate.startswith(("http://", "https://")):
                roots.append(candidate)
        if roots:
            try:
                program_tool_evidence, toolchain_runs = run_deep_toolchain(
                    roots,
                    scopes,
                    max_roots=settings.toolchain_max_roots,
                    active=active,
                )
                result["checks_run"] += len(toolchain_runs)
                result["evidence_collected"] += len(program_tool_evidence)
            except Exception as exc:
                result["skipped"].append(f"toolchain: {exc.__class__.__name__}: {exc}")
    if on_progress:
        on_progress({
            "program": handle,
            "target": None,
            "planned_targets": len(selected_assets),
            "completed_targets": 0,
        })
    if not selected_assets:
        result["status"] = "blocked"
        result["skipped"].append("No eligible structured-scope assets available for research.")
        return result

    llm = LLMClient(settings)
    llm_available = llm.available()

    for index, asset in enumerate(selected_assets, start=1):
        target = _target_for_asset(asset) or asset.asset_identifier.strip()
        result["asset_types"][asset.asset_type] = result["asset_types"].get(asset.asset_type, 0) + 1

        if on_progress:
            on_progress({
                "program": handle,
                "target": target,
                "asset_type": asset.asset_type,
                "planned_targets": len(selected_assets),
                "completed_targets": index - 1,
            })

        existing = store.list_findings()
        if any(
            row.get("program_handle") == handle
            and row.get("target") == target
            and row.get("state") in {"needs_review", "approved", "submitted"}
            for row in existing
        ):
            result["skipped"].append(f"Existing finding queue entry for {target}")
            continue

        evidence_results = []
        evidence: list[Evidence] = []

        if target.startswith(("http://", "https://")) and asset.asset_type.upper() in {"URL", "DOMAIN", "WILDCARD", "WEB", "WEBSITE"}:
            engine = LowImpactResearch(settings, scopes)
            try:
                evidence_results = engine.run(target, active=active, deep=deep)
                evidence = flatten(evidence_results)
            except Exception as exc:
                result["skipped"].append(f"{target}: {exc}")
                continue
            finally:
                engine.close()

            current_surface = sorted({
                item.source
                for item in evidence
                if item.name == "attack_surface_endpoint"
                and item.source.startswith(("http://", "https://"))
            })
            snapshot = store.save_surface_snapshot(f"{handle}:{target}", current_surface)
            delta = compare_surfaces(snapshot["previous"], snapshot["current"])
            if delta.added:
                evidence.append(
                    Evidence(
                        "surface_delta_added",
                        f"New attack-surface items since last research: {', '.join(delta.added[:50])}",
                        target,
                    )
                )
            if delta.removed:
                evidence.append(
                    Evidence(
                        "surface_delta_removed",
                        f"Removed attack-surface items since last research: {', '.join(delta.removed[:50])}",
                        target,
                    )
                )

        else:
            analysis = analyze_asset(asset, settings)
            evidence = analysis.evidence
            evidence_results = [
                type("AssetCheck", (), {
                    "name": f"asset_intelligence:{asset.asset_type.lower()}",
                    "status": analysis.status,
                    "detail": analysis.detail,
                })()
            ]
            if analysis.status in {"manual", "skipped"}:
                result["skipped"].append(f"{target}: {analysis.detail}")
                result["targets_checked"] += 1
                result["evidence_collected"] += len(evidence)
                result["checks_run"] += 1
                continue

        result["targets_checked"] += 1
        result["evidence_collected"] += len(evidence)
        result["checks_run"] += len(evidence_results)

        memory_items = [
            make_memory(
                f"{target}:research-mode",
                "active" if active else "full-read-only",
                "worker",
            ).__dict__,
            make_memory(
                f"{target}:evidence-count",
                str(len(evidence)),
                "worker",
            ).__dict__,
        ]
        store.save_memory(f"{handle}:{target}", memory_items)

        relevant_tool_evidence = []
        target_host = (urlparse(target).hostname or "").lower()
        for item in program_tool_evidence:
            item_host = (urlparse(item.source).hostname or "").lower()
            if item.name == "nuclei_match" and item_host and target_host and item_host != target_host:
                continue
            relevant_tool_evidence.append(item)
            if len(relevant_tool_evidence) >= 250:
                break
        evidence.extend(relevant_tool_evidence)
        evidence_json = [item.__dict__ for item in evidence]
        result["research_trace"] = {
            "checks": [item.name for item in evidence_results],
            "evidence_count": len(evidence_json),
            "deep": deep,
            "active": active,
            "asset_type": asset.asset_type,
        }

        if on_progress:
            on_progress({
                "program": handle,
                "target": target,
                "asset_type": asset.asset_type,
                "planned_targets": len(selected_assets),
                "completed_targets": index,
                "evidence_collected": len(evidence_json),
            })

        if not llm_available:
            result["skipped"].append(
                f"{target}: evidence collected, but no hosted LLM is configured; candidate drafting was skipped."
            )
            continue

        try:
            triage = llm.triage_evidence(
                handle,
                target,
                program_context or {},
                evidence_json,
            )
            leads = triage.get("leads") if isinstance(triage.get("leads"), list) else []
            leads = leads[:8]
        except Exception as exc:
            leads = []
            result["skipped"].append(f"{target}: evidence triage failed; continuing with direct synthesis: {exc}")

        try:
            draft = llm.draft_finding(
                handle,
                target,
                evidence_json,
                leads=leads,
                program_context=program_context or {},
            )
        except Exception as exc:
            result["skipped"].append(f"{target}: LLM analysis failed: {exc}")
            continue

        if draft.get("status") != "candidate":
            result["skipped"].append(
                f"{target}: LLM evaluation returned status={draft.get('status')!r}; no bounty candidate was created from the collected evidence."
            )
            continue

        try:
            confidence = float(draft.get("confidence") or 0)
        except (TypeError, ValueError):
            confidence = 0

        if confidence < 0.70:
            result["skipped"].append(
                f"{target}: LLM confidence below threshold ({confidence:.2f})"
            )
            continue

        metadata = {
            "asset_type": asset.asset_type,
            "asset_identifier": asset.asset_identifier,
            "scope_reference": asset.reference or "",
            "scope_max_severity": asset.max_severity or "",
            "scope_confidentiality_requirement": asset.confidentiality_requirement or "",
            "scope_integrity_requirement": asset.integrity_requirement or "",
            "scope_availability_requirement": asset.availability_requirement or "",
            "affected_component": draft.get("affected_component") or "",
            "preconditions": draft.get("preconditions") or "",
            "observed_behavior": draft.get("observed_behavior") or "",
            "expected_behavior": draft.get("expected_behavior") or "",
            "attack_scenario": draft.get("attack_scenario") or "",
            "remediation": draft.get("remediation") or "",
            "references": draft.get("references") or [],
            "weakness_name": draft.get("weakness_name") or "",
            "cvss_score": draft.get("cvss_score"),
            "cvss_vector": draft.get("cvss_vector") or "",
            "missing_validation": draft.get("missing_validation") or [],
        }
        finding_id = store.create_finding(
            {
                "program_handle": handle,
                "target": target,
                "title": draft.get("title", ""),
                "severity": draft.get("severity"),
                "state": "needs_review",
                "summary": draft.get("summary", ""),
                "impact": draft.get("impact", ""),
                "reproduction": draft.get("reproduction", []),
                "evidence": evidence_json,
                "structured_scope_id": asset.id,
                "weakness_id": draft.get("weakness_id"),
                "metadata": metadata,
            }
        )
        result["created_findings"] += 1
        result["findings"].append(
            {
                "id": finding_id,
                "program": handle,
                "target": target,
                "asset_type": asset.asset_type,
                "title": draft.get("title", ""),
                "severity": draft.get("severity"),
                "confidence": confidence,
            }
        )

    return result


def run_program_passive_research(
    settings: Settings,
    handle: str,
    max_targets: int = 2,
) -> dict:
    store = Store(settings)
    api = None
    try:
        api = HackerOneClient(settings)
        return _research_program(
            settings,
            api,
            store,
            handle,
            max(1, max_targets),
            active=False,
        )
    except HackerOneAPIError as exc:
        return {
            "program": handle,
            "status": "blocked",
            "error_type": "hackerone_api",
            "error": str(exc),
            "targets_checked": 0,
            "created_findings": 0,
            "findings": [],
            "skipped": [],
        }
    except Exception as exc:
        return {
            "program": handle,
            "status": "error",
            "error_type": "worker",
            "error": f"{exc.__class__.__name__}: {exc}",
            "targets_checked": 0,
            "created_findings": 0,
            "findings": [],
            "skipped": [],
        }
    finally:
        if api is not None:
            api.close()
        store.close()


def run_cycle(
    settings: Settings,
    requested_programs: set[str] | None = None,
    active: bool = False,
    mode: str = "",
    on_progress=None,
) -> dict:
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
        api = HackerOneClient(settings)

        # A selected-program request should not rescan the entire HackerOne catalog.
        if requested_programs:
            requested_mode = (mode or ("active" if active else "passive")).strip().lower()
            if requested_mode in {"full", "deep", "deep-research"}:
                research_mode = "selected-program-full-research"
                # Full research always runs the complete non-destructive research
                # pipeline. The legacy active flag is not required for that work.
                selected_active = False
                selected_deep = True
            elif requested_mode in {"active", "assessment"}:
                if not settings.allow_active_tests:
                    summary["status"] = "blocked"
                    summary["mode"] = "selected-program-active-assessment"
                    summary["error_type"] = "authorization_gate"
                    summary["error"] = (
                        "Active vulnerability assessment is disabled. "
                        "Set ALLOW_ACTIVE_TESTS=true only after reviewing program policy and scope."
                    )
                    return summary
                research_mode = "selected-program-active-assessment"
                selected_active = True
                selected_deep = True
            else:
                research_mode = "selected-program-passive-research"
                selected_active = False
                selected_deep = False

            summary["mode"] = research_mode
            per_program = []

            for handle in sorted(requested_programs):
                try:
                    program_payload = api.program(handle)
                    attrs = program_payload.get("data", {}).get("attributes", {})
                    if attrs.get("handle") and attrs.get("handle") != handle:
                        raise RuntimeError(
                            f"HackerOne returned handle {attrs.get('handle')} for requested {handle}."
                        )

                    store.save_program(program_payload)
                    result = _research_program(
                        settings,
                        api,
                        store,
                        handle,
                        settings.full_research_max_targets_per_program
                        if selected_deep
                        else settings.autonomous_max_targets_per_program,
                        active=selected_active,
                        deep=selected_deep,
                        on_progress=on_progress,
                        program_context={
                            "handle": handle,
                            "name": attrs.get("name") or handle,
                            "state": attrs.get("state") or "",
                            "policy": attrs.get("policy") or attrs.get("description") or "",
                            "toolchain": [
                                {"name": run.name, "status": run.status, "detail": run.detail}
                                for run in locals().get("toolchain_runs", [])
                            ],
                        },
                    )
                except HackerOneAPIError as exc:
                    result = {
                        "program": handle,
                        "status": "blocked",
                        "error_type": "hackerone_api",
                        "error": str(exc),
                        "targets_checked": 0,
                        "created_findings": 0,
                        "findings": [],
                        "skipped": [],
                    }
                except Exception as exc:
                    result = {
                        "program": handle,
                        "status": "error",
                        "error_type": "selected_program",
                        "error": f"{exc.__class__.__name__}: {exc}",
                        "targets_checked": 0,
                        "created_findings": 0,
                        "findings": [],
                        "skipped": [],
                    }

                per_program.append(result)
                summary["researched_targets"] += result.get("targets_checked", 0)
                summary["created_findings"] += result.get("created_findings", 0)
                summary["findings"].extend(result.get("findings", []))
                summary["skipped"].extend(
                    [{"program": handle, "reason": reason} for reason in result.get("skipped", [])]
                )

                if result.get("error"):
                    summary["skipped"].append(
                        {"program": handle, "reason": result["error"]}
                    )

            summary["program_results"] = per_program
            if any(r.get("status") == "error" for r in per_program):
                summary["status"] = "error"
            elif all(r.get("status") == "blocked" for r in per_program):
                summary["status"] = "blocked"
            return summary

        try:
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
            summary["next_action"] = "Set the missing HackerOne environment variable in Vercel Production, then redeploy."
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

        if settings.autonomous_passive_research:
            allowlist = set(settings.research_program_allowlist)
            summary["mode"] = "autonomous-passive-research"
            for opportunity, _scopes in ranked[: settings.autonomous_max_programs]:
                if opportunity.handle not in allowlist:
                    continue
                result = _research_program(
                    settings,
                    api,
                    store,
                    opportunity.handle,
                    settings.autonomous_max_targets_per_program,
                    active=False,
                )
                summary["researched_targets"] += result.get("targets_checked", 0)
                summary["created_findings"] += result.get("created_findings", 0)
                summary["findings"].extend(result.get("findings", []))
                summary["skipped"].extend(
                    [{"program": opportunity.handle, "reason": reason} for reason in result.get("skipped", [])]
                )
            return summary

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

        for opportunity, scopes in ranked[: settings.autonomous_max_programs]:
            if opportunity.handle not in allowlist:
                continue

            targets = _select_targets(
                scopes,
                settings.autonomous_max_targets_per_program,
            )

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
                    results = engine.run(target, active=True)
                except Exception as exc:
                    summary["skipped"].append(
                        {"program": opportunity.handle, "target": target, "reason": str(exc)}
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

        summary["mode"] = "autonomous-authorized-active-research"
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
