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
from .models import Evidence, Finding
from .asset_intelligence import analyze_asset
from .toolchain import run_deep_toolchain
from .pattern_library import relevant_patterns
from .reporting import markdown_report
from .scope import target_is_in_scope
from .validation import validate_finding
from .recon_diff import compare_surfaces
from .research_memory import make_memory


def _coerce_optional_int(value) -> int | None:
    if value is None or isinstance(value, bool): return None
    if isinstance(value, int): return value
    if isinstance(value, str):
        candidate=value.strip()
        if candidate and (candidate.isdigit() or (candidate.startswith("-") and candidate[1:].isdigit())): return int(candidate)
    return None


def _target_for_asset(asset) -> str | None:
    kind=asset.asset_type.strip().lower(); identifier=asset.asset_identifier.strip()
    if not identifier: return None
    if kind in {"url","web","website"}: return identifier if identifier.startswith(("http://","https://")) else f"https://{identifier}"
    if kind in {"domain","wildcard"}:
        host=identifier.replace("*.","",1); host=host.split("://",1)[-1].split("/",1)[0]; return f"https://{host}"
    return None


def _select_research_assets(scopes,max_assets:int,*,exhaustive:bool=False):
    seen=set(); assets=[]
    for asset in sorted(scopes,key=lambda a:(0 if a.eligible_for_bounty else 1,str(a.asset_type).upper(),str(a.asset_identifier).lower())):
        if not asset.eligible_for_submission or not asset.eligible_for_bounty or asset.instruction: continue
        identifier=asset.asset_identifier.strip()
        if not identifier or identifier in seen: continue
        seen.add(identifier); assets.append(asset)
        if len(assets)>=max_assets: break
    return assets


def _select_targets(scopes,max_targets:int,*,exhaustive:bool=False):
    return [(asset,target) for asset in _select_research_assets(scopes,max_targets,exhaustive=exhaustive) if (target:=_target_for_asset(asset))]


def _maybe_auto_submit(settings,api,store,finding_id,handle,target,title,severity,confidence,summary,impact,reproduction,evidence_json,asset,scopes,metadata):
    if not settings.auto_submit_findings: return None
    if not settings.enable_submission or not settings.hackerone_api_token: return {"status":"blocked","reason":"automatic submission gate is not fully enabled"}
    if settings.dry_run: return {"status":"blocked","reason":"DRY_RUN is enabled"}
    if severity not in {"high", "critical"}: return {"status":"blocked","reason":"automatic submission requires high/critical severity"}
    if confidence < 0.90: return {"status":"blocked","reason":f"confidence {confidence:.2f} is below the 0.90 automatic-submission threshold"}
    if not reproduction or len(evidence_json)<10: return {"status":"blocked","reason":"insufficient reproduction/evidence"}
    if metadata.get("missing_validation"): return {"status":"blocked","reason":"finding still requires validation"}
    ok,scoped_asset,reason=target_is_in_scope(target,scopes)
    if not ok or scoped_asset is None or not scoped_asset.eligible_for_submission: return {"status":"blocked","reason":f"scope validation failed: {reason}"}
    finding=Finding(program_handle=handle,target=target,title=title,severity=severity,state="approved",summary=summary,impact=impact,reproduction=reproduction,evidence=[Evidence(**item) for item in evidence_json],structured_scope_id=asset.id,weakness_id=metadata.get("weakness_id"),metadata=metadata)
    validation=validate_finding(finding)
    if not validation.ok: return {"status":"blocked","reason":"; ".join(validation.blockers)}
    payload=api.create_report(team_handle=handle,title=title,vulnerability_information=markdown_report(finding),impact=impact,severity_rating=severity,weakness_id=metadata.get("weakness_id"),structured_scope_id=int(asset.id) if str(asset.id).isdigit() else None)
    store.mark_submitted(finding_id,payload); return {"status":"submitted","report_id":str(payload.get("data",{}).get("id") or "")}


def _research_program(settings,api,store,handle,max_targets,*,active=False,deep=False,on_progress=None,program_context=None):
    result={"program":handle,"targets_checked":0,"created_findings":0,"evidence_collected":0,"checks_run":0,"findings":[],"skipped":[],"asset_types":{},"status":"ok"}
    if on_progress: on_progress({"program":handle,"phase":"loading_scope","target":None,"planned_targets":0,"completed_targets":0})
    scopes_payload=api.structured_scopes(handle); scopes=normalize_scopes(scopes_payload); store.save_scopes(handle,scopes_payload)
    selected_assets=_select_research_assets(scopes,max_targets,exhaustive=deep and not active)
    if on_progress: on_progress({"program":handle,"phase":"scope_ready","target":None,"planned_targets":len(selected_assets),"completed_targets":0})
    program_tool_evidence=[]
    if deep and settings.toolchain_enabled:
        roots=[candidate for asset in selected_assets if (candidate:=_target_for_asset(asset)) and candidate.startswith(("http://","https://"))]
        if roots:
            try:
                if on_progress: on_progress({"program":handle,"phase":"finding_evidence","detail":f"Running bounded discovery toolchain across {len(roots)} scoped roots","target":None,"planned_targets":len(selected_assets),"completed_targets":0})
                program_tool_evidence,_=run_deep_toolchain(roots,scopes,max_roots=settings.toolchain_max_roots,max_targets=settings.toolchain_max_targets,httpx_timeout=settings.toolchain_httpx_timeout_seconds,katana_timeout=settings.toolchain_katana_timeout_seconds,nuclei_timeout=settings.toolchain_nuclei_timeout_seconds,active=active)
            except Exception as exc: result["skipped"].append(f"toolchain: {exc.__class__.__name__}: {exc}")
    if not selected_assets:
        result["status"]="blocked"; result["skipped"].append("No eligible structured-scope assets available for research."); return result
    llm=LLMClient(settings); llm_available=llm.available()
    for index,asset in enumerate(selected_assets,1):
        target=_target_for_asset(asset) or asset.asset_identifier.strip(); result["asset_types"][asset.asset_type]=result["asset_types"].get(asset.asset_type,0)+1
        if on_progress:
            on_progress({
                "program": handle,
                "target": target,
                "phase": "finding_evidence",
                "asset_type": asset.asset_type,
                "planned_targets": len(selected_assets),
                "completed_targets": index - 1,
            })
        existing=store.list_findings()
        if any(row.get("program_handle")==handle and row.get("target")==target and row.get("state") in {"needs_review","approved","submitted"} for row in existing): result["skipped"].append(f"Existing finding queue entry for {target}"); continue
        evidence=[]
        if target.startswith(("http://","https://")) and asset.asset_type.upper() in {"URL","DOMAIN","WILDCARD","WEB","WEBSITE"}:
            engine=LowImpactResearch(settings,scopes)
            try: evidence=flatten(engine.run(target,active=active,deep=deep))
            except Exception as exc: result["skipped"].append(f"{target}: {exc}"); continue
            finally: engine.close()
            current_surface=sorted({item.source for item in evidence if item.name=="attack_surface_endpoint" and item.source.startswith(("http://","https://"))}); snapshot=store.save_surface_snapshot(f"{handle}:{target}",current_surface); delta=compare_surfaces(snapshot["previous"],snapshot["current"])
            if delta.added: evidence.append(Evidence("surface_delta_added",f"New attack-surface items since last research: {', '.join(delta.added[:50])}",target))
        else:
            analysis = analyze_asset(asset, settings)
            evidence = analysis.evidence
            result["research_trace"] = result.get("research_trace", [])
            result["research_trace"].append({
                "target": target,
                "asset_intelligence": f"asset_intelligence:{asset.asset_type.lower()}",
                "status": analysis.status,
                "detail": analysis.detail,
                "evidence_count": len(evidence),
            })
            if analysis.status in {"manual","skipped"}: result["skipped"].append(f"{target}: {analysis.detail}"); result["targets_checked"]+=1; continue
        result["targets_checked"] += 1
        result["evidence_collected"] += len(evidence)
        result["research_trace"] = result.get("research_trace", [])
        result["research_trace"].append({
            "target": target,
            "asset_type": asset.asset_type,
            "checks_run": len(evidence),
            "evidence_collected": len(evidence),
            "deep": deep,
            "active": active,
        })
        relevant=[item for item in program_tool_evidence if not (item.name=="nuclei_match" and (urlparse(item.source).hostname or "").lower()!=(urlparse(target).hostname or "").lower())][:250]; evidence.extend(relevant); evidence_json=[item.__dict__ for item in evidence]
        if on_progress: on_progress({"program":handle,"target":target,"phase":"triaging_evidence","detail":f"Evaluating {len(evidence_json)} evidence items","planned_targets":len(selected_assets),"completed_targets":index,"evidence_collected":len(evidence_json)})
        if not llm_available: result["skipped"].append(f"{target}: no hosted LLM configured"); continue
        matched_patterns=relevant_patterns(evidence,limit=12)
        if on_progress:
            on_progress({"program": handle, "target": target, "phase": "triaging_evidence", "detail": f"Evaluating {len(evidence_json)} evidence items", "planned_targets": len(selected_assets), "completed_targets": index, "evidence_collected": len(evidence_json)})
        try:
            triage=llm.triage_evidence(handle,target,{**(program_context or {}),"matched_patterns":[{"name":p.name,"classes":p.classes,"prerequisites":p.prerequisites,"strong_signals":p.strong_signals,"false_positive_traps":p.false_positive_traps,"impact":p.impact} for p in matched_patterns]},evidence_json); leads=triage.get("leads") if isinstance(triage.get("leads"),list) else []; leads=leads[:8]
        except Exception as exc: leads=[]; result["skipped"].append(f"{target}: evidence triage failed: {exc}")
        if on_progress: on_progress({"program":handle,"target":target,"phase":"drafting_report","detail":"Building an evidence-grounded candidate report","planned_targets":len(selected_assets),"completed_targets":index,"evidence_collected":len(evidence_json)})
        if on_progress:
            on_progress({"program": handle, "target": target, "phase": "drafting_report", "detail": "Building an evidence-grounded candidate report", "planned_targets": len(selected_assets), "completed_targets": index, "evidence_collected": len(evidence_json)})
        try: draft=llm.draft_finding(handle,target,evidence_json,leads=leads,program_context=program_context or {})
        except Exception as exc: result["skipped"].append(f"{target}: LLM analysis failed: {exc}"); continue
        if draft.get("status") != "candidate":
            result["skipped"].append(f"{target}: LLM evaluation returned status={draft.get('status')!r}; no bounty candidate was created from the collected evidence.")
            continue
        try: confidence=float(draft.get("confidence") or 0)
        except (TypeError,ValueError): confidence=0
        if confidence<0.70: continue
        weakness_id = _coerce_optional_int(draft.get("weakness_id"))
        metadata = {
            "asset_type": asset.asset_type,
            "asset_identifier": asset.asset_identifier,
            "scope_reference": asset.reference or "",
            "scope_max_severity": asset.max_severity or "",
            "affected_component": draft.get("affected_component") or "",
            "preconditions": draft.get("preconditions") or "",
            "observed_behavior": draft.get("observed_behavior") or "",
            "expected_behavior": draft.get("expected_behavior") or "",
            "attack_scenario": draft.get("attack_scenario") or "",
            "remediation": draft.get("remediation") or "",
            "references": draft.get("references") or [],
            "weakness_name": draft.get("weakness_name") or "",
            "weakness_id": weakness_id,
            "cvss_score": draft.get("cvss_score"),
            "cvss_vector": draft.get("cvss_vector") or "",
            "missing_validation": draft.get("missing_validation") or [],
        }
        finding_id=store.create_finding({"program_handle":handle,"target":target,"title":draft.get("title",""),"severity":draft.get("severity"),"state":"needs_review","summary":draft.get("summary",""),"impact":draft.get("impact",""),"reproduction":draft.get("reproduction",[]),"evidence":evidence_json,"structured_scope_id":asset.id,"weakness_id":weakness_id,"metadata":metadata}); result["created_findings"]+=1; result["findings"].append({"id":finding_id,"program":handle,"target":target,"title":draft.get("title",""),"severity":draft.get("severity"),"confidence":confidence})
        if settings.auto_submit_findings:
            try: result["findings"][-1]["auto_submission"]=_maybe_auto_submit(settings,api,store,finding_id,handle,target,draft.get("title",""),draft.get("severity"),confidence,draft.get("summary",""),draft.get("impact",""),draft.get("reproduction",[]),evidence_json,asset,scopes,metadata)
            except Exception as exc: result["skipped"].append(f"{target}: automatic submission blocked: {exc}")
    return result


def run_cycle(settings: Settings, requested_programs: set[str] | None = None, active: bool = False, mode: str = "", on_progress=None):
    summary={"status":"ok","mode":"discovery","checked_programs":0,"researched_targets":0,"created_findings":0,"skipped":[],"findings":[]}; store=Store(settings); api=None
    try:
        api=HackerOneClient(settings)
        if requested_programs:
            requested_mode=(mode or ("active" if active else "passive")).strip().lower(); selected_deep = requested_mode in {"full","deep","deep-research"};
            if selected_deep:
                selected_deep = True; selected_active=requested_mode in {"active","assessment"}
            if selected_active and not settings.allow_active_tests: return {**summary,"status":"blocked","error_type":"authorization_gate","error":"Active vulnerability assessment is disabled."}
            summary["mode"]="selected-program-full-research" if selected_deep else "selected-program-passive-research"; per_program=[]
            for handle in sorted(requested_programs):
                try:
                    program_payload=api.program(handle); attrs=program_payload.get("data",{}).get("attributes",{}); store.save_program(program_payload)
                    result=_research_program(settings,api,store,handle,settings.full_research_max_targets_per_program if selected_deep else settings.autonomous_max_targets_per_program,active=selected_active,deep=selected_deep,on_progress=on_progress,program_context={"handle":handle,"name":attrs.get("name") or handle,"state":attrs.get("state") or "","policy":attrs.get("policy") or attrs.get("description") or ""})
                except Exception as exc: result={"program":handle,"status":"error","error":f"{exc.__class__.__name__}: {exc}","targets_checked":0,"created_findings":0,"findings":[],"skipped":[]}
                per_program.append(result); summary["researched_targets"]+=result.get("targets_checked",0); summary["created_findings"]+=result.get("created_findings",0); summary["findings"].extend(result.get("findings",[])); summary["skipped"].extend([{"program":handle,"reason":x} for x in result.get("skipped",[])])
            summary["program_results"]=per_program; return summary
        payload={"data":[]}
        max_pages=12
        for catalog_page in range(1,max_pages+1):
            page_payload=api._programs_page(page=catalog_page,page_size=100); page_data=page_payload.get("data",[]); payload["data"].extend(page_data)
            if on_progress: on_progress({"phase":"discovering_programs","detail":f"Scanned HackerOne program page {catalog_page}/{max_pages}","programs_seen":len(payload["data"]),"planned_targets":0,"completed_targets":0})
            if len(page_data)<100: break
        ranked=[]
        metadata_candidates=[]
        for item in payload.get("data",[]):
            attrs=item.get("attributes",{}); handle=attrs.get("handle")
            if not handle or not attrs.get("offers_bounties",False):
                continue
            state=str(attrs.get("state") or "").lower()
            cheap_score=(2 if state in {"public","active"} else 0)+(2 if attrs.get("open_scope",False) else 0)+(2 if attrs.get("fast_payments",False) else 0)
            metadata_candidates.append((-cheap_score,handle,item))
        metadata_candidates.sort(key=lambda row:(row[0],row[1]))

        scope_probe_limit=max(10,settings.autonomous_max_programs*10)
        for _,handle,item in metadata_candidates[:scope_probe_limit]:
            attrs=item.get("attributes",{})
            try:
                scopes_payload=api.structured_scopes(handle)
                scopes=normalize_scopes(scopes_payload)
            except Exception as exc:
                summary["skipped"].append({"program":handle,"reason":f"scope fetch failed: {exc}"})
                continue
            bounty_scopes=[x for x in scopes if x.eligible_for_bounty and x.eligible_for_submission]
            if not bounty_scopes:
                continue
            store.save_program({"data":{"attributes":attrs,"id":item.get("id"),"type":item.get("type","program")}})
            store.save_scopes(handle,scopes_payload)
            opportunity=rank(handle,attrs.get("name",handle),attrs.get("state",""),bounty_scopes,{"offers_bounties":True,"open_scope":attrs.get("open_scope",False),"fast_payments":attrs.get("fast_payments",False)})
            ranked.append((opportunity,bounty_scopes))
            if on_progress:
                on_progress({"phase":"ranking_programs","detail":f"Evaluated bounty scope for {handle}","programs_seen":len(payload["data"]),"bounty_programs":len(ranked),"scope_candidates":scope_probe_limit,"planned_targets":0,"completed_targets":0})
        ranked.sort(key=lambda pair:(-pair[0].score,pair[0].handle)); summary["checked_programs"]=len(ranked)
        if not settings.autonomous_research:
            summary["top_opportunities"]=[asdict(x[0])|{"triage_score":x[0].score} for x in ranked[:10]]; return summary
        settings.require_autonomous_research(); allowlist=set(settings.research_program_allowlist); llm=LLMClient(settings)
        if not llm.available(): return {**summary,"status":"blocked","error":"LLM provider is not configured/available.","error_type":"llm"}
        for opportunity,scopes in ranked[:settings.autonomous_max_programs]:
            if allowlist and opportunity.handle not in allowlist: continue
            if on_progress: on_progress({"phase":"selecting_program","program":opportunity.handle,"detail":"Selected bounty-eligible program for autonomous research","planned_targets":settings.autonomous_max_targets_per_program,"completed_targets":0})
            result=_research_program(settings,api,store,opportunity.handle,settings.autonomous_max_targets_per_program,active=False,deep=True,on_progress=on_progress,program_context={"handle":opportunity.handle,"name":opportunity.name,"state":opportunity.state,"offers_bounties":opportunity.offers_bounties})
            summary["researched_targets"]+=result.get("targets_checked",0); summary["created_findings"]+=result.get("created_findings",0); summary["findings"].extend(result.get("findings",[])); summary["skipped"].extend([{"program":opportunity.handle,"reason":x} for x in result.get("skipped",[])])
            if result.get("findings"): break
        summary["mode"]="autonomous-authorized-research"; return summary
    except Exception as exc: return {**summary,"status":"error","error":f"{exc.__class__.__name__}: {exc}","error_type":"worker"}
    finally:
        if api is not None: api.close()
        store.close()
