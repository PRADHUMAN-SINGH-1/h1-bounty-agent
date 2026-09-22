from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import Settings
from .discovery import rank
from .hackerone import HackerOneClient
from .llm import LLMClient
from .models import Evidence, Finding
from .mobile import analyze_mobile_package
from .cloud import analyze_cloud_text
from .browser_trace import browser_model_json, load_har
from .browser_automation import AuthorizedBrowserMapper
from .business_logic import build_workflow_model, model_evidence
from .hypotheses import generate_hypotheses

from .reporting import markdown_report
from .research import LowImpactResearch, flatten
from .scope import normalize_scopes, target_is_in_scope
from .store import Store
from .validation import require_human_approval, validate_finding


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="h1-agent",
        description="Scope-gated AI-assisted HackerOne research agent",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("programs", help="List programs visible to your HackerOne account")

    discover = sub.add_parser("discover", help="Rank visible programs using scope eligibility")
    discover.add_argument("--limit", type=int, default=15)

    program = sub.add_parser("program", help="Show program policy and structured scope")
    program.add_argument("handle")

    plan = sub.add_parser("plan", help="Generate an AI research plan from policy/scope")
    plan.add_argument("handle")

    dry = sub.add_parser("dry-run", help="Check target scope without sending target traffic")
    dry.add_argument("handle")
    dry.add_argument("target")

    research = sub.add_parser("research", help="Run the low-impact research engine")
    research.add_argument("handle")
    research.add_argument("target")
    research.add_argument("--active", action="store_true")

    mobile = sub.add_parser("mobile-analyze", help="Statically analyze an APK/IPA package")
    mobile.add_argument("path")

    cloud = sub.add_parser("cloud-analyze", help="Analyze a text/JSON/IAM policy file for cloud footprint and policy indicators")
    cloud.add_argument("path")

    browser = sub.add_parser("browser-analyze", help="Analyze an authorized browser HAR trace and build a session/workflow model")
    browser.add_argument("handle")
    browser.add_argument("path")

    crawl = sub.add_parser("browser-crawl", help="Run an authorized local Playwright read-only crawl")
    crawl.add_argument("handle")
    crawl.add_argument("target")
    crawl.add_argument("--storage-state", default=None)
    crawl.add_argument("--max-pages", type=int, default=20)

    business = sub.add_parser("business-model", help="Build a business-logic model from a JSON request trace")
    business.add_argument("path")

    sub.add_parser("capabilities", help="Show implemented research capabilities")

    sub.add_parser("findings", help="List candidate findings")

    review = sub.add_parser("review", help="Show a candidate finding and its human checklist")
    review.add_argument("finding_id", type=int)

    approve = sub.add_parser("approve", help="Mark a finding approved after your own validation")
    approve.add_argument("finding_id", type=int)

    submit = sub.add_parser("submit", help="Submit an approved finding")
    submit.add_argument("finding_id", type=int)
    submit.add_argument("--team-handle", required=True)
    submit.add_argument("--severity", required=True, choices=["none", "low", "medium", "high", "critical"])
    submit.add_argument("--confirmed", action="store_true")

    args = parser.parse_args()
    settings = Settings()
    store = Store(settings)

    if args.command == "capabilities":
        capabilities = [
            "authenticated session mapping",
            "read-only workflow exploration",
            "IDOR/BOLA differential testing",
            "role/permission differential modeling",
            "stateful read-only API workflows",
            "GraphQL introspection",
            "WebSocket handshake discovery",
            "mobile package static analysis",
            "cloud/IAM footprint and policy analysis",
            "attack-chain correlation",
            "scheduled recon integration",
        ]
        for item in capabilities:
            print("[OK] " + item)
        return

    if args.command == "browser-crawl":
        api = HackerOneClient(settings)
        try:
            scopes = normalize_scopes(api.structured_scopes(args.handle))
        finally:
            api.close()
        mapper = AuthorizedBrowserMapper(scopes, max_pages=args.max_pages)
        result, evidence = mapper.crawl(args.target, storage_state=args.storage_state)
        print(json.dumps({
            "pages": result.pages,
            "requests": result.requests,
            "storage_origins": result.storage_origins,
            "evidence": [item.__dict__ for item in evidence],
        }, indent=2))
        return

    if args.command == "browser-analyze":
        api = HackerOneClient(settings)
        try:
            scopes = normalize_scopes(api.structured_scopes(args.handle))
        finally:
            api.close()
        model, evidence = load_har(args.path, scopes)
        print(json.dumps({
            "model": browser_model_json(model),
            "business_model": {
                "objects": [item.__dict__ for item in build_workflow_model([
                    {"method": item.method, "url": item.url, "status": item.status, "source": item.source}
                    for item in model.requests
                ]).objects]
            },
            "evidence": [item.__dict__ for item in evidence],
        }, indent=2))
        return

    if args.command == "business-model":
        payload = json.loads(Path(args.path).read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise SystemExit("business-model expects a JSON array of request objects.")
        model = build_workflow_model(payload)
        hypotheses = generate_hypotheses(model_evidence(model))
        print(json.dumps({
            "objects": [item.__dict__ for item in model.objects],
            "nodes": [item.__dict__ for item in model.nodes],
            "edges": [item.__dict__ for item in model.edges],
            "invariants": [item.__dict__ for item in model.invariants],
            "hypotheses": [item.__dict__ for item in hypotheses],
        }, indent=2))
        return

    if args.command == "mobile-analyze":
        result, evidence = analyze_mobile_package(args.path)
        print(json.dumps({"result": result, "evidence": [item.__dict__ for item in evidence]}, indent=2))
        return

    if args.command == "cloud-analyze":
        from pathlib import Path
        path = Path(args.path)
        text = path.read_text(encoding="utf-8", errors="ignore")
        result, evidence = analyze_cloud_text(text, str(path))
        print(json.dumps({"result": result, "evidence": [item.__dict__ for item in evidence]}, indent=2))
        return

    if args.command == "findings":
        for row in store.list_findings():
            print(json.dumps(row, ensure_ascii=False))
        return

    if args.command == "approve":
        row = store.get_finding(args.finding_id)
        finding = _row_to_finding(row)
        result = validate_finding(finding)
        if not result.ok:
            raise SystemExit("Cannot approve: " + "; ".join(result.blockers))
        store.set_state(args.finding_id, "approved")
        print(f"Finding {args.finding_id} approved for submission.")
        return

    if args.command == "review":
        row = store.get_finding(args.finding_id)
        finding = _row_to_finding(row)
        print(markdown_report(finding))
        result = validate_finding(finding)
        print("\nAutomated completeness:", "PASS" if result.ok else "BLOCK")
        for blocker in result.blockers:
            print("-", blocker)
        print("\nHuman checklist:")
        for check in (
            "Reproduce the behavior yourself",
            "Confirm the exact asset/path remains in scope",
            "Review current program testing restrictions",
            "Verify every evidence item",
            "Check duplicates/exclusions and set accurate severity",
        ):
            print(f"- [ ] {check}")
        return

    if args.command == "submit":
        settings.require_submission_enabled()
        if not args.confirmed:
            raise SystemExit("Submission blocked: pass --confirmed only after your final validation.")
        row = store.get_finding(args.finding_id)
        finding = _row_to_finding(row)
        finding.severity = args.severity
        require_human_approval(finding)

        api = HackerOneClient(settings)
        try:
            payload = api.create_report(
                team_handle=args.team_handle,
                title=finding.title,
                vulnerability_information=markdown_report(finding),
                impact=finding.impact,
                severity_rating=args.severity,
                weakness_id=finding.weakness_id,
                structured_scope_id=(
                    int(finding.structured_scope_id)
                    if (finding.structured_scope_id or "").isdigit()
                    else None
                ),
            )
        finally:
            api.close()

        store.mark_submitted(args.finding_id, payload)
        print(json.dumps(payload, indent=2))
        return

    api = HackerOneClient(settings)
    try:
        if args.command == "programs":
            print(json.dumps(api.programs(), indent=2))
            return

        if args.command == "discover":
            programs = api.programs().get("data", [])[: max(args.limit, 1)]
            ranked = []
            for item in programs:
                attrs = item.get("attributes", {})
                handle = attrs.get("handle")
                if not handle:
                    continue
                scopes = normalize_scopes(api.structured_scopes(handle))
                ranked.append(
                    rank(
                        handle,
                        attrs.get("name", handle),
                        attrs.get("state", ""),
                        scopes,
                    )
                )
            for item in sorted(ranked, key=lambda x: (-x.score, x.handle)):
                print(json.dumps(item.__dict__ | {"score": item.score}))
            return

        if args.command == "program":
            program_payload = api.program(args.handle)
            scope_payload = api.structured_scopes(args.handle)
            store.save_program(program_payload)
            store.save_scopes(args.handle, scope_payload)
            print(
                json.dumps(
                    {"program": program_payload, "structured_scopes": scope_payload},
                    indent=2,
                )
            )
            return

        if args.command == "plan":
            program_payload = api.program(args.handle)
            scope_payload = api.structured_scopes(args.handle)
            exclusions = api.scope_exclusions(args.handle)
            store.save_program(program_payload)
            store.save_scopes(args.handle, scope_payload)

            attrs = program_payload.get("data", {}).get("attributes", {})
            llm = LLMClient(settings)
            if not llm.available():
                raise SystemExit("LLM provider is unavailable. Configure a local or hosted provider.")

            result = llm.research_plan(
                args.handle,
                str(attrs.get("policy") or attrs.get("description") or ""),
                [a.__dict__ for a in normalize_scopes(scope_payload)],
                exclusions,
            )
            print(json.dumps(result, indent=2))
            return

        if args.command == "dry-run":
            scopes = normalize_scopes(api.structured_scopes(args.handle))
            ok, asset, reason = target_is_in_scope(args.target, scopes)
            print(
                json.dumps(
                    {
                        "allowed": ok,
                        "matched_scope": asset.__dict__ if asset else None,
                        "reason": reason,
                    },
                    indent=2,
                )
            )
            if not ok:
                raise SystemExit(1)
            return

        if args.command == "research":
            if not args.active:
                raise SystemExit(
                    "Pass --active only after reviewing the current program policy."
                )
            if not settings.allow_active_tests:
                raise SystemExit(
                    "Active testing is disabled by ALLOW_ACTIVE_TESTS. Review the current program policy before enabling it."
                )

            scopes = normalize_scopes(api.structured_scopes(args.handle))
            ok, asset, reason = target_is_in_scope(args.target, scopes)
            if not ok or asset is None:
                raise SystemExit("Blocked by scope gate: " + reason)

            engine = LowImpactResearch(settings, scopes)
            try:
                results = engine.run(args.target, active=True)
            finally:
                engine.close()

            evidence = flatten(results)
            evidence_json = [e.__dict__ for e in evidence]
            print(
                json.dumps(
                    [
                        {
                            "name": r.name,
                            "status": r.status,
                            "detail": r.detail,
                            "evidence": [e.__dict__ for e in r.evidence],
                        }
                        for r in results
                    ],
                    indent=2,
                )
            )

            llm = LLMClient(settings)
            if llm.available():
                draft = llm.draft_finding(args.handle, args.target, evidence_json)
                finding_id = store.create_finding(
                    {
                        "program_handle": args.handle,
                        "target": args.target,
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
                print(f"Candidate finding saved as #{finding_id}")
                print(json.dumps(draft, indent=2))
            else:
                print("LLM unavailable; evidence collected but no finding draft was created.")
            return
    finally:
        api.close()


def _row_to_finding(row: dict) -> Finding:
    return Finding(
        program_handle=row["program_handle"],
        target=row["target"],
        title=row["title"],
        severity=row["severity"],
        state=row["state"],
        summary=row["summary"],
        impact=row["impact"],
        reproduction=row["reproduction"],
        evidence=[Evidence(**e) for e in row["evidence"]],
        structured_scope_id=row.get("structured_scope_id"),
        weakness_id=row.get("weakness_id"),
        metadata=row.get("metadata") or {},
    )


if __name__ == "__main__":
    main()
