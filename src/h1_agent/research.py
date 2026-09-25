from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from .authorization import AuthorizationDifferentialTester, evidence_from_results
from .chains import build_candidate_chains
from .graphql import discover_graphql_endpoints, introspection_probe
from .idor import ObjectAuthorizationTester
from .session_mapper import AuthenticatedSessionMapper
from .websocket import discover_websocket_urls, websocket_handshake_probe
from .workflow import evidence_summary, run_stateful_get_workflow
from .cloud import analyze_cloud_text
from .business_logic import build_workflow_model, model_evidence
from .hypotheses import generate_hypotheses, hypothesis_evidence
from .mutation import build_mutation_plans
from .research_graph import build_research_graph
from .recon_diff import compare_surfaces
from .role_model import RoleObservation, build_role_graph, role_graph_evidence
from .attack_surface import (
    discover_from_html,
    discover_from_javascript,
    discover_from_openapi,
    parse_openapi,
    surface_evidence,
)
from .config import Settings
from .models import Evidence, ScopeAsset
from .scope import require_in_scope, target_is_in_scope


def same_origin(left: str, right: str) -> bool:
    """Return True when two URLs share scheme, hostname, and effective port."""
    try:
        a = urlparse(left)
        b = urlparse(right)
        if a.scheme.lower() != b.scheme.lower() or (a.hostname or "").lower() != (b.hostname or "").lower():
            return False

        def effective_port(parsed):
            try:
                explicit = parsed.port
            except ValueError:
                return None
            if explicit is not None:
                return explicit
            scheme = parsed.scheme.lower()
            return 443 if scheme == "https" else 80 if scheme == "http" else None

        return effective_port(a) is not None and effective_port(a) == effective_port(b)
    except (TypeError, ValueError):
        return False

from .vulnerability_checks import (
    api_spec_probe,
    cookie_probe,
    cors_probe,
    discover_page,
    error_injection_probe,
    interesting_query_links,
    mixed_content_probe,
    sensitive_response_probe,
    open_redirect_probe,
    reflection_probe,
    sourcemap_probe,
)


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    detail: str
    evidence: list[Evidence]


class LowImpactResearch:
    """Scope-gated HTTP evidence collection with optional non-destructive probes."""

    def __init__(self, settings: Settings, scopes: list[ScopeAsset]):
        self.settings = settings
        self.scopes = scopes
        self.last_request = 0.0
        self._deadline: float | None = None
        self.client = httpx.Client(
            follow_redirects=False,
            timeout=12,
            headers={"User-Agent": settings.user_agent},
        )

    def _remaining(self) -> float:
        if self._deadline is None:
            return 12.0
        return self._deadline - time.monotonic()

    def _request_timeout(self) -> float:
        remaining = self._remaining()
        if remaining <= 0:
            raise httpx.ReadTimeout("research target deadline exceeded")
        return max(0.25, min(12.0, remaining))

    def close(self) -> None:
        self.client.close()

    def _wait(self) -> None:
        interval = 1 / max(self.settings.requests_per_second, 0.1)
        remaining = interval - (time.monotonic() - self.last_request)
        if self._deadline is not None and self._remaining() <= 0:
            raise httpx.ReadTimeout("research target deadline exceeded")
        if remaining > 0:
            time.sleep(min(remaining, self._remaining()))
        self.last_request = time.monotonic()

    def _get(self, url: str, **kwargs) -> httpx.Response:
        self._wait()
        kwargs.setdefault("timeout", self._request_timeout())
        try:
            return self.client.get(url, **kwargs)
        except (httpx.InvalidURL, ValueError) as exc:
            raise httpx.ReadError(f"invalid research URL: {url}", request=None) from exc

    def _options(self, url: str) -> httpx.Response:
        self._wait()
        try:
            return self.client.options(url, timeout=self._request_timeout())
        except (httpx.InvalidURL, ValueError) as exc:
            raise httpx.ReadError(f"invalid research URL: {url}", request=None) from exc

    def _head(self, url: str) -> httpx.Response:
        self._wait()
        try:
            return self.client.head(url, follow_redirects=False, timeout=self._request_timeout())
        except (httpx.InvalidURL, ValueError) as exc:
            raise httpx.ReadError(f"invalid research URL: {url}", request=None) from exc

    def run(
        self,
        target: str,
        *,
        active: bool = False,
        deep: bool = False,
    ) -> list[CheckResult]:
        asset = require_in_scope(target, self.scopes)
        self._deadline = time.monotonic() + max(30, self.settings.research_target_timeout_seconds)
        if active and not self.settings.allow_active_tests:
            raise PermissionError(
                "Active testing is disabled. Set ALLOW_ACTIVE_TESTS=true only after reviewing program policy."
            )
        if asset.instruction:
            instruction = asset.instruction.strip().replace("\n", " ")
            raise PermissionError(
                "This asset has program-specific instructions. Review them manually before active testing: "
                + instruction[:600]
            )

        base = target if target.endswith("/") else target + "/"
        results, home_response = self._get_home(base)

        for path in ("robots.txt", ".well-known/security.txt", "sitemap.xml"):
            results.append(self._get_metadata(base, path))

        results.append(self._options_probe(base))

        # "deep" means the full read-only research surface: endpoint discovery,
        # business-logic modeling, hypotheses, API/GraphQL/WebSocket checks, CORS,
        # reflection, redirect, error indicators, source maps, cloud signals, etc.
        # These probes are non-destructive and do not require ALLOW_ACTIVE_TESTS.
        # The legacy "active" flag remains available for callers that explicitly
        # opt into that gate.
        if (deep or active) and home_response is not None:
            results.extend(self._active_assessment(base, home_response))

        return results

    def _get_home(self, url: str) -> tuple[list[CheckResult], httpx.Response | None]:
        try:
            r = self._get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}
            evidence = [
                Evidence("status", str(r.status_code), url),
                Evidence("final_url", str(r.url), url),
                Evidence("content_type", headers.get("content-type", ""), url),
                Evidence("server", headers.get("server", ""), url),
            ]
            for name in (
                "content-security-policy",
                "strict-transport-security",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "permissions-policy",
            ):
                evidence.append(Evidence(name, headers.get(name, "missing"), url))
            cookie_status, cookie_evidence = cookie_probe(r, url)
            evidence.extend(cookie_evidence)
            result = CheckResult("homepage", "ok", f"HTTP {r.status_code}; cookie={cookie_status}", evidence)
            return [result], r
        except httpx.HTTPError as exc:
            return [CheckResult("homepage", "error", str(exc), [Evidence("error", str(exc), url)])], None

    def _get_metadata(self, base: str, path: str) -> CheckResult:
        url = urljoin(base, path)
        try:
            r = self._get(url)
            return CheckResult(
                path,
                "found" if r.status_code < 400 else "absent",
                f"HTTP {r.status_code}",
                [
                    Evidence("status", str(r.status_code), url),
                    Evidence("content_type", r.headers.get("content-type", ""), url),
                    Evidence("location", r.headers.get("location", ""), url),
                ],
            )
        except httpx.HTTPError as exc:
            return CheckResult(path, "error", str(exc), [Evidence("error", str(exc), url)])

    def _options_probe(self, url: str) -> CheckResult:
        try:
            r = self._options(url)
            return CheckResult(
                "options_metadata",
                "ok",
                f"HTTP {r.status_code}",
                [
                    Evidence("allow", r.headers.get("allow", ""), url),
                    Evidence("access-control-allow-origin", r.headers.get("access-control-allow-origin", ""), url),
                    Evidence("access-control-allow-methods", r.headers.get("access-control-allow-methods", ""), url),
                ],
            )
        except httpx.HTTPError as exc:
            return CheckResult("options_metadata", "error", str(exc), [Evidence("error", str(exc), url)])

    def _active_assessment(self, base: str, home_response: httpx.Response) -> list[CheckResult]:
        checks: list[CheckResult] = []
        html = home_response.text[:2_000_000]
        links, scripts, forms = discover_page(html, base)

        # Deep mode performs a bounded same-origin GET crawl. This is intentionally
        # read-only: it follows links and analyzes responses, but never submits forms
        # or changes application state.
        pages_seen = {base.rstrip("/")}
        page_queue = [
            link
            for link in links
            if same_origin(link, base)
            and target_is_in_scope(link, self.scopes)[0]
        ][: self.settings.deep_max_page_links]
        page_documents: list[tuple[str, str]] = [(base, html)]
        all_links = list(links)
        all_scripts = list(scripts)
        all_forms = list(forms)

        while page_queue and len(page_documents) < self.settings.deep_max_pages:
            page_url = page_queue.pop(0)
            normalized = page_url.rstrip("/")
            if normalized in pages_seen:
                continue
            pages_seen.add(normalized)
            try:
                response = self._get(page_url, follow_redirects=False)
            except httpx.HTTPError:
                continue
            content_type = response.headers.get("content-type", "").lower()
            if response.status_code >= 400 or "html" not in content_type and "text" not in content_type:
                continue
            page_html = response.text[:2_000_000]
            page_documents.append((page_url, page_html))
            page_links, page_scripts, page_forms = discover_page(page_html, page_url)
            for item in page_links:
                if item not in all_links:
                    all_links.append(item)
                if (
                    same_origin(item, base)
                    and target_is_in_scope(item, self.scopes)[0]
                    and item.rstrip("/") not in pages_seen
                    and len(page_queue) < self.settings.deep_max_page_links
                ):
                    page_queue.append(item)
            for item in page_scripts:
                if item not in all_scripts:
                    all_scripts.append(item)
            all_forms.extend(page_forms)

        query_links = [
            url for url in interesting_query_links(all_links, base)
            if target_is_in_scope(url, self.scopes)[0]
        ]

        surface = []
        for page_url, page_html in page_documents:
            surface.extend(
                endpoint
                for endpoint in discover_from_html(page_html, page_url)
                if target_is_in_scope(endpoint.url, self.scopes)[0]
            )

        script_texts: list[tuple[str, str]] = []
        in_scope_scripts = [
            url for url in all_scripts
            if target_is_in_scope(url, self.scopes)[0]
        ]
        for script_url in in_scope_scripts[: self.settings.deep_max_scripts]:
            try:
                response = self._get(script_url, follow_redirects=False)
                content_type = response.headers.get("content-type", "")
                if response.status_code == 200 and ("javascript" in content_type or "text" in content_type or script_url.endswith(".js")):
                    script_texts.append((script_url, response.text))
                    surface.extend(discover_from_javascript(response.text, script_url, base))
            except httpx.HTTPError:
                continue

        unique_surface = []
        seen_surface = set()
        for endpoint in surface:
            if endpoint.url in seen_surface:
                continue
            seen_surface.add(endpoint.url)
            unique_surface.append(endpoint)
        page_evidence = [
            Evidence("deep_crawl_pages", str(len(page_documents)), base),
            Evidence("deep_crawl_links", str(len(all_links)), base),
            Evidence("deep_crawl_forms", str(len(all_forms)), base),
        ]
        checks.append(CheckResult(
            "attack_surface_inventory",
            "found" if unique_surface else "empty",
            f"{len(unique_surface)} same-origin endpoints discovered across {len(page_documents)} pages",
            page_evidence + surface_evidence(unique_surface),
        ))

        request_records = [
            {
                "method": endpoint.method_hint,
                "url": endpoint.url,
                "status": None,
                "source": endpoint.source,
            }
            for endpoint in unique_surface
        ]
        graph = build_research_graph(request_records)
        checks.append(
            CheckResult(
                "business_logic_model",
                "found" if graph.business_model.nodes else "empty",
                f"{len(graph.business_model.nodes)} workflow nodes, {len(graph.business_model.objects)} object signals, {len(graph.business_model.invariants)} invariants",
                graph.evidence,
            )
        )
        hypotheses = generate_hypotheses(graph.evidence)
        checks.append(
            CheckResult(
                "hypothesis_engine",
                "found" if hypotheses else "empty",
                f"{len(hypotheses)} attack hypotheses generated from observed application semantics",
                hypothesis_evidence(hypotheses),
            )
        )
        mutation_plans = build_mutation_plans(request_records, self.scopes)
        checks.append(
            CheckResult(
                "state_change_planner",
                "ready" if mutation_plans else "empty",
                f"{len(mutation_plans)} authorized state-change plans require explicit human/program approval before execution",
                [
                    Evidence(
                        "mutation_plan",
                        f"{item.method} {item.url}: {item.rationale}",
                        item.url,
                    )
                    for item in mutation_plans
                ],
            )
        )


        if self.settings.authz_header_a:
            try:
                mapper = AuthenticatedSessionMapper(
                    self.client,
                    self.settings.authz_header_a,
                    self.settings.session_map_max_pages,
                    self.settings.session_map_max_depth,
                )
                pages, auth_evidence = mapper.crawl(base, self.scopes)
                checks.append(CheckResult(
                    "authenticated_workflow_map",
                    "found" if pages else "empty",
                    f"{len(pages)} authenticated read-only pages mapped",
                    auth_evidence,
                ))
            except ValueError as exc:
                checks.append(CheckResult("authenticated_workflow_map", "error", str(exc), []))

        status, evidence = cors_probe(self.client, base, self._get)
        checks.append(CheckResult("cors_probe", status, status.replace("_", " "), evidence))

        if query_links:
            for url in query_links[: self.settings.deep_max_query_links]:
                status, evidence = reflection_probe(self.client, url, self._get)
                if status != "skipped":
                    checks.append(CheckResult("reflection_probe", status, f"Query reflection check for {url}", evidence))

                status, evidence = open_redirect_probe(self.client, url, self._get)
                if status != "skipped":
                    checks.append(CheckResult("open_redirect_probe", status, f"Redirect parameter check for {url}", evidence))

                status, evidence = error_injection_probe(url, self._get)
                if status != "skipped":
                    checks.append(CheckResult("injection_error_probe", status, f"Error-based injection check for {url}", evidence))

        status, evidence = sourcemap_probe(self.client, in_scope_scripts, base, self._get)
        checks.append(CheckResult("sourcemap_probe", status, status.replace("_", " "), evidence))

        status, evidence = api_spec_probe(base, self._get)
        checks.append(CheckResult("api_spec_probe", status, status.replace("_", " "), evidence))

        openapi_endpoints = []
        for path in ("openapi.json", "swagger.json", "api-docs", "v3/api-docs"):
            spec_url = urljoin(base, path)
            if not target_is_in_scope(spec_url, self.scopes)[0]:
                continue
            try:
                response = self._get(spec_url, follow_redirects=False)
                if response.status_code == 200:
                    document = parse_openapi(response.text)
                    if document:
                        openapi_endpoints.extend(
                            endpoint
                            for endpoint in discover_from_openapi(document, base)
                            if target_is_in_scope(endpoint.url, self.scopes)[0]
                        )
            except httpx.HTTPError:
                continue

        api_candidates = [
            endpoint.url
            for endpoint in unique_surface
            if target_is_in_scope(endpoint.url, self.scopes)[0]
            and (
                "/api/" in endpoint.url.lower()
                or "/graphql" in endpoint.url.lower()
                or "/rest/" in endpoint.url.lower()
                or "/v1/" in endpoint.url.lower()
                or "/v2/" in endpoint.url.lower()
            )
        ]
        for api_url in api_candidates[: self.settings.deep_max_api_candidates]:
            status, evidence = sensitive_response_probe(api_url, self._get)
            checks.append(CheckResult(
                "sensitive_response_probe",
                status,
                f"Read-only API response inspection for {api_url}",
                evidence,
            ))

        if openapi_endpoints:
            seen_openapi = set()
            deduped_openapi = []
            for endpoint in openapi_endpoints:
                if endpoint.url in seen_openapi:
                    continue
                seen_openapi.add(endpoint.url)
                deduped_openapi.append(endpoint)
            checks.append(CheckResult(
                "openapi_surface",
                "found",
                f"{len(deduped_openapi)} read-only API operations discovered",
                surface_evidence(deduped_openapi),
            ))

            workflow_steps, workflow_evidence = run_stateful_get_workflow(
                self.client,
                deduped_openapi,
                base,
                self.scopes,
                max_steps=self.settings.deep_max_openapi_steps,
            )
            checks.append(CheckResult(
                "stateful_api_workflow",
                "found" if workflow_steps else "empty",
                f"{len(workflow_steps)} read-only API workflow steps exercised",
                workflow_evidence + evidence_summary(workflow_steps),
            ))

        graphql_urls = discover_graphql_endpoints([endpoint.url for endpoint in unique_surface], self.scopes)
        for graphql_url in graphql_urls[: self.settings.deep_max_graphql_endpoints]:
            status, evidence = introspection_probe(self.client, graphql_url, self.scopes)
            checks.append(CheckResult("graphql_introspection", status, f"GraphQL schema read for {graphql_url}", evidence))

        websocket_urls = discover_websocket_urls(home_response.text[:2_000_000], base, self.scopes)
        for websocket_url in websocket_urls[: self.settings.deep_max_websocket_endpoints]:
            status, evidence = websocket_handshake_probe(self.client, websocket_url, self.scopes)
            checks.append(CheckResult("websocket_handshake", status, f"WebSocket endpoint check for {websocket_url}", evidence))

        cloud_text = (html + "\n" + "\n".join(text for _url, text in script_texts))[: self.settings.deep_max_cloud_text_bytes]
        cloud_result, cloud_evidence = analyze_cloud_text(cloud_text, base)
        if cloud_result["aws_arns"] or cloud_result["azure_storage_urls"] or cloud_result["gcp_storage_hosts"] or cloud_result["policy_observations"]:
            checks.append(CheckResult("cloud_iam_analysis", "review", "Cloud footprint and policy indicators discovered", cloud_evidence))

        if self.settings.allow_authz_tests and self.settings.authz_header_a and self.settings.authz_header_b:
            authz_urls = [
                endpoint.url
                for endpoint in unique_surface
                if target_is_in_scope(endpoint.url, self.scopes)[0]
                and ("/api/" in endpoint.url.lower() or "graphql" in endpoint.url.lower())
            ]
            authz_urls.extend(
                endpoint.url
                for endpoint in openapi_endpoints[:20]
                if target_is_in_scope(endpoint.url, self.scopes)[0]
            )
            try:
                tester = AuthorizationDifferentialTester(
                    self.client,
                    self.settings.authz_header_a,
                    self.settings.authz_header_b,
                    self.settings.authz_max_endpoints,
                )
                differential = tester.compare(authz_urls)
                checks.append(CheckResult(
                    "authorization_differential",
                    "review" if any(item.suspicious for item in differential) else "observed",
                    "Two-account read-only authorization differential",
                    evidence_from_results(differential),
                ))
                role_observations = []
                for item in differential:
                    role_observations.extend(
                        [
                            RoleObservation(
                                "account-A",
                                item.url,
                                item.status_a or 0,
                                200 <= (item.status_a or 0) < 300,
                                "allowed" if 200 <= (item.status_a or 0) < 300 else "denied",
                            ),
                            RoleObservation(
                                "account-B",
                                item.url,
                                item.status_b or 0,
                                200 <= (item.status_b or 0) < 300,
                                "allowed" if 200 <= (item.status_b or 0) < 300 else "denied",
                            ),
                        ]
                    )
                role_graph = build_role_graph(role_observations)
                checks.append(
                    CheckResult(
                        "role_permission_model",
                        "review" if role_graph.anomalies else "observed",
                        f"{len(role_graph.permissions)} account permission sets inferred",
                        role_graph_evidence(role_graph),
                    )
                )
            except ValueError as exc:
                checks.append(CheckResult(
                    "authorization_differential",
                    "error",
                    str(exc),
                    [Evidence("authorization_config_error", str(exc), base)],
                ))

            try:
                object_tester = ObjectAuthorizationTester(
                    self.client,
                    self.settings.authz_header_a,
                    self.settings.authz_header_b,
                    self.settings.authz_max_endpoints,
                )
                observations, object_evidence = object_tester.run(authz_urls, self.scopes)
                checks.append(CheckResult(
                    "idor_bola_differential",
                    "review" if any(item.suspicious for item in observations) else "observed",
                    "Read-only object identifier substitution against the second test account",
                    object_evidence,
                ))
            except ValueError as exc:
                checks.append(CheckResult("idor_bola_differential", "error", str(exc), []))

        status, evidence = mixed_content_probe(base, html)
        checks.append(CheckResult("mixed_content_probe", status, status.replace("_", " "), evidence))

        chain_evidence = flatten(checks)
        chains = build_candidate_chains(chain_evidence)
        checks.append(
            CheckResult(
                "attack_chain_analysis",
                "found" if any(item.stages for item in chains) else "empty",
                "; ".join(item.name for item in chains),
                [
                    Evidence("attack_chain", f"{item.name}: {' -> '.join(item.stages)}; {item.rationale}", base)
                    for item in chains
                ],
            )
        )

        return checks


def flatten(results: list[CheckResult]) -> list[Evidence]:
    evidence: list[Evidence] = []
    for result in results:
        evidence.append(
            Evidence(
                "check_result",
                f"{result.name}: status={result.status}; detail={result.detail}",
                "h1-bounty-agent",
            )
        )
        evidence.extend(result.evidence)
    return evidence
