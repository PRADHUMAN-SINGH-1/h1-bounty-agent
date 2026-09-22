import json

from h1_agent.browser_automation import AuthorizedBrowserMapper
from h1_agent.browser_trace import browser_model_json, parse_har
from h1_agent.business_logic import build_workflow_model
from h1_agent.hypotheses import generate_hypotheses
from h1_agent.mutation import build_mutation_plans
from h1_agent.recon_diff import compare_surfaces
from h1_agent.research_graph import build_research_graph
from h1_agent.research_memory import make_memory, merge_memory
from h1_agent.role_model import RoleObservation, build_role_graph


class Scope:
    asset_type = "DOMAIN"
    asset_identifier = "example.com"
    eligible_for_submission = True
    eligible_for_bounty = True
    instruction = ""
    id = "1"
    max_severity = confidentiality_requirement = integrity_requirement = availability_requirement = reference = None


def test_har_builds_browser_session_model():
    payload = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/",
                        "headers": [{"name": "Cookie", "value": "session=x"}],
                        "cookies": [{"name": "session", "value": "x"}],
                    },
                    "response": {"status": 200, "headers": [{"name": "content-type", "value": "text/html"}]},
                    "_resourceType": "document",
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://example.com/api/orders",
                        "headers": [{"name": "Authorization", "value": "Bearer test"}],
                        "cookies": [],
                    },
                    "response": {"status": 201, "headers": [{"name": "content-type", "value": "application/json"}]},
                    "_resourceType": "fetch",
                },
                {
                    "request": {"method": "GET", "url": "https://evil.example.net/"},
                    "response": {"status": 200},
                },
            ]
        }
    }
    model, evidence = parse_har(payload, [Scope()])
    view = browser_model_json(model)
    assert len(model.requests) == 2
    assert "cookie-backed-session" in model.stateful_signals
    assert "state-changing-browser-actions-observed" in model.stateful_signals
    assert view["methods"] == ["GET", "POST"]
    assert evidence


def test_business_model_infers_objects_and_invariants():
    model = build_workflow_model(
        [
            {"method": "GET", "url": "https://example.com/api/orders/123", "status": 200, "source": "trace"},
            {"method": "PATCH", "url": "https://example.com/api/orders/123", "status": 200, "source": "trace"},
            {"method": "POST", "url": "https://example.com/api/orders/123/refund", "status": 201, "source": "trace"},
        ]
    )
    assert any(item.identifier == "123" for item in model.objects)
    assert any(item.name == "state-transition-authorization" for item in model.invariants)
    assert model.edges


def test_hypothesis_engine_creates_business_logic_hypothesis():
    graph = build_research_graph(
        [{"method": "PATCH", "url": "https://example.com/api/orders/123", "status": 200, "source": "trace"}]
    )
    assert graph.hypotheses
    assert any(item.class_name == "business-logic" for item in graph.hypotheses)


def test_mutation_plans_are_scope_gated():
    plans = build_mutation_plans(
        [
            {"method": "PATCH", "url": "https://example.com/api/orders/123"},
            {"method": "DELETE", "url": "https://evil.example.net/orders/123"},
        ],
        [Scope()],
    )
    assert len(plans) == 1
    assert plans[0].requires_confirmation


def test_role_graph_models_permission_sets():
    graph = build_role_graph(
        [
            RoleObservation("account-A", "/admin", 403, False, "denied"),
            RoleObservation("account-B", "/admin", 200, True, "allowed"),
        ]
    )
    assert graph.permissions["account-B"] == ["/admin"]


def test_surface_diff_detects_added_and_removed():
    delta = compare_surfaces(["https://example.com/a", "https://example.com/b"], ["https://example.com/b", "https://example.com/c"])
    assert delta.added == ["https://example.com/c"]
    assert delta.removed == ["https://example.com/a"]


def test_memory_merge_replaces_same_key():
    first = make_memory("target:role", "user", "test")
    second = make_memory("target:role", "admin", "test")
    merged = merge_memory([first], [second])
    assert len(merged) == 1
    assert merged[0].value == "admin"


def test_browser_mapper_fails_closed_without_playwright_or_scope():
    try:
        AuthorizedBrowserMapper([Scope()]).crawl("https://evil.example.net/")
    except PermissionError:
        return
    raise AssertionError("Expected out-of-scope browser start to be blocked")
