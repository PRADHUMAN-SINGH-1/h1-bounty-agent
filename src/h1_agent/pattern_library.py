from __future__ import annotations

from dataclasses import dataclass

from .models import Evidence


@dataclass(frozen=True)
class Pattern:
    name: str
    classes: tuple[str, ...]
    prerequisites: tuple[str, ...]
    strong_signals: tuple[str, ...]
    false_positive_traps: tuple[str, ...]
    impact: str


PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        "object-authorization-boundary",
        ("idor", "bola", "access-control"),
        ("object identifiers", "at least two authorized identities"),
        ("cross-account readable object", "unexpected role access", "ownership mismatch"),
        ("200 response without sensitive/different object data"),
        "high",
    ),
    Pattern(
        "graphql-resolver-authorization",
        ("graphql", "access-control"),
        ("GraphQL operation or schema", "role/tenant context"),
        ("resolver allows object outside caller scope", "mutation available to lower role"),
        ("introspection alone", "schema visibility alone"),
        "high",
    ),
    Pattern(
        "oauth-redirect-or-token-confusion",
        ("oauth", "authentication"),
        ("OAuth flow", "redirect or token exchange evidence"),
        ("cross-client redirect", "authorization code leakage", "token audience confusion"),
        ("ordinary redirect", "documentation-only OAuth endpoint"),
        "high",
    ),
    Pattern(
        "credentialed-cors-data-exposure",
        ("cors", "web"),
        ("credentialed response", "attacker-controlled origin reflection"),
        ("sensitive authenticated response readable cross-origin"),
        ("wildcard CORS without credentials", "public data"),
        "high",
    ),
    Pattern(
        "stored-or-blind-xss-impact-chain",
        ("xss", "client-side"),
        ("user-controlled input", "rendering sink"),
        ("execution in privileged context", "persistent/blind delivery"),
        ("reflection without executable sink", "sanitization intact"),
        "high",
    ),
    Pattern(
        "ssrf-to-sensitive-boundary",
        ("ssrf", "server-side-request"),
        ("server-side URL fetch primitive"),
        ("internal metadata access", "sensitive internal service access"),
        ("open redirect only", "client-side fetch"),
        "critical",
    ),
    Pattern(
        "business-logic-state-transition",
        ("business-logic", "workflow"),
        ("state-changing workflow"),
        ("illegal state transition", "server-side invariant bypass", "financial impact"),
        ("client-side-only state", "normal alternate flow"),
        "high",
    ),
    Pattern(
        "mass-assignment-or-property-injection",
        ("mass-assignment", "access-control"),
        ("structured object update", "server-side object binding"),
        ("protected property accepted from client", "role/ownership field change"),
        ("ignored unknown property", "client-side model only"),
        "high",
    ),
    Pattern(
        "race-condition-double-action",
        ("race-condition", "business-logic"),
        ("repeatable request", "state or balance transition"),
        ("duplicate authorization", "double spend", "multiple one-time benefits"),
        ("idempotent endpoint", "harmless duplicate"),
        "critical",
    ),
    Pattern(
        "sensitive-data-exposure",
        ("privacy", "data-exposure"),
        ("sensitive response field"),
        ("cross-user/cross-tenant exposure", "private credential/token material"),
        ("public metadata", "user-visible own data"),
        "high",
    ),
    Pattern(
        "api-key-or-secret-exposure",
        ("secrets", "supply-chain"),
        ("secret-like artifact"),
        ("live credential with demonstrated access"),
        ("placeholder/test key", "redacted/public token"),
        "high",
    ),
    Pattern(
        "file-upload-to-code-or-data-impact",
        ("file-upload", "web"),
        ("upload feature"),
        ("executable content accepted", "cross-user file exposure", "path traversal"),
        ("ordinary image/document upload"),
        "high",
    ),
    Pattern(
        "cache-key-authentication-confusion",
        ("cache-poisoning", "web"),
        ("cacheable authenticated or dynamic response"),
        ("shared cache serves attacker-influenced authenticated content"),
        ("uncacheable response", "self-only cache effect"),
        "high",
    ),
    Pattern(
        "subdomain-takeover-or-dangling-service",
        ("subdomain", "dns"),
        ("in-scope dangling record/service"),
        ("claimable provider resource", "unclaimed production hostname"),
        ("provider error without claimability"),
        "high",
    ),
    Pattern(
        "request-smuggling-boundary",
        ("http", "proxy"),
        ("front-end/back-end protocol boundary"),
        ("parser disagreement with security impact"),
        ("single parser normalization"),
        "high",
    ),
    Pattern(
        "path-traversal-file-read",
        ("path-traversal", "file-disclosure"),
        ("file/path input"),
        ("arbitrary in-scope server file read"),
        ("fixed filename/path", "local-only error"),
        "high",
    ),
)


def pattern_evidence() -> list[Evidence]:
    return [
        Evidence(
            "bounty_pattern_reference",
            (
                f"{pattern.name} | classes={','.join(pattern.classes)} | "
                f"prerequisites={'; '.join(pattern.prerequisites)} | "
                f"strong_signals={'; '.join(pattern.strong_signals)} | "
                f"false_positive_traps={'; '.join(pattern.false_positive_traps)} | "
                f"impact={pattern.impact}"
            ),
            "public-bounty-pattern-library",
        )
        for pattern in PATTERNS
    ]


def _items(value) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    return tuple(value or ())


def relevant_patterns(evidence: list[Evidence], limit: int = 12) -> list[Pattern]:
    names = " ".join(item.name + " " + item.value for item in evidence).lower()
    scored = []
    for pattern in PATTERNS:
        score = 0
        for token in _items(pattern.classes) + _items(pattern.prerequisites) + _items(pattern.strong_signals):
            if str(token).lower() in names:
                score += 1
        if score:
            scored.append((score, pattern))
    scored.sort(key=lambda item: (-item[0], item[1].name))
    return [pattern for _score, pattern in scored[:limit]]
