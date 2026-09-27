# H1 Bounty Agent

AI-assisted HackerOne research workspace for **authorized, scope-gated bug-bounty research**. The application discovers accessible public programs, ranks paid scope, performs bounded deep read-only research, correlates evidence into vulnerability candidates, and places candidates in a human-review queue before any HackerOne submission.

It is deliberately evidence-first: **a green scan is not a vulnerability, and the system never fabricates a bounty candidate when evidence is insufficient.**

## End-to-end architecture

```text
HackerOne Hacker API
        |
        v
Exhaustive paginated program discovery
        |
        v
Public/active + bounty-eligible scope filter
        |
        v
Program + policy + exclusions + weakness context
        |
        v
Bounty opportunity ranking
        |
        v
Eligible structured-scope assets
        |
        v
Bounded deep read-only research
  |-- same-origin crawl
  |-- JavaScript / endpoint discovery
  |-- OpenAPI / Swagger
  |-- GraphQL
  |-- WebSocket
  |-- CORS / reflection / redirect indicators
  |-- source maps / API specs
  |-- business workflow modeling
  |-- authorization differentials when explicitly configured
  |-- cloud / mobile / static-artifact analysis
        |
        v
Attack hypotheses + evidence graph
        |
        v
LLM evidence triage + finding draft
        |
        v
Validation / duplicate / scope checks
        |
        v
Human review queue
        |
        v
Explicit Approve & Submit
```

## What the one-click hunt actually does

The dashboard's **Hunt automatically** workflow is now a real two-stage pipeline rather than a cosmetic button:

1. Fetches the HackerOne program catalog with pagination instead of only the first 25 programs.
2. Fetches complete structured-scope pages for each discovered program.
3. Removes programs with no bounty-eligible assets from the top hunt set.
4. Ranks remaining opportunities using bounty-eligible scope, submission-eligible scope, web assets, high-severity-capable assets, and available program signals.
5. Selects the configured top opportunities.
6. Runs full **non-destructive** research on their eligible assets.
7. Supplies current program policy, exclusions, and weakness information to the research/LLM stages.
8. Creates a candidate only when the evidence supports one.
9. Stores the candidate as `needs_review`.
10. Requires human approval and current scope validation before submission.

HackerOne's Hacker API documents the program and structured-scope endpoints as paginated; the implementation therefore treats pagination as mandatory rather than assuming the first response is the complete catalog.

HackerOne's current documentation also exposes program signals such as `offers_bounties`, `open_scope`, and `fast_payments`, while structured scopes expose bounty/submission eligibility and maximum severity.

## Safety and authorization boundaries

- Deep research runs with `active=False` and is read-only by default.
- Every HTTP target must match an eligible structured scope before target traffic is sent.
- Program-specific scope instructions are treated as a manual-review boundary.
- State-changing requests are planned separately and require their own explicit gate.
- Two-account authorization testing requires two explicitly configured authorized test accounts.
- Automatic submission is disabled unless the deployment explicitly enables it.
- Even when submission is enabled, the dashboard requires the finding to be approved and to pass current scope/completeness validation.
- No credential brute forcing, form submission, destructive actions, or out-of-scope scanning is part of the default deep-research path.

HackerOne's current guidance emphasizes that scope determines which assets can be reported and whether they are bounty eligible; the agent uses those structured-scope fields as hard routing gates.


## Latest targeted hunt modules

The repository also contains targeted, read-only checks for high-signal program surfaces: Superhuman/Grammarly CTF document paths, Superhuman identity/OAuth endpoints, Kong public XSS/Algolia exposure, Kong Identity OAuth, and Kong documentation exposure.

The September 26, 2026 autonomous HackerOne run authenticated successfully, scanned 500 programs during discovery, evaluated 595 programs, identified 9 bounty programs with 16 scope candidates, and selected **Flutteruki** and **Superhuman** for the configured two-program pass. It researched 3 targets and created 0 findings. The research evidence reached report drafting, but evidence triage and LLM analysis were blocked by the configured Hugging Face router returning HTTP 402. No bounty report was submitted from that run.

The current CTF follow-up checks on September 27, 2026 tested the known document ID 1198436185, including the document, download, alternate document paths, and CAPI routes with anonymous GET/HEAD/OPTIONS requests. The download path returned HTTP 403 anonymously and no challenge flag marker was observed, so there is currently no verified CTF finding from this pass.

Files.com target status (September 27, 2026): the program handle is allowlisted as `files`. A bounded GET-only probe against the explicitly in-scope `https://app.files.com` returned HTTP 200 for the public application shell, HTTP 401 for tested authenticated REST resources (`api_key`, `permissions`, `users`, `custom_domains`, `bundle_downloads`, `files`, `folders`, `public_keys`), and no external redirect from the tested login/OAuth parameter variants. Public CSS/JS contained generic words such as `password`/token field names but no matched credential material. This pass therefore produced **0 confirmed Files.com vulnerabilities**. The remaining high-signal validation path is the program-mandated researcher-owned `[BUGBOUNTY]` trial site plus two distinct researcher-controlled authorization contexts for tenant/object isolation testing; those credentials/assigned host are not present in GitHub Actions, so no cross-tenant claim is made without them.

A separate current-program source-integrity review produced a private submission dossier. Target-specific vulnerability details are intentionally kept out of this public README until responsible disclosure is appropriate.

Authorized cross-account testing now uses an exact-object BOLA workflow: Account A reads an object, the agent extracts the object URL and ownership binding, then Account B requests that exact same object URL. The agent only marks it suspicious when Account B receives HTTP 2xx and reproduces both the object identifier and an A-owned binding on a private-object path. The previous arbitrary `+1`/reversed-ID substitution logic was removed because it could not prove an authorization bypass. Configure two distinct researcher-owned test sessions only in the deployment environment using ALLOW_AUTHZ_TESTS=true, AUTHZ_HEADER_A, and AUTHZ_HEADER_B; never place live session tokens in source control or chat. A deterministic CWE-639 report draft is generated from this high-signal evidence, but it remains `needs_review` and requires human approval before any submission.

## Research engine

Deep research currently includes:

- bounded same-origin crawling
- HTML, JavaScript, and endpoint discovery
- query-parameter discovery
- OpenAPI/Swagger surface extraction
- GraphQL introspection analysis
- WebSocket discovery and handshake analysis
- CORS differential checks
- reflection indicators
- redirect-parameter checks
- error-based indicators
- cookie/security-header observations
- source-map and API-spec discovery
- sensitive-response inspection
- business-logic/workflow modeling
- object ownership and tenant-isolation modeling
- role/privilege graph inference
- authorized two-account differential testing
- stateful read-only API workflows
- attack hypothesis generation
- attack-chain correlation
- recon surface change detection
- persistent research memory
- optional toolchain evidence
- evidence-grounded LLM triage and report drafting

Informational observations are deliberately not promoted into bounty findings by themselves. The LLM is instructed to require security-relevant evidence and to keep uncertain claims in `needs_review`/`no_finding` states.

## Resilience and bounded execution

- **Postgres schema migration/retry hardening** protects long-lived Render deployments and dashboard queue reads.
- Deep toolchain subprocesses have bounded execution time; a slow `httpx`, `katana`, `nuclei`, or passive discovery process cannot hold a research job indefinitely.
- Toolchain target counts are bounded so a large scope cannot silently expand a single research job into hundreds of targets.
- Evidence collection is treated as a partial-progress stage: a tool timeout is recorded as research telemetry and does not erase evidence already collected.
- The dashboard reports the actual research-job error rather than displaying a generic `Unknown error`.

## Deployment

### Render

The production service can run as a FastAPI web service:

```text
uvicorn api.index:app --host 0.0.0.0 --port $PORT
```

The repository includes `render.yaml` for Render deployment and Postgres-backed persistence.

### Vercel

The repository also contains the Vercel/ASGI deployment configuration and the authenticated dashboard. Long-running work is queued as background jobs rather than executed synchronously inside the request handler.

### GitHub Actions

CI validates the Python project, dashboard syntax, release integrity, and research workflow regressions. Scheduled research can be triggered through the repository's existing workflow/cron integration.

## Environment

Core HackerOne credentials:

```text
HACKERONE_USERNAME=<HackerOne API token identifier>
HACKERONE_API_TOKEN=<HackerOne API token value>
HACKERONE_BASE_URL=https://api.hackerone.com
```

Research defaults:

```text
DRY_RUN=true
ALLOW_ACTIVE_TESTS=false
ALLOW_AUTHZ_TESTS=false
ALLOW_STATE_CHANGING_TESTS=false

FULL_RESEARCH_MAX_TARGETS_PER_PROGRAM=50
DEEP_MAX_SCRIPTS=30
DEEP_MAX_QUERY_LINKS=20
DEEP_MAX_API_CANDIDATES=30
DEEP_MAX_GRAPHQL_ENDPOINTS=10
DEEP_MAX_WEBSOCKET_ENDPOINTS=10
DEEP_MAX_PAGES=30
DEEP_MAX_PAGE_LINKS=80
TOOLCHAIN_ENABLED=true
TOOLCHAIN_MAX_ROOTS=10
TOOLCHAIN_MAX_TARGETS=50
TOOLCHAIN_HTTPX_TIMEOUT_SECONDS=120
TOOLCHAIN_KATANA_TIMEOUT_SECONDS=180
TOOLCHAIN_NUCLEI_TIMEOUT_SECONDS=180
RESEARCH_TARGET_TIMEOUT_SECONDS=180
```

LLM configuration for a hosted deployment can use the configured OpenAI-compatible provider/Vercel gateway; local development can use Ollama.

Dashboard authentication requires:

```text
DASHBOARD_USER=<username>
DASHBOARD_PASSWORD=<strong password>
DASHBOARD_SECRET=<random secret>
```

Submission remains separately controlled:

```text
H1_ENABLE_SUBMISSION=false
AUTO_SUBMIT_FINDINGS=false
```

Never commit HackerOne credentials or dashboard secrets.

## Local development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
```

Run tests:

```bash
pytest -q
```

Run the dashboard locally:

```bash
uvicorn api.index:app --reload
```

## Important limitation

This project can automate a substantial amount of authorized reconnaissance, evidence collection, hypothesis generation, and report drafting, but **no software can guarantee that every hunt produces a valid paid vulnerability**. A candidate becomes a real report only after the evidence is independently reproducible and the current program rules permit the activity.

That distinction is intentional: the agent optimizes for reproducible security evidence rather than manufacturing findings to make the dashboard look successful.


## 2026-09-27 Hunt Results

Recent authorized, low-impact bounty research recorded on `main`:
- Amazon VRP: no verified reflected XSS or external redirect on tested public/app surfaces.
- Elastic VRP: 321 `*.elastic.co` certificate names reviewed; no verified subdomain takeover. `eden.elastic.co` was confirmed to redirect from its S3 website endpoint to `demo.prod.sa.elastic.co`, so it is not a dangling bucket.
- GitHub VRP: redirect-bearing public pages rejected the external canary; public search rendering returned no JavaScript execution across code/issues/repository/global search probes.
- Current status: no confirmed bounty finding from these passes. Do not submit speculative reports.
