# H1 Bounty Agent

AI-assisted HackerOne research workspace designed to automate the repetitive parts of authorized bug-bounty research while keeping the required human validation gate.

## What it does

```text
HackerOne API
     ↓
Program discovery + scope cache
     ↓
Opportunity triage
     ↓
Scope gate
     ↓
Low-impact research checks
     ↓
Evidence collection
     ↓
Local LLM analysis / report draft
     ↓
Human validation
     ↓
Explicit approval
     ↓
Optional HackerOne submission
```

The project is intentionally **fail-closed**. A target must match an eligible structured scope before the research engine can send target traffic.

## Current v0.2

- HackerOne Hacker API client
- Program discovery and scope retrieval
- URL/domain/wildcard scope validation with URL-path awareness
- Local SQLite research workspace
- Local Ollama LLM integration
- Low-impact HTTP evidence collection
- Evidence-grounded finding drafting
- Human review checklist
- Explicit approval state
- Submission flag + `--confirmed` gate
- GitHub Actions CI

## Zero-cash start

The initial architecture can run using your existing machine and a local Ollama model, avoiding per-request LLM charges. You may later add paid compute/models only after the system has demonstrated useful results. This does **not** guarantee bounty income.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
```

Put your HackerOne API credentials in `.env`. Never commit the file or token.

## Workflow

### 1. Discover programs

```bash
h1-agent discover --limit 15
```

This only queries HackerOne. It does not touch target systems.

### 2. Inspect a program

```bash
h1-agent program <handle>
```

### 3. Generate a research plan

```bash
h1-agent plan <handle>
```

Requires local Ollama.

### 4. Check a target without sending traffic

```bash
h1-agent dry-run <handle> https://target.example/
```

### 5. Run low-impact research

Only after reviewing the current program policy and confirming that this activity is permitted:

```text
ALLOW_ACTIVE_TESTS=true
```

Then:

```bash
h1-agent research <handle> https://target.example/ --active
```

The first research engine only performs low-impact HTTP metadata collection: the target URL, `robots.txt`, `security.txt`, `sitemap.xml`, and an OPTIONS metadata request. Program-specific asset instructions trigger a manual review rather than being guessed by the software.

### 6. Review candidate findings

```bash
h1-agent findings
h1-agent review <finding-id>
```

### 7. Validate and approve yourself

Only after personally reproducing the behavior and checking scope, policy, evidence, impact, and duplicate/exclusion rules:

```bash
h1-agent approve <finding-id>
```

### 8. Submit only after approval

Keep this disabled until you are ready:

```text
H1_ENABLE_SUBMISSION=true
```

Then:

```bash
h1-agent submit <finding-id> --team-handle <handle> --severity <level> --confirmed
```

The application refuses submission unless the finding is approved.

## What the AI does vs. what you do

**AI / automation:** program discovery, scope loading, research planning, low-impact evidence collection, evidence-grounded draft generation, local history, report formatting.

**You:** review program rules, reproduce and validate a potential vulnerability, verify impact/evidence, check duplicates/exclusions, choose/confirm severity, and explicitly approve submission.

That split is deliberate. HackerOne currently requires a human-in-the-loop for Hackbots and says AI-assisted submissions remain the researcher’s responsibility. It also prohibits unverified/fabricated findings and unsafe or out-of-scope testing.

## Safety boundary

The agent does not provide an unrestricted internet scanner or blind autonomous exploitation. It must operate only against authorized scope, respect program-specific limits, avoid unsafe testing, and keep submission behind human approval.

## Income expectations

A bounty is not earned merely because the agent runs. A result must be real, reproducible, in scope, eligible, sufficiently demonstrated, and accepted by the program. Treat this as an automation/research system, not guaranteed passive income.

## Roadmap

1. Program and scope intelligence ✅
2. Low-impact research engine ✅
3. Evidence-grounded LLM finding draft ✅
4. Human validation gate ✅
5. Submission gate ✅
6. Research plugin framework: authorization-aware checks per vulnerability class
7. Duplicate/history correlation
8. Better opportunity telemetry from your own accepted/rejected results
9. Earnings and report-state synchronization
10. Optional background scheduler after local validation and stable policy controls
