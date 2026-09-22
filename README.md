# H1 Bounty Agent

AI-assisted HackerOne research workspace with strict scope gates and a mandatory human validation step.

> **Safety / platform rule:** This project is an assistant for authorized security research. It must never test an asset unless the relevant HackerOne program explicitly permits the activity. It does not bypass authentication, evade rate limits, or submit findings without human validation.

## Current status

- HackerOne API client foundation
- Program/scope cache
- Strict in-scope URL validation
- Local SQLite workspace
- LLM abstraction for research planning/report drafting
- Human validation gate
- Dry-run by default
- Automated unit tests

## Zero-cash starting plan

The project is designed to run locally using free/open-source tooling where practical. No paid model is required by the core architecture. Any external API, model, or infrastructure with a cost must be explicitly configured by the operator.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
```

Add your HackerOne API credentials to `.env`. **Never commit credentials.**

Run:

```bash
python -m h1_agent.cli --help
python -m h1_agent.cli programs
python -m pytest
```

## Architecture

```text
HackerOne API
     |
     v
Program/scope cache
     |
     v
Opportunity planner
     |
     v
Authorized research adapters
     |
     v
Evidence + verification engine
     |
     v
Report draft
     |
     v
HUMAN VALIDATION GATE
     |
     v
Optional submission adapter
```

The validation gate is intentionally impossible to skip through normal application flow.

## Configuration

See `.env.example`. Keep secrets outside source control.

## Disclaimer

Use only against assets and programs where you have explicit authorization. HackerOne program policies are authoritative for each target. This software does not guarantee findings, acceptance, or bounty income.
