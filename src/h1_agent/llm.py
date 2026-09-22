from __future__ import annotations

import json
import os

import httpx

from .config import Settings


class LLMClient:
    """Small provider adapter: local Ollama, Hugging Face router, or OpenAI-compatible APIs."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.provider = settings.llm_provider.strip().lower()
        self.base_url = settings.llm_base_url.rstrip("/")
        self.model = settings.llm_model

    def _gateway_token(self) -> str:
        return self.settings.llm_api_key or os.getenv("VERCEL_OIDC_TOKEN", "")

    def available(self) -> bool:
        if self.provider in {"vercel_gateway", "ai_gateway"}:
            return bool(self._gateway_token())
        if self.provider == "ollama":
            try:
                return httpx.get(f"{self.base_url}/api/tags", timeout=3).is_success
            except httpx.HTTPError:
                return False
        if self.provider == "huggingface":
            return bool(self.settings.hf_token)
        if self.provider in {"openai", "openai_compatible"}:
            return bool(self.settings.llm_api_key)
        return False

    def generate(self, prompt: str) -> str:
        if self.provider in {"vercel_gateway", "ai_gateway"}:
            token = self._gateway_token()
            if not token:
                raise RuntimeError(
                    "Vercel AI Gateway authentication is unavailable. Enable Vercel OIDC for the project or set AI_GATEWAY_API_KEY."
                )
            response = httpx.post(
                self.base_url.rstrip("/") + "/chat/completions",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.05,
                    "max_tokens": 1600,
                    "stream": False,
                },
                timeout=180,
            )
            response.raise_for_status()
            data = response.json()
            return str(data["choices"][0]["message"]["content"])

        if self.provider == "ollama":
            response = httpx.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.05},
                },
                timeout=180,
            )
            response.raise_for_status()
            return str(response.json().get("response", ""))

        if self.provider == "huggingface":
            response = httpx.post(
                "https://router.huggingface.co/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.settings.hf_token}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.05,
                    "max_tokens": 1600,
                    "stream": False,
                },
                timeout=180,
            )
            response.raise_for_status()
            data = response.json()
            return str(data["choices"][0]["message"]["content"])

        if self.provider in {"openai", "openai_compatible"}:
            response = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.settings.llm_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.05,
                    "max_tokens": 1600,
                    "stream": False,
                },
                timeout=180,
            )
            response.raise_for_status()
            data = response.json()
            return str(data["choices"][0]["message"]["content"])

        raise ValueError(f"Unsupported LLM_PROVIDER: {self.provider}")

    def json(self, prompt: str) -> dict:
        text = self.generate(prompt)
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("Model did not return JSON")
        return json.loads(text[start : end + 1])

    def draft_finding(self, program_handle: str, target: str, evidence: list[dict]) -> dict:
        prompt = f"""
You are an evidence-grounded assistant in an authorized bug bounty workflow.

Use ONLY the supplied evidence. Never invent endpoints, parameters, permissions, exploitability,
impact, reproduction steps, CVSS values, CWE IDs, references, or remediation details.

The human researcher must independently reproduce and validate the issue before submission.

Return JSON with these keys:
status,title,summary,impact,reproduction,severity,confidence,missing_validation,
weakness_id,cvss_score,cvss_vector,affected_component,preconditions,
observed_behavior,expected_behavior,attack_scenario,remediation,references

Rules:
- status must be one of: candidate, needs_review, no_finding.
- severity must be one of: none, low, medium, high, critical, or null.
- confidence must be a number from 0 to 1.
- weakness_id may be null when the evidence does not support a specific HackerOne weakness.
- cvss_score/cvss_vector may be null/empty unless the evidence and human review support them.
- references must contain only URLs or references actually present in the evidence.
- Every technical claim must be traceable to the evidence.
- Do not turn a missing security header or informational metadata into a bounty candidate by itself.
- Use status=candidate only when the supplied evidence itself demonstrates a plausible security-relevant condition.
- Otherwise use no_finding or needs_review.
- Keep reproduction concrete and minimal; do not invent steps that were not performed.
- affected_component, preconditions, observed_behavior, expected_behavior, attack_scenario, and remediation
  must be empty/null when they cannot be established from the evidence.

PROGRAM={program_handle}
TARGET={target}
EVIDENCE={json.dumps(evidence, indent=2)}
"""
        return self.json(prompt)
    def research_plan(self, program_handle: str, policy: str, scopes: list[dict], exclusions: dict) -> dict:
        prompt = f"""
Create a conservative research plan for an authorized HackerOne program.
Use only supplied policy/scope. Prefer passive or low-impact actions. Do not infer permission.
Return JSON keys: priorities,allowed_actions,prohibited_or_uncertain,human_checks,evidence_to_capture.
PROGRAM={program_handle}
POLICY={policy[:12000]}
SCOPES={json.dumps(scopes, indent=2)}
EXCLUSIONS={json.dumps(exclusions, indent=2)[:12000]}
"""
        return self.json(prompt)
