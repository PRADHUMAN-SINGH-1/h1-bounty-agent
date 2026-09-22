from __future__ import annotations

import json
import httpx

from .config import Settings


class LocalLLM:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.base_url = settings.llm_base_url.rstrip("/")
        self.model = settings.llm_model

    def available(self) -> bool:
        if self.settings.llm_provider != "ollama":
            return False
        try:
            return httpx.get(f"{self.base_url}/api/tags", timeout=3).is_success
        except httpx.HTTPError:
            return False

    def generate(self, prompt: str) -> str:
        response = httpx.post(
            f"{self.base_url}/api/generate",
            json={"model": self.model, "prompt": prompt, "stream": False, "options": {"temperature": 0.05}},
            timeout=180,
        )
        response.raise_for_status()
        return str(response.json().get("response", ""))

    def json(self, prompt: str) -> dict:
        text = self.generate(prompt)
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("Local model did not return JSON")
        return json.loads(text[start:end + 1])

    def draft_finding(self, program_handle: str, target: str, evidence: list[dict]) -> dict:
        prompt = f"""
You are an evidence-grounded assistant in an authorized bug bounty workflow.
Use ONLY the evidence below. Never invent endpoints, parameters, impact, or exploit steps.
When evidence is insufficient, return status=needs_review.
Return JSON keys: status,title,summary,impact,reproduction,severity,confidence,missing_validation.
severity must be none, low, medium, high, or critical.
PROGRAM={program_handle}
TARGET={target}
EVIDENCE={json.dumps(evidence, indent=2)}
"""
        return self.json(prompt)

    def research_plan(self, program_handle: str, policy: str, scopes: list[dict], exclusions: dict) -> dict:
        prompt = f"""
Create a conservative research plan for an authorized HackerOne program.
Use only supplied policy/scope. Prefer passive or low-impact actions. Do not invent permission.
Return JSON keys: priorities,allowed_actions,prohibited_or_uncertain,human_checks,evidence_to_capture.
PROGRAM={program_handle}
POLICY={policy[:12000]}
SCOPES={json.dumps(scopes, indent=2)}
EXCLUSIONS={json.dumps(exclusions, indent=2)[:12000]}
"""
        return self.json(prompt)
