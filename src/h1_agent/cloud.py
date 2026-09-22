from __future__ import annotations

import json
import re

from .models import Evidence


ARN_RE = re.compile(r"arn:aws:[A-Za-z0-9_-]+:[^\\s\"']+")
AZURE_RE = re.compile(r"https://[A-Za-z0-9.-]+\\.blob\\.core\\.windows\\.net(?:/[^\\s\"']*)?")
GCP_RE = re.compile(r"[A-Za-z0-9._-]+\\.storage\\.googleapis\\.com")


def analyze_cloud_text(text: str, source: str) -> tuple[dict, list[Evidence]]:
    arns = sorted(set(ARN_RE.findall(text)))[:100]
    azure = sorted(set(AZURE_RE.findall(text)))[:100]
    gcp = sorted(set(GCP_RE.findall(text)))[:100]

    findings = []
    if re.search(r'"Action"\\s*:\\s*"\\*"', text) and re.search(r'"Resource"\\s*:\\s*"\\*"', text):
        findings.append("wildcard_cloud_policy")

    result = {
        "aws_arns": arns,
        "azure_storage_urls": azure,
        "gcp_storage_hosts": gcp,
        "policy_observations": findings,
    }
    evidence = [
        Evidence("cloud_aws_arn_count", str(len(arns)), source),
        Evidence("cloud_azure_url_count", str(len(azure)), source),
        Evidence("cloud_gcp_host_count", str(len(gcp)), source),
        Evidence("cloud_policy_observations", json.dumps(findings), source),
    ]
    return result, evidence
