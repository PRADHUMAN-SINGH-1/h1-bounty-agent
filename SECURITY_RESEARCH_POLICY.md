# Security Research Contract

This repository implements an evidence-first HackerOne workflow. The contract below is enforced by configuration and finding validation.

## 1. Authorization and scope

- A HackerOne program must be explicitly authorized by the caller or by `RESEARCH_PROGRAM_ALLOWLIST`.
- Before target research, fetch the current program policy and structured scope.
- Fetch scope exclusions and program weaknesses before treating a target as research-ready.
- Only assets that are explicitly eligible for submission and bounty may be selected as bounty targets.
- Program-specific instructions are a hard stop until reviewed.
- Discovery does not grant permission to test an asset.

## 2. Research order

1. Program policy
2. Structured allowlist
3. Exclusions/instructions
4. Passive reconnaissance
5. Low-impact validation permitted by the policy
6. Authenticated authorization tests only with explicitly authorized researcher-controlled accounts
7. Evidence triage
8. Duplicate screening
9. Reproduction/impact gate
10. Human review
11. Submission

## 3. Confirmation gate

A finding is `CONFIRMED` only when the evidence records all of the following:

- the vulnerable behavior was reproduced;
- the relevant security boundary was actually crossed;
- the security impact was demonstrated using minimum safe proof;
- the result is repeatable;
- the exact target is in scope;
- duplicate screening was completed and found no matching disclosure.

Source-code suspicion, a scanner hit, a reflected marker, an unusual response, a matching regex, or a theoretical attack path never satisfies this gate by itself.

## 4. Evidence

Evidence should contain the exact URL, HTTP method, parameters, relevant request/response details, account/role context, before/after behavior, timestamps where useful, and sanitized logs or screenshots. Do not collect another customer's data. Use researcher-controlled or synthetic data for impact proof.

## 5. Explicit non-goals

The workflow must not perform credential theft/brute forcing, phishing/social engineering, fraudulent transactions, persistence, malware deployment, destructive actions, DoS/DDoS, bulk data extraction, or out-of-scope testing.

## 6. Submission gate

`H1_ENABLE_SUBMISSION` is disabled by default and the deployment template keeps it disabled. Even if submission is enabled, `validate_finding()` blocks any finding that is not `CONFIRMED` by the structured reproduction gate. Human approval remains required before HackerOne submission.

## 7. Truthful statuses

Use only:

- `CONFIRMED`
- `UNCONFIRMED`
- `FALSE POSITIVE`
- `DUPLICATE`
- `OUT OF SCOPE`

Only `CONFIRMED` findings can become submission-ready. Unconfirmed findings must identify the missing proof and the safest validation method rather than being presented as successful vulnerabilities.

## 8. Severity

Severity must follow the demonstrated attack path and actual impact. The system must not infer critical severity from theoretical worst-case impact, scanner labels, or model confidence alone.
