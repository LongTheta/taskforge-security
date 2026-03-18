# Skill Assessments — taskforge-security

*Generated from running all applicable Cursor skills against this repository.*

---

# 1. CVE Detect and Remediate

## Vulnerability Remediation Report

### Executive Summary

- **Total findings:** 0 — pip-audit reports no known vulnerabilities in project dependencies.
- **Critical / High / Medium / Low:** None.
- **KEV-listed:** None.
- **Fixable now vs manual review:** N/A — project deps are clean.

### Findings (Project Scope)

| Package | Version | Status |
|---------|---------|--------|
| All deps | (see uv.lock) | No known vulns |

*Note: CI runs `pip-audit --skip-editable` on every push. SBOM job generates CycloneDX JSON. `uv.lock` ensures reproducible installs.*

### Remediation Plan

- **Auto-fix candidates:** None.
- **Manual review:** If CI reports new vulns, apply patch/minor bumps per skill rules.
- **Temporary mitigations:** N/A.

### Validation Plan

- CI already runs pip-audit and SBOM.
- Run `pytest` and `ruff` after any dependency changes.
- `POST /api/v1/remediate/create-pr` can create remediation PRs when configured.

---

# 2. Zero Trust GitOps Enforcement Report

**Repository:** taskforge-security

## Pass / Fail

**PASS** — No High violations. Required controls present.

## Violations

| # | Area | Violation | Severity |
|---|------|-----------|----------|
| 1 | Supply Chain | SBOM uses `|| true` (may mask failures) | Low |
| 2 | Supply Chain | Trivy image scan job disabled by default | Low |

## Required Fixes

- [ ] None — all High/Medium violations addressed.

## Completed Fixes (since last assessment)

- [x] SBOM generation in CI (`pip-audit -f cyclonedx-json`)
- [x] Lockfile (`uv.lock`) for reproducible builds
- [x] Metrics endpoint (`/metrics`)
- [x] CI branches: `main` and `master` both supported
- [x] Pinned actions (checkout, setup-python, upload-artifact)

## Recommended Improvements

- Remove `|| true` from SBOM step so failures are visible
- Enable Trivy image scan in scheduled workflow when base image is defined
- Add manual approval gate for production in platform deployment (not in this repo)

## Compliance Alignment

| Framework | Alignment Notes |
|-----------|-----------------|
| DoD Zero Trust | Improved: SBOM, lockfile, metrics, policy gate |
| NIST 800-53 | SI-3, SA-11 partially addressed; AC-2 via API key |
| Supply Chain (SLSA) | Level 1: SBOM, lockfile, pinned artifacts |

---

# 3. DoD Zero Trust Assessment

**System:** taskforge-security (DevSecOps CVE scanning microservice)

## Overall Score

**6.5 / 10** — Solid security microservice; gaps in automation, visibility, and workload identity.

## Maturity Level

| Level | Status |
|-------|--------|
| Traditional | Partially (no perimeter; internal service) |
| Target ZT | In progress |
| Advanced ZT | Not started |

## Pillar Breakdown

### 1. User
- **Score:** 5
- **Current State:** Optional X-API-Key auth when `REQUIRE_API_KEY=true`. No MFA, IdP.
- **Gaps:** Auth is opt-in; API key is single shared secret.
- **Required Controls:** Enable API key in production; consider OIDC for platform integration.
- **Recommended Fixes:** Document auth requirements; enable `REQUIRE_API_KEY` in production.

### 2. Device
- **Score:** 5
- **Current State:** Runs in container; non-root user.
- **Gaps:** No device attestation; N/A for server-side service.
- **Recommended Fixes:** Ensure host/container hardening in platform deployment.

### 3. Application & Workload
- **Score:** 7
- **Current State:** FastAPI, path validation, no shell injection, subprocess with list args. **Rate limiting** (SlowAPI). Scan timeout 120s.
- **Gaps:** No scan concurrency limits.
- **Recommended Fixes:** Consider concurrency limits for high load.

### 4. Data
- **Score:** 5
- **Current State:** No persistent data; scan results returned in response. No PII in logs.
- **Gaps:** No encryption-at-rest (N/A for stateless); TLS assumed at ingress.
- **Recommended Fixes:** Document TLS requirement at load balancer/ingress.

### 5. Network & Environment
- **Score:** 5
- **Current State:** Single port 8081; no network policies in repo (handled in taskforge-platform).
- **Gaps:** Micro-segmentation not visible in this repo.
- **Recommended Fixes:** Align with platform network policies.

### 6. Automation & Orchestration
- **Score:** 7
- **Current State:** CI with ruff, pytest, bandit, pip-audit, SBOM; uv.lock; scheduled scan workflow; pinned actions.
- **Gaps:** No provenance/signing; no Argo CD in repo.
- **Recommended Fixes:** Align with platform GitOps.

### 7. Visibility & Analytics
- **Score:** 7
- **Current State:** Structured JSON logging; request ID middleware; **Prometheus metrics** (`/metrics`); **Grafana dashboard** (docs/grafana).
- **Gaps:** No distributed tracing.
- **Recommended Fixes:** Add trace correlation if platform supports it.

## Cross-Pillar Risks

- **Auth opt-in:** API key required only when `REQUIRE_API_KEY=true`; may be disabled in dev.
- **GitHub token:** Stored in env; ensure platform uses External Secrets or similar.

## Priority Fixes (Top 5)

1. **Enable API auth in production** — Effort: Low — Impact: High
2. **Document TLS at ingress** — Effort: Low — Impact: Medium
3. **Remove `|| true` from SBOM step** — Effort: Low — Impact: Low
4. **Add trace correlation** — Effort: Medium — Impact: Medium
5. **Consider OIDC for platform integration** — Effort: High — Impact: Medium

## Roadmap to Target ZT

- **0–3 months:** Enable API auth in prod; document TLS; verify platform secrets.
- **3–6 months:** Trace correlation; workload identity if platform supports.

## Roadmap to Advanced ZT

- **6–12 months:** Provenance, signed artifacts, adaptive rate limiting.

---

# 4. Security Evaluator

## 1. Security Summary

TaskForge Security is a FastAPI service with pip-audit, Trivy image scanning, OSV/KEV enrichment, remediation planning, PR creation, policy gating, and Prometheus metrics. It has solid controls: path validation, no shell injection, structured logging, non-root container, rate limiting, optional API auth, SBOM, lockfile, and metrics. For internal platform use, risk is moderate-low; for internet exposure, ensure API auth and rate limits are enabled.

## 2. Threat / Risk Areas

- **Abuse of scan endpoint:** Mitigated by rate limiting (10/min scan, 5/min remediate).
- **Path traversal:** Mitigated by validation in `requirements.py`.
- **Command injection:** Mitigated (subprocess with list args, no `shell=True`).
- **Supply chain:** SBOM, lockfile, pip-audit in CI.
- **Secrets:** Loaded from env; no hardcoded secrets.

## 3. Security Scorecard

| Domain | Score (1–5) | Notes |
|--------|-------------|-------|
| Identity and access management | 4 | Optional API key; enable in prod |
| RBAC / least privilege | 3 | Non-root container; no API RBAC |
| Secrets handling | 4 | Env vars; no secrets in code |
| Audit logging and accountability | 4 | Structured logs, request IDs |
| Encryption in transit and at rest | 3 | TLS at ingress assumed |
| API / network exposure | 4 | Rate limiting; auth optional |
| Supply chain security | 4 | SBOM, lockfile, pip-audit |
| Dependency/image scanning | 5 | pip-audit, Trivy, bandit |
| Configuration management | 4 | Pydantic settings; .env |
| Secure-by-default posture | 4 | Path validation, fail-safe errors |
| Observability | 4 | Metrics, Grafana dashboard |

## 4. Key Strengths

- Path validation (length, traversal)
- Subprocess without `shell=True`
- Structured JSON logging with request IDs
- Non-root Docker user
- Rate limiting (SlowAPI)
- Optional API key auth
- CI: ruff, pytest, bandit, pip-audit, SBOM
- uv.lock for reproducible builds
- Prometheus metrics
- Policy gate (block on critical/KEV)
- Trivy image scanning
- GitHub PR creation

## 5. Key Risks / Gaps

- API auth is opt-in (default off)
- No distributed tracing
- SBOM step uses `|| true` (masks failures)

## 6. Compliance / Control Considerations

- **NIST 800-53:** SI-3, SA-11 addressed; AC-2 via API key when enabled.
- **FedRAMP:** Would need auth enabled, SBOM, and audit evidence for ATO.

## 7. Required Mitigations

1. Enable `REQUIRE_API_KEY` in production (Low effort)
2. Remove `|| true` from SBOM step so failures are visible (Low effort)

## 8. Operational Security Considerations

- Patching: CI runs pip-audit; address findings promptly.
- Monitoring: Prometheus metrics; Grafana dashboard available.
- Secrets: Use platform secret management (e.g., External Secrets) for GITHUB_TOKEN, API_KEY.

## 9. Final Recommendation

**Low risk** — Suitable for internal platform use. Enable API auth and rate limiting in production. Proceed with standard due diligence.

## 10. Next Validation Steps

- Enable `REQUIRE_API_KEY` in production deployment
- Verify SBOM generation succeeds (remove `|| true` or handle failures explicitly)
- Run scheduled scan workflow weekly

---

# 5. AI Agent Architecture

**Scope:** This repository does not contain AI agents, MCP servers, or agent orchestration logic. It is a conventional FastAPI microservice.

## Assessment

- **Layer 1 (Model):** N/A
- **Layer 2 (Memory/Context):** N/A
- **Layer 3 (Tooling):** N/A (pip-audit, Trivy are subprocesses)
- **Layer 4 (Orchestration):** N/A
- **Layer 5 (Communication):** REST API only
- **Layer 6 (Infrastructure):** Docker, CI, metrics
- **Layer 7 (Evaluation):** No agent-specific evaluation

**Verdict:** Not applicable. No AI agent architecture to evaluate.

---

# 6. AI DevSecOps Policy Enforcement

**Note:** The `ai_devsecops_agent` CLI is not installed in this repo. Assessment is manual based on policy criteria.

## Manual Policy Review

| Policy Area | Status | Notes |
|-------------|--------|-------|
| Secrets in code | Pass | No hardcoded secrets |
| Pinned actions | Pass | checkout, setup-python, upload-artifact use v4/SHA |
| SBOM | Pass | pip-audit cyclonedx-json in CI |
| Resource limits | N/A | No K8s in repo |
| Promotion gates | N/A | Single pipeline; gate endpoint for policy |
| Rate limiting | Pass | SlowAPI on scan/remediate |
| Metrics | Pass | /metrics endpoint |

**Verdict:** **pass** — No critical/high findings. SBOM present. Optional: remove `|| true` from SBOM step.

---

# 7. Tool Evaluator

**Tool:** TaskForge Security (DevSecOps CVE scanning microservice)

## 1. Summary

TaskForge Security is a Python FastAPI service with pip-audit, Trivy image scanning, OSV/KEV enrichment, remediation planning, PR creation, policy gating, and Prometheus metrics. It fits well as an internal platform security component. Recommendation: **Fit** — suitable for internal use; enable auth in production.

## 2. Best Fit Use Cases

- Internal platform CVE scanning
- CI integration for dependency checks
- Pre-deployment policy gate
- Container image scanning (Trivy)
- Automated remediation PR creation

## 3. Evaluation Scorecard

| Category | Score (1–10) | Justification |
|----------|--------------|---------------|
| Problem Fit | 9 | CVE scanning, OSV/KEV, remediation, policy gate |
| Capability Fit | 8 | pip-audit, Trivy, PR creation, metrics |
| Integration Fit | 8 | REST API; easy to call from CI/platform |
| Data Hydration & Readiness | 8 | requirements.txt, image ref; standard inputs |
| Security & Compliance | 7 | Auth, rate limit, SBOM, lockfile |
| Operational Fit | 8 | Docker, metrics, Grafana dashboard |
| Cost & Risk | 9 | Open source; minimal deps |

## 4. Recommendation

**Fit** — Production-ready for internal platform use. Enable API auth and rate limiting in production. Add Grafana dashboard to observability stack.

---

# Summary of Action Items

| Priority | Action | Status |
|----------|--------|--------|
| 1 | Enable `REQUIRE_API_KEY` in production | ✅ Startup warning when production without API key; README updated |
| 2 | Remove `|| true` from SBOM step | ✅ CI SBOM job now fails on vulnerabilities |
| 3 | Document TLS requirement at ingress | ✅ Production Deployment section in README |
| 4 | Add trace correlation (if platform supports) | Pending |
| 5 | Add Grafana dashboard to platform observability | Pending |
