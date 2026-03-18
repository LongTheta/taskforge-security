# Skill Assessments — taskforge-security

*Generated from running all applicable skills against this repository.*

---

# 1. CVE Detect and Remediate

## Vulnerability Remediation Report

### Executive Summary

- **Total findings (project deps):** Declared dependencies in `pyproject.toml` are minimal and well-pinned (fastapi, uvicorn, pydantic, pydantic-settings, python-json-logger, pip-audit). CI runs `pip-audit --skip-editable` on every push.
- **Critical / High / Medium / Low:** Project deps appear clean; CI would fail on new vulns.
- **KEV-listed:** None identified in declared project dependencies.
- **Fixable now vs manual review:** Project is in good shape; no immediate remediation needed for declared deps.

### Findings (Project Scope)

| Package | Version | Status |
|---------|---------|--------|
| fastapi | ≥0.109.0 | Declared, no known vulns in typical range |
| uvicorn | ≥0.27.0 | Declared |
| pydantic | ≥2.5.0 | Declared |
| pydantic-settings | ≥2.1.0 | Declared |
| python-json-logger | ≥2.0.0 | Declared |
| pip-audit | ≥2.6.0 | Declared |

*Note: Local `pip-audit` run may report vulns from the global Python environment (e.g., langchain, tornado, pillow). Those are outside this project's declared dependencies.*

### Remediation Plan

- **Auto-fix candidates:** None for project deps.
- **Manual review:** If CI reports new vulns, apply patch/minor bumps per skill rules.
- **Temporary mitigations:** N/A.

### Validation Plan

- CI already runs `pip-audit --skip-editable`.
- Run `pytest` and `ruff` after any dependency changes.

---

# 2. Zero Trust GitOps Enforcement Report

**Repository:** taskforge-security

## Pass / Fail

**FAIL** — Medium violations present; no High violations.

## Violations

| # | Area | Violation | Severity |
|---|------|------------|----------|
| 1 | Supply Chain | No SBOM generation in CI | Medium |
| 2 | Supply Chain | Dependencies use version ranges (≥) not pinned digests | Medium |
| 3 | Observability | No explicit metrics endpoint; logs are structured | Low |
| 4 | Identity | CI uses default GitHub Actions identity; no OIDC/workload identity | Low |

## Required Fixes

- [ ] Add SBOM generation step (e.g., `pip-audit --format cyclonedx-json` or syft) to CI
- [ ] Consider lockfile (e.g., `pip freeze` or `uv lock`) for reproducible builds

## Recommended Improvements

- Pin GitHub Actions to full SHA digests (already done for checkout and setup-python)
- Add Trivy or Grype for container image scanning in CI
- Document promotion path (dev → prod) when platform repo is integrated

## Compliance Alignment

| Framework | Alignment Notes |
|-----------|------------------|
| DoD Zero Trust | Partial: path validation, no shell injection, structured logs; missing SBOM |
| NIST 800-53 | SI-3 (malicious code), SA-11 (developer security) partially addressed |
| Supply Chain (SLSA) | Level 0–1: no provenance, no SBOM |

---

# 3. DoD Zero Trust Assessment

**System:** taskforge-security (DevSecOps CVE scanning microservice)

## Overall Score

**5.5 / 10** — Usable security microservice with solid basics; gaps in supply chain, automation, and visibility.

## Maturity Level

| Level | Status |
|-------|--------|
| Traditional | Partially (no perimeter; internal service) |
| Target ZT | In progress |
| Advanced ZT | Not started |

## Pillar Breakdown

### 1. User
- **Score:** 4
- **Current State:** No direct user auth; service is internal. No MFA, IdP.
- **Gaps:** No auth on scan endpoint; assumes trusted caller.
- **Required Controls:** API auth (API key, OIDC) when exposed beyond platform.
- **Recommended Fixes:** Add API key or service-account auth before production exposure.

### 2. Device
- **Score:** 5
- **Current State:** Runs in container; non-root user.
- **Gaps:** No device attestation; N/A for server-side service.
- **Recommended Fixes:** Ensure host/container hardening in platform deployment.

### 3. Application & Workload
- **Score:** 6
- **Current State:** FastAPI, path validation, no shell injection, subprocess with list args.
- **Gaps:** No rate limiting; scan endpoint can be abused for resource exhaustion.
- **Required Controls:** Rate limiting, scan timeout (present: 120s).
- **Recommended Fixes:** Add rate limiting middleware; consider scan concurrency limits.

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
- **Score:** 6
- **Current State:** CI with ruff, pytest, bandit, pip-audit; pinned actions.
- **Gaps:** No SBOM; CI triggers on `main` but repo uses `master` (branch mismatch).
- **Required Controls:** Fix CI branch trigger; add SBOM step.
- **Recommended Fixes:** Change CI `on.push.branches` to `[master]` or rename branch to `main`.

### 7. Visibility & Analytics
- **Score:** 6
- **Current State:** Structured JSON logging; request ID middleware; duration in headers.
- **Gaps:** No metrics endpoint; no Prometheus/Grafana integration in repo.
- **Recommended Fixes:** Add `/metrics` or rely on platform observability.

## Cross-Pillar Risks

- **Branch mismatch:** CI on `main`, repo on `master` → CI may not run on pushes.
- **No SBOM:** Limits supply chain visibility and policy enforcement.

## Priority Fixes (Top 5)

1. **Fix CI branch trigger** — Effort: Low — Impact: High (CI may not run)
2. **Add SBOM generation** — Effort: Low — Impact: Medium
3. **Add API auth for scan endpoint** — Effort: Medium — Impact: High (when exposed)
4. **Add rate limiting** — Effort: Low — Impact: Medium
5. **Add lockfile for reproducible builds** — Effort: Low — Impact: Medium

## Roadmap to Target ZT

- **0–3 months:** Fix CI branch; add SBOM; document TLS/auth requirements.
- **3–6 months:** Add auth middleware; rate limiting; align with platform observability.

## Roadmap to Advanced ZT

- **6–12 months:** Provenance, signed artifacts, adaptive rate limiting.

---

# 4. Security Evaluator

## 1. Security Summary

TaskForge Security is a minimal FastAPI service that scans `requirements.txt` files for CVEs via pip-audit. It has solid basics: path validation, no shell injection, structured logging, non-root container, and CI security checks. Gaps include no API authentication, no rate limiting, no SBOM generation, and a CI branch mismatch. For internal platform use with network isolation, risk is moderate; for internet exposure, additional controls are required.

## 2. Threat / Risk Areas

- **Abuse of scan endpoint:** Unbounded scans can exhaust CPU/memory.
- **Path traversal:** Mitigated by validation in `requirements.py`.
- **Command injection:** Mitigated (subprocess with list args, no `shell=True`).
- **Supply chain:** No SBOM; dependency ranges (≥) not pinned.
- **CI not running:** Branch mismatch (`main` vs `master`).

## 3. Security Scorecard

| Domain | Score (1–5) | Notes |
|--------|-------------|-------|
| Identity and access management | 2 | No auth on endpoints |
| RBAC / least privilege | 3 | Non-root container; no API RBAC |
| Secrets handling | 4 | No secrets in code; .env in .gitignore |
| Audit logging and accountability | 4 | Structured logs, request IDs |
| Encryption in transit and at rest | 3 | TLS at ingress assumed; no at-rest (stateless) |
| API / network exposure | 3 | No rate limiting; single port |
| Supply chain security | 3 | pip-audit in CI; no SBOM |
| Dependency/image scanning | 4 | pip-audit, bandit in CI |
| Configuration management | 4 | Pydantic settings; .env |
| Secure-by-default posture | 4 | Path validation, fail-safe errors |

## 4. Key Strengths

- Path validation (length, traversal) in `requirements.py`
- Subprocess without `shell=True`
- Structured JSON logging with request IDs
- Non-root Docker user
- CI: ruff, pytest, bandit, pip-audit
- Pinned GitHub Actions (SHA)
- Clean error handling (no stack traces to clients)

## 5. Key Risks / Gaps

- No API authentication
- No rate limiting
- CI triggers on `main`; repo uses `master`
- No SBOM generation
- Unpinned dependency versions (≥)

## 6. Compliance / Control Considerations

- **NIST 800-53:** SI-3, SA-11 partially addressed; AC-2, AC-17 need auth when exposed.
- **FedRAMP:** Would need auth, SBOM, and audit evidence for ATO.

## 7. Required Mitigations

1. Fix CI branch trigger (Low effort)
2. Add SBOM step to CI (Low effort)
3. Add API auth before production exposure (Medium effort)
4. Add rate limiting (Low effort)

## 8. Operational Security Considerations

- Patching: CI runs pip-audit; address findings promptly.
- Monitoring: Rely on platform (taskforge-observability) for metrics/alerts.
- Secrets: Use platform secret management (e.g., External Secrets) when needed.

## 9. Final Recommendation

**Moderate risk with controls** — Suitable for internal platform use with network isolation. Before broader or internet exposure: add API auth, rate limiting, and SBOM.

## 10. Next Validation Steps

- Confirm CI runs on `master` (or align branch names)
- Run `pip-audit` in project venv to validate declared deps only
- Add integration test with real `requirements.txt` containing known-vulnerable package

---

# 5. AI Agent Architecture

**Scope:** This repository does not contain AI agents, MCP servers, or agent orchestration logic. It is a conventional FastAPI microservice.

## Assessment

- **Layer 1 (Model):** N/A
- **Layer 2 (Memory/Context):** N/A
- **Layer 3 (Tooling):** N/A (pip-audit is a subprocess, not an agent tool)
- **Layer 4 (Orchestration):** N/A
- **Layer 5 (Communication):** REST API only
- **Layer 6 (Infrastructure):** Docker, CI present
- **Layer 7 (Evaluation):** No agent-specific evaluation

**Verdict:** Not applicable. No AI agent architecture to evaluate.

---

# 6. AI DevSecOps Policy Enforcement

**Note:** The `ai_devsecops_agent` CLI is not installed in this repo. Assessment is manual based on policy criteria.

## Manual Policy Review

| Policy Area | Status | Notes |
|-------------|--------|-------|
| Secrets in code | Pass | No hardcoded secrets |
| Pinned actions | Pass | checkout, setup-python use SHA |
| SBOM | Fail | No SBOM step |
| Resource limits | N/A | No K8s in repo |
| Promotion gates | N/A | Single pipeline |

**Verdict:** `pass_with_warnings` — Add SBOM for full compliance.

---

# 7. Tool Evaluator

**Tool:** TaskForge Security (CVE scanning microservice)

## 1. Summary

TaskForge Security is a minimal Python FastAPI service that scans `requirements.txt` for CVEs via pip-audit. It fits well as an internal platform security component. Recommendation: **Fit with caveats** — use internally with network isolation; add auth and SBOM before broader adoption.

## 2. Best Fit Use Cases

- Internal platform CVE scanning
- CI integration for dependency checks
- Pre-deployment security gate (when integrated with platform)

## 3. Evaluation Scorecard

| Category | Score (1–10) | Justification |
|----------|--------------|---------------|
| Problem Fit | 8 | Solves CVE scanning for Python deps |
| Capability Fit | 7 | Minimal; no OSV, remediation, or container scanning yet |
| Integration Fit | 7 | REST API; easy to call from CI/platform |
| Data Hydration & Readiness | 8 | requirements.txt is standard; no transformation |
| Security & Compliance | 6 | Good basics; no auth, no SBOM |
| Operational Fit | 8 | Simple; Docker, clear README |
| Cost & Risk | 9 | Open source; minimal deps |

## 4. Recommendation

**Fit with caveats** — Add API auth and SBOM before production exposure.

---

# Summary of Action Items

| Priority | Action | Skill Source |
|----------|--------|--------------|
| 1 | Fix CI branch: use `master` or rename to `main` | DoD ZT, Security |
| 2 | Add SBOM generation to CI | Zero Trust GitOps, DoD ZT, Security |
| 3 | Add API authentication | DoD ZT, Security |
| 4 | Add rate limiting | DoD ZT, Security |
| 5 | Add lockfile for reproducible builds | Zero Trust GitOps |
