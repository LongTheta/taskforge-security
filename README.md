# TaskForge Security

**Platform security service** for the TaskForge ecosystem. Scans Python dependencies for CVEs, enriches with OSV and CISA KEV, produces reviewable remediation recommendations, and provides scaffolding for GitHub PR automation.

---

## What TaskForge Security Does

TaskForge Security is a production-grade DevSecOps microservice that:

- **Scans** `requirements.txt` files for known vulnerabilities via pip-audit
- **Enriches** findings with OSV.dev (summary, aliases, affected/fixed versions)
- **Prioritizes** using CISA Known Exploited Vulnerabilities (KEV) catalog
- **Plans remediation** with reviewable recommendations (no silent file mutation)
- **Creates** remediation PRs via GitHub API (branch + commit + PR)
- **Runs** in Docker with non-root user and reproducible installs (uv.lock)
- **Protects** endpoints with optional API key auth and rate limiting

---

## Role in the TaskForge Platform

TaskForge is a multi-repo platform. Security sits alongside:

| Repo | Purpose |
|------|---------|
| **taskforge-backend** | Core API, auth, tasks, notes |
| **taskforge-platform** | GitOps, Argo CD, Kubernetes |
| **taskforge-observability** | Grafana, Prometheus, dashboards |
| **taskforge-security** | CVE scanning, Trivy images, remediation, PR creation, policy gate (this repo) |

Security provides dependency vulnerability scanning, container image scanning (Trivy), remediation planning, PR creation, policy gating, and Prometheus metrics for Grafana dashboards.

---

## Scan Flow

1. **Validate** `target_path` and `manifest_path` (no traversal)
2. **Run** pip-audit against the manifest
3. **Enrich** (optional) with OSV.dev API for summary/aliases
4. **Flag** KEV-listed CVEs from CISA catalog
5. **Prioritize** findings (critical/high/medium/low)
6. **Return** structured JSON with risk summary

---

## Remediation Planning

- **Endpoint**: `POST /api/v1/remediate`
- **Input**: `target_path`, `manifest_path`
- **Output**: Reviewable recommendations (no file mutation)

Each recommendation includes:
- `package`, `current_version`, `recommended_version`
- `vulnerability_ids`, `severity`, `kev_listed`
- `rationale`, `confidence`, `upgrade_type` (patch/minor/major)
- `manual_review_required` (true for major upgrades, auth/crypto libs, KEV)

**Decision rules**: Prefer patch → minor → major. Mark auth/crypto/database libs for manual review. If no fix exists, provide mitigation guidance.

---

## OSV Enrichment

- Uses OSV.dev API (`/v1/querybatch`, `/v1/vulns`)
- Enriches with summary, aliases, affected/fixed versions
- Fails gracefully if OSV is unavailable (scan still returns pip-audit results)
- Configurable via `OSV_API_BASE`, `OSV_TIMEOUT`

---

## CISA KEV Prioritization

- Loads CISA Known Exploited Vulnerabilities catalog
- Flags findings with `kev_listed: true` when CVE is in catalog
- Heavily weights KEV in priority (critical)
- Catalog cached in memory; configurable via `KEV_CATALOG_URL`

---

## GitHub PR Automation

- **Preview**: `GET /api/v1/remediate/preview-pr?target_path=.&manifest_path=requirements.txt`
- **Create PR**: `POST /api/v1/remediate/create-pr` — creates branch, commits manifest updates, opens PR
- **Config**: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`, `GITHUB_BASE_BRANCH`, `GITHUB_DRY_RUN`
- Set `GITHUB_DRY_RUN=false` to enable actual PR creation

## Trivy Image Scanning

- **Endpoint**: `POST /api/v1/scan/image`
- **Input**: `image_ref` (e.g. `python:3.11-slim`, `myregistry/app:v1`)
- **Requires**: Trivy CLI installed
- **Output**: Same `ScanResponse` format as manifest scan, with KEV prioritization

## Policy Gating

- **Endpoint**: `GET /api/v1/gate?target_path=.&manifest_path=requirements.txt`
- **Returns**: `pass` (bool), `blocked_by` (reasons), `risk_summary`
- **Config**: `POLICY_BLOCK_CRITICAL`, `POLICY_BLOCK_KEV` (default: true)
- Use in CI/CD to block deployment when critical or KEV findings exist

## Metrics & Grafana

- **Metrics**: `GET /metrics` — Prometheus exposition format
- **Dashboard**: `docs/grafana/taskforge-security-dashboard.json` — import into Grafana
- **Metrics**: `taskforge_security_scans_total`, `taskforge_security_scan_vulnerabilities_total`, `taskforge_security_gate_failures_total`, etc.

---

## Safety Guardrails

- **Reviewable remediation**: Recommendations only; no silent file mutation
- **No auto-merge**: PR automation is scaffolding; no automatic merging
- **Conservative upgrades**: Major upgrades and security-sensitive libs require manual review
- **Graceful degradation**: OSV/KEV failures do not break scan; pip-audit results still returned
- **No fabricated data**: Fixed versions come from advisories only

---

## Quick Start

### Local Development

```bash
uv sync --all-extras
uvicorn app.main:app --reload --host 0.0.0.0 --port 8081
```

### Docker

```bash
docker build -t taskforge-security .
docker run -p 8081:8081 taskforge-security
```

### Production Deployment

For production deployments:

1. **TLS**: Terminate TLS at the load balancer, ingress, or reverse proxy. The service listens on HTTP; do not expose it directly to the internet without TLS termination upstream.
2. **API authentication**: Set `REQUIRE_API_KEY=true` and `API_KEY` to a strong secret. The service logs a warning at startup if `APP_ENV=production` and API key is not required.
3. **Secrets**: Use platform secret management (e.g., External Secrets Operator, Vault) for `API_KEY`, `GITHUB_TOKEN`, and other sensitive config.

---

## API Reference

### Health (unrestricted)

```bash
curl http://localhost:8081/health
# {"status": "ok"}
```

### Info

```bash
curl http://localhost:8081/api/v1/info
# Service metadata, version, endpoints
```

### Scan

```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key" \
  -d '{
    "target_path": ".",
    "manifest_path": "requirements.txt",
    "include_osv_enrichment": true,
    "include_kev_prioritization": true
  }'
```

### Remediate

```bash
curl -X POST http://localhost:8081/api/v1/remediate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key" \
  -d '{"target_path": ".", "manifest_path": "requirements.txt"}'
```

### Scan Image (Trivy)

```bash
curl -X POST http://localhost:8081/api/v1/scan/image \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key" \
  -d '{"image_ref": "python:3.11-slim"}'
```

### Policy Gate

```bash
curl "http://localhost:8081/api/v1/gate?target_path=.&manifest_path=requirements.txt" \
  -H "X-API-Key: your-secret-key"
```

### Preview PR

```bash
curl "http://localhost:8081/api/v1/remediate/preview-pr?target_path=.&manifest_path=requirements.txt" \
  -H "X-API-Key: your-secret-key"
```

### Create PR

```bash
curl -X POST http://localhost:8081/api/v1/remediate/create-pr \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key" \
  -d '{"target_path": ".", "manifest_path": "requirements.txt"}'
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | development | development, production, test |
| `LOG_LEVEL` | INFO | Logging level |
| `SCAN_TIMEOUT` | 120 | Scan timeout (seconds) |
| `OSV_API_BASE` | https://api.osv.dev | OSV API URL |
| `OSV_TIMEOUT` | 30 | OSV request timeout |
| `KEV_CATALOG_URL` | CISA feed | KEV catalog URL |
| `REQUIRE_API_KEY` | false | Require X-API-Key when true; **set true in production** |
| `API_KEY` | "" | Expected API key (required when REQUIRE_API_KEY=true) |
| `GITHUB_TOKEN` | "" | GitHub token (optional) |
| `GITHUB_OWNER` | "" | Repo owner |
| `GITHUB_REPO` | "" | Repo name |
| `GITHUB_DRY_RUN` | true | No PR creation when true |
| `POLICY_BLOCK_CRITICAL` | true | Block gate on critical findings |
| `POLICY_BLOCK_KEV` | true | Block gate on KEV findings |

---

## Project Structure

```
taskforge-security/
├── app/
│   ├── main.py
│   ├── api/routes/
│   │   ├── health.py
│   │   ├── info.py
│   │   ├── scan.py
│   │   └── remediation.py
│   ├── core/
│   │   ├── auth.py
│   │   ├── config.py
│   │   ├── logging_config.py
│   │   ├── middleware.py
│   │   └── rate_limit.py
│   ├── integrations/github/
│   │   ├── client.py
│   │   ├── models.py
│   │   └── pr_creator.py
│   ├── schemas/
│   │   ├── scan.py
│   │   └── remediation.py
│   ├── scanners/
│   │   ├── pip_audit.py
│   │   ├── osv.py
│   │   ├── kev.py
│   │   └── requirements.py
│   └── services/
│       ├── scan_service.py
│       ├── remediation_service.py
│       └── priority.py
├── docs/
│   ├── examples/
│   └── grafana/
├── tests/
├── .github/workflows/
│   ├── ci.yml
│   └── scheduled-scan.yml
├── Dockerfile
├── pyproject.toml
├── uv.lock
└── README.md
```

---

## Implemented vs Roadmap

| Feature | Status |
|---------|--------|
| pip-audit scan | ✅ Implemented |
| OSV enrichment | ✅ Implemented |
| CISA KEV prioritization | ✅ Implemented |
| Remediation planning | ✅ Implemented |
| GitHub PR preview | ✅ Implemented |
| PR creation | ✅ Implemented |
| Trivy image scanning | ✅ Implemented |
| Policy gating | ✅ Implemented |
| Prometheus metrics | ✅ Implemented |
| Grafana dashboard | ✅ Implemented |
| Scheduled scan workflow | ✅ Implemented |
| Audit trail persistence | 🔜 Roadmap |

---

## Development

```bash
make install    # Install deps
make lint      # Ruff check + format
make test      # Pytest
make security  # Bandit + pip-audit
make run       # Local uvicorn
```

---

## License

MIT
