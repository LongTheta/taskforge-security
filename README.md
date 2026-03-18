# TaskForge Security

**DevSecOps security service** for the TaskForge platform. Scans dependencies for vulnerabilities (CVE detection), prioritizes risk, suggests remediation actions, and integrates with GitOps workflows.

---

## What is TaskForge Security?

TaskForge Security is a production-grade security microservice that:

- **Scans** Python dependencies (requirements.txt) for known CVEs via pip-audit
- **Enriches** findings with OSV.dev for severity and metadata
- **Recommends** remediation (lowest fixed version) without auto-modifying files
- **Integrates** with CI/CD and GitOps pipelines
- **Prepares** for PR-based auto-remediation (future phase)

This is **not** a toy project. It follows production engineering standards suitable for platform teams.

---

## Role in the TaskForge Platform

TaskForge is a multi-repo platform. Security sits alongside:

| Repo | Purpose |
|------|---------|
| **taskforge-backend** | Core API, auth, tasks, notes |
| **taskforge-platform** | GitOps, Argo CD, Kubernetes |
| **taskforge-observability** | Grafana, Prometheus, dashboards |
| **taskforge-security** | CVE scanning, remediation, policy (this repo) |

Security provides:

- Dependency vulnerability scanning for backend and platform components
- Remediation recommendations for safe version upgrades
- Future: PR automation, policy engine, Grafana security dashboards

---

## Quick Start

### Local Development

```bash
# Install
pip install -e ".[dev]"

# Run
uvicorn app.main:app --reload --host 0.0.0.0 --port 8081
```

### Docker

```bash
docker build -t taskforge-security .
docker run -p 8081:8081 taskforge-security
```

### Docker Compose

```bash
docker-compose up
```

---

## API Reference

### Health

```bash
curl http://localhost:8081/api/v1/health
```

### Scan

```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_path": "/path/to/your/project",
    "manifest_path": "requirements.txt",
    "include_osv_enrichment": true
  }'
```

**Response:**

```json
{
  "total_vulnerabilities": 2,
  "vulnerabilities": [
    {
      "package": "requests",
      "current_version": "2.25.0",
      "vulnerability_id": "CVE-2023-32681",
      "severity": "high",
      "summary": "Request smuggling vulnerability",
      "fixed_versions": ["2.31.0"],
      "source": "pip-audit"
    }
  ]
}
```

### Remediate

```bash
curl -X POST http://localhost:8081/api/v1/remediate \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [
      {
        "package": "requests",
        "current_version": "2.25.0",
        "vulnerability_id": "CVE-2023-32681",
        "fixed_versions": ["2.31.0"]
      }
    ]
  }'
```

**Response:**

```json
{
  "recommendations": [
    {
      "package": "requests",
      "current_version": "2.25.0",
      "recommended_version": "2.31.0",
      "rationale": "Recommended upgrade from 2.25.0 to 2.31.0 (lowest fixed version).",
      "confidence": "high"
    }
  ]
}
```

---

## Architecture

```
taskforge-security/
├── app/
│   ├── main.py              # FastAPI app, lifespan
│   ├── api/routes/          # Health, Scan, Remediation
│   ├── core/                # Config, logging, middleware
│   ├── schemas/             # Pydantic models
│   ├── scanners/            # pip_audit, OSV, Dockerfile (future)
│   └── services/            # Scan, Remediation orchestration
├── tests/
├── .github/workflows/ci.yml  # Lint, test, bandit, pip-audit
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

**Design principles:**

- **Separation of concerns**: Scanner (pip-audit) → Service (orchestration) → API (routes)
- **Extensible**: Placeholders for Trivy, policy engine, GitHub integration
- **Secure**: Path validation, no shell injection, fail safely

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | development | development, production, test |
| `LOG_LEVEL` | INFO | Logging level |
| `OSV_API_BASE` | https://api.osv.dev | OSV API URL |
| `SCAN_TIMEOUT` | 120 | Scan timeout (seconds) |

Copy `.env.example` to `.env` and adjust.

---

## Security Requirements

- **Path validation**: `target_path` and `manifest_path` validated; no path traversal
- **Command injection**: Subprocess uses list args, no `shell=True`
- **Scope**: Scan limited to local directory
- **Errors**: Clean error messages, no stack traces to clients

---

## Future Roadmap

| Phase | Feature |
|-------|---------|
| **PR automation** | Auto-create PRs with remediation patches |
| **Trivy** | Container/Dockerfile scanning |
| **Policy engine** | Block deployments on critical CVEs |
| **Grafana dashboards** | Security metrics and trends |

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
