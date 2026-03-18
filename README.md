# TaskForge Security

**DevSecOps security service** for the TaskForge platform. Scans Python dependencies for known CVEs via pip-audit and returns structured JSON results.

---

## What is TaskForge Security?

TaskForge Security is a production-grade security microservice that:

- **Scans** `requirements.txt` files for known vulnerabilities using pip-audit
- **Returns** structured JSON with package, version, CVE ID, summary, and fixed versions
- **Runs** in Docker with non-root user and reproducible installs (uv.lock)
- **Validates** in CI (ruff, pytest, bandit, pip-audit, SBOM, lockfile check)
- **Protects** scan endpoint with optional API key auth and rate limiting

---

## Role in the TaskForge Platform

TaskForge is a multi-repo platform. Security sits alongside:

| Repo | Purpose |
|------|---------|
| **taskforge-backend** | Core API, auth, tasks, notes |
| **taskforge-platform** | GitOps, Argo CD, Kubernetes |
| **taskforge-observability** | Grafana, Prometheus, dashboards |
| **taskforge-security** | CVE scanning (this repo) |

---

## Positioning and Exposure

**Suitable for internal use** within the TaskForge platform. Designed for network-isolated or platform-internal deployment. When exposed beyond the platform:

- Set `REQUIRE_API_KEY=true` and configure `API_KEY`
- Rate limiting (10 req/min on scan) helps mitigate abuse
- Consider additional controls (WAF, mTLS) at the platform layer

---

## Quick Start

### Local Development

```bash
pip install -e ".[dev]"
# or with uv: uv sync --all-extras
uvicorn app.main:app --reload --host 0.0.0.0 --port 8081
```

### Docker

```bash
docker build -t taskforge-security .
docker run -p 8081:8081 taskforge-security
```

---

## API Reference

### Health (unrestricted)

```bash
curl http://localhost:8081/health
```

**Response:**

```json
{"status": "ok"}
```

### Scan (rate-limited; auth required when `REQUIRE_API_KEY=true`)

```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key" \
  -d '{"target_path": ".", "manifest_path": "requirements.txt"}'
```

**Response:**

```json
{
  "vulnerability_count": 2,
  "vulnerabilities": [
    {
      "package": "requests",
      "current_version": "2.25.0",
      "vulnerability_id": "CVE-2023-32681",
      "summary": "Request smuggling vulnerability",
      "fixed_versions": ["2.31.0"]
    }
  ]
}
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | development | development, production, test |
| `LOG_LEVEL` | INFO | Logging level |
| `SCAN_TIMEOUT` | 120 | Scan timeout (seconds) |
| `REQUIRE_API_KEY` | false | Require X-API-Key for scan when true |
| `API_KEY` | "" | Expected API key (set when REQUIRE_API_KEY=true) |
| `RATE_LIMIT_SCAN` | 10/minute | Rate limit for scan endpoint |

Copy `.env.example` to `.env` and adjust.

---

## API Auth Model

- **Lightweight**: Simple `X-API-Key` header check
- **Configurable**: `REQUIRE_API_KEY=true` in production; `false` for dev/test
- **Health exempt**: `/health` is always open for liveness probes
- **401** on missing or invalid key when auth is required

---

## Rate Limiting

- **Scan endpoint**: 10 requests/minute per client (configurable via `RATE_LIMIT_SCAN`)
- **Health**: Unrestricted
- **429** when limit exceeded

---

## Lockfile and Reproducible Builds

The project uses **uv** and `uv.lock` for reproducible dependency installs:

- **Lockfile**: `uv.lock` pins all transitive dependencies
- **CI**: `uv lock --frozen` verifies the lockfile is in sync with `pyproject.toml`
- **Docker**: Uses `uv sync --locked` for reproducible image builds

### Refreshing Dependencies

```bash
# Install uv: https://docs.astral.sh/uv/getting-started/installation/
uv lock                    # Update lockfile after changing pyproject.toml
uv sync --all-extras       # Install deps (dev)
uv lock --frozen            # Verify lockfile is up to date (CI)
```

---

## SBOM Generation

CI generates a CycloneDX SBOM for Python dependencies and uploads it as an artifact:

- **Job**: `sbom`
- **Format**: CycloneDX JSON
- **Output**: `sbom.json` (downloadable from workflow artifacts)

---

## CI / Branch Expectations

- **Branches**: CI runs on `main` and `master`
- **Jobs**: lockfile, lint, test, security, sbom
- **Lockfile**: Must be committed when `pyproject.toml` dependencies change

---

## Security

- **Path validation**: `target_path` and `manifest_path` validated; no path traversal
- **Command injection**: Subprocess uses list args, no `shell=True`
- **Scope**: Scan limited to local directory
- **Errors**: Clean error messages, no stack traces to clients
- **Auth**: Optional API key for scan endpoint
- **Rate limiting**: Abuse protection on scan

---

## Project Structure

```
taskforge-security/
├── app/
│   ├── main.py
│   ├── api/routes/
│   │   ├── health.py
│   │   └── scan.py
│   ├── core/
│   │   ├── auth.py
│   │   ├── config.py
│   │   ├── logging_config.py
│   │   ├── middleware.py
│   │   └── rate_limit.py
│   ├── schemas/
│   │   └── scan.py
│   ├── scanners/
│   │   ├── pip_audit.py
│   │   └── requirements.py
│   └── services/
│       └── scan_service.py
├── tests/
├── .github/workflows/ci.yml
├── Dockerfile
├── pyproject.toml
├── uv.lock
└── README.md
```

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

## Future Roadmap

- Richer auth (OIDC, service accounts) when platform integration requires it
- Policy engine for blocking deployments on critical CVEs
- Grafana security dashboards

---

## License

MIT
