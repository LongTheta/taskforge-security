# TaskForge Security

**DevSecOps security service** for the TaskForge platform. Scans Python dependencies for known CVEs via pip-audit and returns structured JSON results.

---

## What is TaskForge Security?

TaskForge Security is a production-grade security microservice that:

- **Scans** `requirements.txt` files for known vulnerabilities using pip-audit
- **Returns** structured JSON with package, version, CVE ID, summary, and fixed versions
- **Runs** in Docker with non-root user
- **Validates** in CI (ruff, pytest, pip-audit)

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

## Quick Start

### Local Development

```bash
pip install -e ".[dev]"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8081
```

### Docker

```bash
docker build -t taskforge-security .
docker run -p 8081:8081 taskforge-security
```

---

## API Reference

### Health

```bash
curl http://localhost:8081/health
```

**Response:**

```json
{"status": "ok"}
```

### Scan

```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
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

## Project Structure

```
taskforge-security/
├── app/
│   ├── main.py
│   ├── api/routes/
│   │   ├── health.py
│   │   └── scan.py
│   ├── core/
│   │   ├── config.py
│   │   ├── logging_config.py
│   │   └── middleware.py
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
└── README.md
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | development | development, production, test |
| `LOG_LEVEL` | INFO | Logging level |
| `SCAN_TIMEOUT` | 120 | Scan timeout (seconds) |

Copy `.env.example` to `.env` and adjust.

---

## Security

- **Path validation**: `target_path` and `manifest_path` validated; no path traversal
- **Command injection**: Subprocess uses list args, no `shell=True`
- **Scope**: Scan limited to local directory
- **Errors**: Clean error messages, no stack traces to clients

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
