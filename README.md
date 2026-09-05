# Blue Team OS Center

Defensive cybersecurity operating system. Python-first, multi-tenant, evidence-backed, AI-optional.

GSE is a practitioner certification, not a software badge. Internally this repository uses **GSE-calibre** as the quality bar: no UI page or stub counts as a defensive capability. Credit requires backend behaviour, tests, replay, evidence, and a measurable score.

Current evidence-backed quality band is **prototype**. That is intentional. The index is not inflated.

## What this slice actually does

- Tenant-scoped control plane (FastAPI) with RBAC and hash-chained audit
- Canonical event ingestion, dead-letter, and idempotent accept
- Deterministic identity detections: password spray, brute force, privilege grant
- Evidence objects with integrity hashes; AI/analyst claims must cite valid IDs
- Blue Range scenarios executed in CI
- Quality index computed from evidence, never from the UI
- Command Center UI bound to the live API (loading / empty / error states)
- Polyglot layer under Python: Sigma, YARA subset, SQL hunts, BlueQL, Rego, execution broker, Windows/Linux collectors

## Local development

```powershell
copy .env.example .env
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m uvicorn app.main:app --app-dir services/api --reload --port 8080
```

In a second terminal:

```powershell
cd apps/web
npm install
npm run dev
```

Sign in with a seeded operator (password from `BTOS_DEV_PASSWORD` in `.env`):

- `detector@demo.blueteam.local` — detection engineer
- `analyst@demo.blueteam.local` — analyst
- `owner@demo.blueteam.local` — tenant owner

## Production stack

One production path only — see [docs/deployment.md](docs/deployment.md):

- **Vercel** — Next.js Command Center  
- **Railway** — FastAPI/Python control-plane container (Docker)  
- **Supabase** — PostgreSQL control-plane database  
- **GitHub / Actions / GHCR** — source, CI, API images  
- **Docker Compose** — local dataplane (Redis, ClickHouse, OpenSearch, Redpanda, MinIO)

## Tests

```powershell
pytest -q
```

Required suites: unit, tenant isolation, detection, Blue Range, control-plane security.

## Compose data plane

```powershell
docker compose up postgres redis clickhouse opensearch redpanda minio
```

SQLite is allowed for local and CI only. ClickHouse, OpenSearch, Redpanda, and MinIO are defined in Compose for dataplane work; they are reported as unconfigured rather than faked when unused.

## Non-negotiables

- Feature code never calls an AI provider SDK
- The platform operates with AI disabled
- Cross-tenant reads and writes fail
- Every state-changing action writes an audit record
