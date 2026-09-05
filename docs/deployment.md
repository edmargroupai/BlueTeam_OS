# Blue Team OS — Production deployment

Official production path (one path only):

```
GitHub
  ↓
CI/CD + GHCR
  ↓
┌─────────────────────┐     ┌──────────────────────────┐
│ Vercel              │     │ FastAPI container host   │
│ Next.js Command     │────▶│ (Railway — current)      │
│ Center              │     │ Python / FastAPI / Docker│
└─────────────────────┘     └────────────┬─────────────┘
                                         ↓
                              ┌──────────────────────┐
                              │ Supabase PostgreSQL  │
                              │ control-plane DB     │
                              └──────────────────────┘

Local Docker Compose (dataplane / integration):
  Redis · ClickHouse · OpenSearch · Redpanda · MinIO · optional local Postgres
```

Railway is the **current FastAPI container host**. It is not part of Blue Team OS security logic.
Portability boundary = Docker image (`infra/docker/Dockerfile.api`).

## Roles

| Layer | Platform | Role |
|-------|----------|------|
| Frontend | Vercel | Next.js Command Center |
| Control plane compute | Railway | FastAPI/Python container |
| Control-plane database | Supabase | PostgreSQL (identity, audit, incidents, detections, graph) |
| Source / CI / images | GitHub + Actions + GHCR | lint, tests, API image publish |
| Local dataplane | Docker Compose | Redis, ClickHouse, OpenSearch, Redpanda, MinIO |

Do **not** provision Railway PostgreSQL for control-plane data. Supabase remains the database.

## Railway (API)

1. Create a Railway project from this GitHub repo (root directory).
2. Railway uses `railway.toml` → builds `infra/docker/Dockerfile.api`.
3. Set secrets (Railway Variables) — never commit them:

| Variable | Purpose |
|----------|---------|
| `BTOS_ENV` | `production` |
| `BTOS_SECRET_KEY` | long random secret |
| `BTOS_DATABASE_URL` | Supabase pooler URL (`postgresql+psycopg://…?sslmode=require`) |
| `BTOS_SUPABASE_URL` | `https://<project>.supabase.co` |
| `BTOS_SUPABASE_PUBLISHABLE_KEY` | publishable key only |
| `BTOS_WEB_ORIGIN` | `https://blueteam-os.vercel.app` |
| `BTOS_CORS_ORIGINS` | comma-separated approved origins (same as web + any extras) |
| `BTOS_CORS_ORIGIN_REGEX` | optional; e.g. `https://.*\\.vercel\\.app` for previews |
| `BTOS_DEV_SEED` | `true` only if demo seed is required; prefer `false` in hardened prod |
| `BTOS_DEV_PASSWORD` | only if seed enabled |
| `BTOS_AI_ENABLED` | `false` |

4. Generate a public HTTPS domain in Railway.
5. Confirm `GET https://<railway-domain>/api/v1/health` returns JSON without secrets.
6. Container binds `0.0.0.0` and listens on Railway `$PORT`.

## Vercel (web)

1. Project `blueteam-os` builds `apps/web` via root `vercel.json`.
2. Set **Production** env:

| Variable | Value |
|----------|-------|
| `NEXT_PUBLIC_API_URL` | `https://<railway-generated-domain>` (no trailing slash) |

3. Do **not** put database passwords or service-role keys in `NEXT_PUBLIC_*`.
4. Redeploy after setting the variable. Production UI fail-closes if `NEXT_PUBLIC_API_URL` is missing.

Local web/dev may omit `NEXT_PUBLIC_API_URL` and use `http://127.0.0.1:8080`.

## Local development

See `docs/local-development.md` and `docker-compose.yml`.

```powershell
docker compose up postgres redis clickhouse opensearch redpanda minio api
```

## Explicitly not used

Fly.io and Render are **not** part of the deployment architecture. Do not add alternate cloud host scaffolding.
