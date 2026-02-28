# SecPurityAI

SecPurityAI is a multi-store cybersecurity platform with:
- Event ingestion and normalization (`/ingest/log`)
- Rule-based alerting with audit logs
- Asset/CVE impact matching
- ML training/scoring/explain endpoints
- Vector similarity search (Qdrant)
- Graph ingestion/scoring (Neo4j)
- Static SOC dashboard pages served by FastAPI

## Stack

- API: FastAPI (`services/api`)
- Stores: Postgres, MinIO, Qdrant, Neo4j
- Feeders: NVD, KEV, Suricata tailer, connector, worker
- Governance scheduler: evaluator (nightly evaluation + release gate)
- Orchestration: Docker Compose
- Cloudflare production profiles:
  - `docker-compose.prod.yml`
  - `docker-compose.cloudflare.yml`
  - `deploy/cloudflare/DEPLOYMENT.md`

## Quick Start

1. Create env file:
```bash
cp .env.example .env
```

2. Start the full stack:
```bash
make up
```

3. Run end-to-end smoke validation:
```bash
make smoke
```

4. Open:
- API docs: `http://localhost:8080/docs`
- Dashboard: `http://localhost:8080/static/index.html`
- Legacy dashboard link: `http://localhost:8080/static/dashboard.html`

## Create New GitHub Repo And Push

```bash
git init
git add .
git commit -m "feat: SecPurityAI production-ready Cloudflare deployment"
git branch -M main
git remote add origin https://github.com/<your-user>/<your-new-repo>.git
git push -u origin main
```

## Deploy Full Project On Cloudflare (UI + API)

1. Copy env and set production values:
```bash
cp .env.example .env
```

2. Set at minimum in `.env`:
- `API_KEY`
- `POSTGRES_PASSWORD`
- `MINIO_ROOT_PASSWORD`
- `NEO4J_AUTH`
- `CORS_ORIGINS=https://securityai.com,https://www.securityai.com`
- `CLOUDFLARE_TUNNEL_TOKEN` (from Cloudflare Zero Trust tunnel)

3. Start production + Cloudflare tunnel:
```bash
make up-cloudflare
```

4. Validate:
```bash
API_KEY=$(grep '^API_KEY=' .env | cut -d= -f2-)
API_BASE=http://127.0.0.1:8080 API_KEY="$API_KEY" python3 tools/smoke_api.py
```

5. Open your site:
- `https://securityai.com`
- `https://www.securityai.com`

Detailed guide: `deploy/cloudflare/DEPLOYMENT.md`

## Key Endpoints

- Health and stores
  - `GET /health`
  - `GET /stores/ping`
  - `GET /metrics/summary`
- Ingestion and events
  - `POST /ingest/log` (requires `X-API-Key`)
  - `GET /events`
  - `GET /events/{event_id}`
  - `GET /events/export`
- Alerts and labels
  - `GET /alerts`
  - `POST /events/{event_id}/label` (API key)
  - `GET /labels/summary`
- Similarity/vector
  - `POST /index/event/{event_id}` (API key)
  - `POST /search/similar` (API key)
  - `GET /similar` (legacy UI alias)
- KEV
  - `POST /kev/sync` (API key)
  - `POST /feeds/kev/sync` (legacy UI alias)
  - `GET /kev`
- Graph/agents/lab
  - `POST /graph/ingest/event` (API key)
  - `GET /graph/subgraph`
  - `GET /graph/score`
  - `POST /lab/red/run` (API key, when enabled)
  - `GET /agents/blue/suggest` (API key, when enabled)
- Privacy/Federation/Deception
  - `GET /privacy/budget?tenant=...`
  - `POST /privacy/budget/consume` (API key)
  - `POST /privacy/budget/limit` (API key)
  - `POST /federation/updates` (API key)
  - `GET /federation/updates`
  - `POST /federation/aggregate` (API key; median/trimmed_mean/krum)
  - `POST /deception/honeytoken/issue` (API key)
  - `POST /deception/honeytoken/trip` (API key)
  - `GET /deception/honeytoken/list`
- Governance, policy, and safety
  - `GET /policy/current` (API key)
  - `POST /policy/reload` (API key)
  - `POST /policy/evaluate` (API key)
  - `POST /firewall/precheck` (API key)
  - `POST /firewall/postcheck` (API key)
  - `POST /provenance/verify` (API key)
  - `GET /audit/verify_chain` (API key)
  - `POST /evaluation/run` (API key)
  - `GET /evaluation/runs` (API key)
  - `POST /governance/cards/generate` (API key)
  - `POST /governance/release-gate/run` (API key)
  - `GET /sandbox/attestation` (API key)
  - `POST /sandbox/execute` (API key)

## Environment Notes

- `API_KEY` is required for mutating routes.
- `NVD_API_KEY` is optional but recommended to reduce rate-limit failures.
- `AUTO_INDEX=true` enables automatic Qdrant indexing on ingest.
- `GRAPH_ENABLED`, `LAB_ENABLED`, and `AGENTS_ENABLED` toggle advanced slices.

## Verify New Governance/Safety Updates

```bash
API_KEY=$(cat supersecret_change_me)

curl -sS -H "X-API-Key: $API_KEY" http://localhost:8080/policy/current
curl -sS -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  http://localhost:8080/firewall/precheck \
  -d '{"text":"normal login event","context":{"src_ip":"1.1.1.1"}}'
curl -sS -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  http://localhost:8080/evaluation/run \
  -d '{"suite":"nightly","include_ingest":true}'
curl -sS -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  http://localhost:8080/governance/release-gate/run \
  -d '{"environment":"staging","include_ingest":true,"generate_cards":true}'
curl -sS -H "X-API-Key: $API_KEY" "http://localhost:8080/audit/verify_chain?limit=5000"
```

## Useful Commands

```bash
make ps
make logs
make smoke
make up-prod
make up-cloudflare
make down
```

## Project Status

This repository includes a runnable expanded MVP aligned with the architecture document:
- End-to-end ingest -> alert -> query flow
- Multi-store health and data paths
- Compatible static UI routes and API aliases
- Automated smoke test for regression detection
- Policy engine, AI firewall, provenance checks, release gate, and evaluator scheduler
- Privacy/federation/deception/sandbox control endpoints for advanced phases
