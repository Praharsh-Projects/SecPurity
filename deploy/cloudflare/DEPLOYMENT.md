# SecPurityAI Cloudflare Deployment (Full Website)

This deployment exposes the full SecPurityAI app (UI + API) on your domain through Cloudflare Tunnel.

Target outcome:
- `https://securityai.com` -> SecPurityAI dashboard + API
- `https://www.securityai.com` -> same app
- No public open backend ports required

## 1) Prepare Server (Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
docker --version
docker compose version
```

## 2) Clone and Configure

```bash
git clone <YOUR_NEW_REPO_URL> SecPurityAI
cd SecPurityAI
cp .env.example .env
```

Edit `.env` and set at minimum:
- `API_KEY` to a long random value
- `POSTGRES_PASSWORD` to a strong value
- `MINIO_ROOT_PASSWORD` to a strong value
- `NEO4J_AUTH` to `neo4j/<strong_password>`
- `CORS_ORIGINS=https://securityai.com,https://www.securityai.com`

## 3) Create Cloudflare Tunnel

In Cloudflare Zero Trust:
1. Go to `Networks -> Tunnels -> Create a tunnel`.
2. Select `Cloudflared` connector.
3. Copy the generated tunnel token.
4. Add public hostnames:
   - `securityai.com` -> `http://api:8080`
   - `www.securityai.com` -> `http://api:8080`

Set in `.env`:

```bash
CLOUDFLARE_TUNNEL_TOKEN=<paste_token_here>
```

## 4) Start Full Stack + Tunnel

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.prod.yml \
  -f docker-compose.cloudflare.yml \
  up -d --build
```

## 5) Validate

```bash
docker compose ps
curl -sS http://127.0.0.1:8080/health
API_KEY=$(grep '^API_KEY=' .env | cut -d= -f2-)
API_BASE=http://127.0.0.1:8080 API_KEY="$API_KEY" python3 tools/smoke_api.py
```

Then open:
- `https://securityai.com`
- `https://securityai.com/docs`

## 6) Cloudflare Recommended Settings

Set these in your Cloudflare zone:
- SSL/TLS mode: `Full (strict)`
- Always Use HTTPS: `On`
- Automatic HTTPS Rewrites: `On`
- WAF Managed Rules: `On`
- Bot Fight Mode: `On` (optional)
- Rate Limiting rule for `/ingest/*` and `/agents/*`

## 7) Updates

```bash
git pull
docker compose \
  -f docker-compose.yml \
  -f docker-compose.prod.yml \
  -f docker-compose.cloudflare.yml \
  up -d --build
```
