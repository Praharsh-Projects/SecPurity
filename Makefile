SHELL := /bin/zsh

COMPOSE := docker compose
API_BASE ?= http://localhost:8080
API_KEY ?= supersecret_change_me
SMOKE_TIMEOUT_SEC ?= 120

.PHONY: up down restart logs ps smoke smoke-local clean

up:
	$(COMPOSE) up -d --build

up-prod:
	$(COMPOSE) -f docker-compose.yml -f docker-compose.prod.yml up -d --build

up-cloudflare:
	$(COMPOSE) -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.cloudflare.yml up -d --build

down:
	$(COMPOSE) down

down-prod:
	$(COMPOSE) -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.cloudflare.yml down

restart: down up

logs:
	$(COMPOSE) logs -f --tail=200

ps:
	$(COMPOSE) ps

smoke:
	API_BASE=$(API_BASE) API_KEY=$(API_KEY) SMOKE_TIMEOUT_SEC=$(SMOKE_TIMEOUT_SEC) python3 tools/smoke_api.py

smoke-local:
	API_BASE=$(API_BASE) API_KEY=$(API_KEY) SMOKE_TIMEOUT_SEC=$(SMOKE_TIMEOUT_SEC) python3 tools/smoke_api.py

clean:
	find . -name ".DS_Store" -type f -delete
