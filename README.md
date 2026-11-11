# Mirage

## Overview

Mirage is an AI-driven HTTP honeypot. Unlike classic honeypots with static responses, it generates believable, context-aware responses and keeps a consistent "fake world" for each attacker. The project's hypothesis: the longer an attacker believes they are talking to a real system, the more data we can collect about their tools, payloads and intent.

> **Status: early stage of development.** The project is built in stages (roadmap v0.1 → v1.0). It is not ready for production use yet.

### Design principles

- **Short request path.** The response never depends on analysis. Every request goes to a Redis Stream, and workers write it to PostgreSQL/TimescaleDB asynchronously.
- **Three response tiers.** Tier 0 is templates and cache (ms), tier 1 is a local model (Ollama, up to 3 s), tier 2 is a stronger model for interesting sessions. When a token budget is exhausted the system degrades to tier 0 and never returns 429.
- **Consistent world.** Base data comes from a deterministic seed (Faker), and the attacker's changes are stored in Redis with a TTL. The model never writes to Redis directly; it only proposes validated `state_updates`.
- **Canary tokens.** Every "secret" in a world is a unique token bound to that world, so its use elsewhere points to the source of the leak.
- **The honeypot itself is safe.** The model has no tools, its output is validated against a Pydantic schema, and attacker input reaches the prompt as data, not instructions. Containers are hardened and egress is restricted by a whitelist (nftables).
- **No hack-back.** The project only observes. Personal data (IPs, request contents) has limited retention, in line with GDPR.
- **Stack:** Python 3.12, FastAPI, Pydantic v2, Redis 7, PostgreSQL 16 + TimescaleDB, SQLAlchemy 2.0 async, Alembic, Ollama, Docker Compose, Caddy, Prometheus and Grafana.

### Done so far

- **Foundation:** FastAPI app, configuration, structlog logging, separate health port, ASGI middleware capturing traffic, Redis stream, `StreamConsumer` with dead-letter and a persister, Alembic migrations (`requests` hypertable), Dockerfile, Compose, Caddy, container hardening, nftables.
- **Personas with templates (tier 0):** `fake_api` (products, users, login with a fake JWT, swagger, `.env`), a catch-all with an nginx-style 404, and bait for WordPress, phpMyAdmin, `.git`/config files and Spring Actuator.
- **Enrichment and detection:** GeoLite2, ASN, reverse DNS, AbuseIPDB, rules for SQLi/XSS/SSTI/traversal/cmdi/Log4Shell, scanner signatures, Prometheus metrics, Grafana, WireGuard.
- **Tier 1 (in progress):** OpenAI-compatible LLM client, `ResponseEngine` with validation and fallback, token budgets (Lua, IP/subnet/global) with concurrency tests, world state (seed, Redis delta, `snapshot_for`, `StateUpdate`), a canary token generator and the `canary_tokens` table.

### To do

- **Stage 3 (finishing):** wire canary tokens into the bait templates and register them, per-world response cache, prompt injection tests and prompt hardening, ADR-002 and ADR-003, enable tier 1 in production.
- **Stage 4:** session signals, bot/human classifier, `interest_score`, `ModelRouter`, ASN budget dimension and dynamic budget multiplier, admin persona.
- **Stage 5:** tier 2 and analyst reports with ATT&CK mapping, IoC extraction, STIX/MISP export and alerts, fake LLM persona (OpenAI-compatible).
- **Stage 6:** anti-fingerprinting (JA4, latency equalization), replay and load tests (k6), retention policies, A/B experiment, analytics API, full documentation and v1.0.

The full plan and rationale will appear in `docs/` (ADRs) as work progresses.
