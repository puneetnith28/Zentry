#!/usr/bin/env bash
set -euo pipefail

echo "=== Zentry Containerized Stack Smoke Test ==="

# 1. Check API Health Probe
echo "[1/4] Checking API Health Probe..."
HEALTH_RESPONSE=$(curl -fsSL -m 10 http://localhost:8000/health || true)
if [[ -z "$HEALTH_RESPONSE" ]]; then
    echo "ERROR: Failed to connect to API /health endpoint."
    exit 1
fi
echo "API Health Response: $HEALTH_RESPONSE"

# 2. Check Database Connectivity
echo "[2/4] Checking PostgreSQL DB connectivity..."
docker compose exec db pg_isready -U postgres -d security_scanner

# 3. Check Redis Broker Connectivity
echo "[3/4] Checking Redis broker ping..."
REDIS_PING=$(docker compose exec redis redis-cli ping)
if [[ "$REDIS_PING" != "PONG" ]]; then
    echo "ERROR: Unexpected Redis response: $REDIS_PING"
    exit 1
fi
echo "Redis Ping: $REDIS_PING"

# 4. Check Celery Worker Health
echo "[4/4] Checking Worker Health probe..."
docker compose exec worker python worker_health.py

echo "=== All Containerized Smoke Tests Passed Successfully ==="
