# Reproducible Development and Production Deployment Guide

This guide provides comprehensive, verified procedures for setting up Zentry in local development environments and deploying the containerized stack into production.

---

## 1. Prerequisites

- **Docker Engine:** Version 24.0+
- **Docker Compose:** Version 2.20+
- **Python:** 3.11+ (for native local development)
- **Node.js:** 20+ (for frontend development)
- **Git**

---

## 2. Quickstart: Containerized Deployment

Deploying the complete stack (PostgreSQL, Redis, FastAPI backend, and Celery worker) requires a single command:

```bash
# 1. Clone repository
git clone https://github.com/puneetnith28/Zentry.git
cd Zentry

# 2. Configure environment
cp .env.example .env
# Edit .env and supply a secure JWT_SECRET_KEY in production!

# 3. Build and launch services in background
docker compose up -d --build

# 4. Verify deployment health
./scripts/smoke_test.sh
```

Once started:
- **API Documentation (Swagger UI):** `http://localhost:8000/docs`
- **OpenAPI JSON Contract:** `http://localhost:8000/openapi.json`
- **Health Check Endpoint:** `http://localhost:8000/health`

---

## 3. Local Development Setup (Native Python)

For active backend development and testing without container overhead:

### 1. Python Virtual Environment

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Launch Local Database & Redis

```bash
docker compose up -d db redis
```

### 3. Run Database Migrations

```bash
alembic upgrade head
```

### 4. Run API Server with Hot Reloading

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 5. Run Celery Worker

```bash
celery -A app.core.celery_app:celery_app worker --loglevel=info --concurrency=4
```

---

## 4. Quality Gates & Testing

Run all quality checks locally before submitting changes:

```bash
# Execute full test suite with coverage
docker compose exec api pytest

# Execute security regression suite only
docker compose exec api pytest -m security

# Run code style & security linting (Ruff)
docker compose exec api ruff check app tests

# Run static type checking (Mypy)
docker compose exec api mypy app/core app/schemas app/services/common.py
```

---

## 5. Production Hardening Checklist

Prior to exposing Zentry in production environments:

- [ ] Set `ENVIRONMENT=production` in `.env`.
- [ ] Generate a cryptographically secure random `JWT_SECRET_KEY` (minimum 32 characters).
- [ ] Change `DATABASE_URL` password from default `securepassword123`.
- [ ] Configure `TRUSTED_PROXIES` with your load balancer / reverse proxy IP addresses.
- [ ] Restrict `CORS_ORIGINS` to production frontend domains.
- [ ] Verify that database and redis ports are isolated from public ingress.
- [ ] Configure an external reverse proxy (Nginx / Cloudflare / Envoy) with TLS termination.
