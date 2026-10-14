# Database Operations and Disaster Recovery Guide

This guide establishes authoritative operational procedures for managing the PostgreSQL relational database backing Zentry, covering schema migrations, automated backups, disaster recovery, and connection pool governance.

---

## 1. Schema Architecture & Data Models

Zentry relies on PostgreSQL 15+ as its primary persistent datastore. The schema consists of three core tables managed via SQLAlchemy models and tracked through Alembic revisions:

- **`users`**: Multi-tenant user accounts with hashed credentials (`bcrypt`), active status flags, role flags (`is_superuser`), and audit timestamps.
- **`scan_jobs`**: Scan executions with target domains, status transitions (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`), risk scores (`0-100`), raw result payloads, and foreign-key isolation linked to `users.id`.
- **`scan_findings`**: Canonical, deduplicated vulnerability and posture findings indexed by deterministic fingerprint (`fingerprint`), severity, category, and target domain.

---

## 2. Schema Migrations with Alembic

All database modifications must be executed through versioned Alembic migrations to ensure forward and backward compatibility across environments.

### Execution Commands

```bash
# Verify current migration revision applied to database
docker compose exec api alembic current

# Inspect migration history and revision tree
docker compose exec api alembic history --verbose

# Apply all pending migrations to head
docker compose exec api alembic upgrade head

# Rollback single migration step
docker compose exec api alembic downgrade -1

# Rollback to base (empty schema)
docker compose exec api alembic downgrade base
```

### Creating New Migrations

```bash
# Generate automated migration from model metadata diff
docker compose exec api alembic revision --autogenerate -m "describe_schema_change"

# Review the generated file in alembic/versions/ before applying
docker compose exec api alembic upgrade head
```

---

## 3. Automated Backup Procedures

Production databases must have automated daily backups with a minimum retention window of 30 days.

### Full Logical Backup via `pg_dump`

```bash
#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="/var/backups/zentry"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/zentry_db_${TIMESTAMP}.dump"

mkdir -p "${BACKUP_DIR}"

# Execute compressed custom-format pg_dump
docker compose exec -T db pg_dump \
  -U postgres \
  -d security_scanner \
  -F c \
  -b \
  -v \
  -f "/tmp/backup.dump"

# Copy backup archive out of container
docker compose cp db:/tmp/backup.dump "${BACKUP_FILE}"
docker compose exec db rm -f /tmp/backup.dump

echo "Backup created successfully: ${BACKUP_FILE}"
```

---

## 4. Disaster Recovery and Restoration

In the event of database failure or corrupted state, perform recovery using the following procedure:

### Full Restoration Workflow

1. **Stop active API and worker services** to prevent concurrent writes:
   ```bash
   docker compose stop api worker
   ```

2. **Re-create or clean target database**:
   ```bash
   docker compose exec db psql -U postgres -c "DROP DATABASE IF EXISTS security_scanner;"
   docker compose exec db psql -U postgres -c "CREATE DATABASE security_scanner;"
   ```

3. **Restore from verified dump file**:
   ```bash
   docker compose cp /var/backups/zentry/zentry_db_<TIMESTAMP>.dump db:/tmp/restore.dump
   docker compose exec db pg_restore \
     -U postgres \
     -d security_scanner \
     -v \
     --clean \
     --if-exists \
     /tmp/restore.dump
   docker compose exec db rm -f /tmp/restore.dump
   ```

4. **Verify schema head and run consistency checks**:
   ```bash
   docker compose exec api alembic current
   docker compose exec db psql -U postgres -d security_scanner -c "SELECT count(*) FROM users; SELECT count(*) FROM scan_jobs;"
   ```

5. **Restart application services**:
   ```bash
   docker compose start api worker
   ./scripts/smoke_test.sh
   ```

---

## 5. Connection Pooling and Operational Tuning

Database performance is governed by pool settings defined in `app/core/config.py`:

| Parameter | Default | Production Guideline | Description |
|---|:---:|:---:|---|
| `DB_POOL_SIZE` | `10` | `20–50` | Persistent connection pool size per worker process. |
| `DB_MAX_OVERFLOW` | `20` | `30–50` | Burst overflow connections allowed above pool size. |
| `DB_POOL_TIMEOUT` | `30.0s` | `30.0s` | Maximum duration to block before failing on pool exhaustion. |
| `DB_POOL_RECYCLE_SECONDS` | `1800s` | `1800s` | Automatic connection recycling window preventing stale TCP sockets. |
