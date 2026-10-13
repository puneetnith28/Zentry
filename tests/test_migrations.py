import os
from pathlib import Path
import uuid
import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
import sqlalchemy as sa
from sqlalchemy import text

from app.core.config import get_settings


@pytest.fixture
def alembic_config() -> Config:
    root_dir = Path(__file__).resolve().parent.parent
    ini_path = root_dir / "alembic.ini"
    cfg = Config(str(ini_path))
    cfg.set_main_option("script_location", str(root_dir / "alembic"))
    return cfg


def test_migration_revision_chain(alembic_config: Config):
    script = ScriptDirectory.from_config(alembic_config)
    heads = script.get_heads()
    assert len(heads) == 1, "Alembic must have exactly one head revision"
    assert heads[0] == "003", "Current head revision must be 003"

    rev_003 = script.get_revision("003")
    assert rev_003.down_revision == "002"

    rev_002 = script.get_revision("002")
    assert rev_002.down_revision == "001"

    rev_001 = script.get_revision("001")
    assert rev_001.down_revision is None


def test_all_migrations_define_upgrade_and_downgrade(alembic_config: Config):
    script = ScriptDirectory.from_config(alembic_config)
    for rev in script.walk_revisions():
        module = rev.module
        assert hasattr(module, "upgrade"), f"Revision {rev.revision} missing upgrade()"
        assert callable(module.upgrade), f"Revision {rev.revision} upgrade is not callable"
        assert hasattr(module, "downgrade"), f"Revision {rev.revision} missing downgrade()"
        assert callable(module.downgrade), f"Revision {rev.revision} downgrade is not callable"


def test_migration_fresh_database_upgrade_and_downgrade_cycle(alembic_config: Config):
    settings = get_settings()
    # Only run real Postgres lifecycle test when connected to a Postgres instance
    if not settings.database_url.startswith("postgresql"):
        pytest.skip("Skipping PostgreSQL migration cycle in non-PostgreSQL environment")

    # Connect to the default 'postgres' database to create an ephemeral test database
    base_url, db_name = settings.database_url.rsplit("/", 1)
    admin_url = f"{base_url}/postgres"
    temp_db_name = f"test_mig_{uuid.uuid4().hex[:8]}"

    admin_engine = sa.create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with admin_engine.connect() as conn:
            conn.execute(text(f"CREATE DATABASE {temp_db_name};"))
    except Exception as exc:
        pytest.skip(f"Could not create ephemeral database on Postgres: {exc}")

    temp_db_url = f"{base_url}/{temp_db_name}"
    alembic_config.set_main_option("sqlalchemy.url", temp_db_url)

    try:
        # 1. Upgrade from empty to head
        command.upgrade(alembic_config, "head")

        # Verify created tables and indexes
        temp_engine = sa.create_engine(temp_db_url)
        with temp_engine.connect() as conn:
            inspector = sa.inspect(conn)
            tables = set(inspector.get_table_names())
            assert "alembic_version" in tables
            assert "scan_jobs" in tables
            assert "users" in tables

            # Verify performance index exists
            indexes = {idx["name"] for idx in inspector.get_indexes("scan_jobs")}
            assert "ix_scan_jobs_user_id_created_at" in indexes

        temp_engine.dispose()

        # 2. Downgrade from head to base
        command.downgrade(alembic_config, "base")

        temp_engine2 = sa.create_engine(temp_db_url)
        with temp_engine2.connect() as conn:
            inspector2 = sa.inspect(conn)
            tables_after = set(inspector2.get_table_names())
            assert "scan_jobs" not in tables_after
            assert "users" not in tables_after
        temp_engine2.dispose()

        # 3. Upgrade back to head to verify idempotent re-upgrade
        command.upgrade(alembic_config, "head")
        temp_engine3 = sa.create_engine(temp_db_url)
        with temp_engine3.connect() as conn:
            inspector3 = sa.inspect(conn)
            tables_final = set(inspector3.get_table_names())
            assert "scan_jobs" in tables_final
            assert "users" in tables_final
        temp_engine3.dispose()

    finally:
        with admin_engine.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS {temp_db_name} WITH (FORCE);"))
        admin_engine.dispose()
