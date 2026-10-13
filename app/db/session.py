import time
from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.models import Base

settings = get_settings()

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def check_db_connectivity(max_retries: int = 10, retry_interval: float = 2.0) -> None:
    """Verify database connection without modifying or generating schema at runtime.

    Alembic migrations are authoritative for all database schema creation and alteration.
    Runtime schema generation via create_all() is strictly disabled in production.
    """
    for attempt in range(max_retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except OperationalError:
            if attempt == max_retries - 1:
                raise
            time.sleep(retry_interval)


def init_db() -> None:
    """Startup database initialization hook asserting connectivity without runtime schema mutation."""
    check_db_connectivity()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
