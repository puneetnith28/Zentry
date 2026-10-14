import logging
import time
from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()



def create_app_engine(database_url: str | None = None, current_settings=None):
    """Create SQLAlchemy engine with robust connection pooling and keepalive settings."""
    if current_settings is None:
        current_settings = get_settings()
    url = database_url or current_settings.database_url
    engine_kwargs: dict = {
        "pool_pre_ping": True,
    }
    if not url.startswith("sqlite"):
        engine_kwargs.update(
            {
                "pool_size": current_settings.db_pool_size,
                "max_overflow": current_settings.db_max_overflow,
                "pool_timeout": current_settings.db_pool_timeout,
                "pool_recycle": current_settings.db_pool_recycle_seconds,
                "connect_args": {"connect_timeout": 10},
            }
        )
    return create_engine(url, **engine_kwargs)


engine = create_app_engine()
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


def dispose_db() -> None:
    """Explicitly dispose the SQLAlchemy engine and all pooled database connections."""
    try:
        engine.dispose()
    except Exception as exc:
        logger.warning("Error disposing database connection pool: %s", exc)


def get_db() -> Generator[Session, None, None]:

    """Yield a database session, automatically rolling back on exception and closing on completion."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
