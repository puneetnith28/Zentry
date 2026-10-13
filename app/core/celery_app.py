import logging

from celery import Celery
import redis

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

celery_app = Celery(
    "zentry",
    broker=settings.celery_broker_url,
    backend=settings.celery_broker_url,
    include=["app.worker.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)


def get_queue_depth(queue_name: str = "celery") -> int:
    """Return the current number of pending tasks in the broker queue."""
    current_settings = get_settings()
    broker_url = current_settings.celery_broker_url
    if broker_url.startswith("redis://"):
        try:
            r = redis.Redis.from_url(broker_url, socket_timeout=2.0)
            depth = r.llen(queue_name)
            r.close()
            return int(depth)
        except Exception as exc:
            logger.warning("Failed to inspect Redis queue depth: %s", exc)
            return 0
    try:
        with celery_app.connection_for_read() as conn:
            channel = conn.default_channel
            if hasattr(channel, "client") and hasattr(channel.client, "llen"):
                return int(channel.client.llen(queue_name))
            return 0
    except Exception as exc:
        logger.warning("Failed to inspect broker queue depth: %s", exc)
        return 0
