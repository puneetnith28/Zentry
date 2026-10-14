from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy.exc import OperationalError

from app.db.models import Base
from app.db.session import check_db_connectivity, init_db


def test_init_db_does_not_call_create_all():
    with patch.object(Base.metadata, "create_all") as mock_create_all:
        with patch("app.db.session.engine.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_connect.return_value.__enter__.return_value = mock_conn

            init_db()

            mock_create_all.assert_not_called()
            mock_connect.assert_called_once()
            mock_conn.execute.assert_called_once()


def test_check_db_connectivity_retries_on_operational_error():
    with patch("app.db.session.time.sleep") as mock_sleep:
        with patch("app.db.session.engine.connect") as mock_connect:
            mock_conn = MagicMock()
            # Fail twice with OperationalError, then succeed
            mock_connect.side_effect = [
                OperationalError("connection failed", None, None),
                OperationalError("connection failed", None, None),
                MagicMock(__enter__=MagicMock(return_value=mock_conn), __exit__=MagicMock()),
            ]

            check_db_connectivity(max_retries=3, retry_interval=0.1)

            assert mock_connect.call_count == 3
            assert mock_sleep.call_count == 2


def test_check_db_connectivity_raises_after_max_retries():
    with patch("app.db.session.time.sleep"):
        with patch("app.db.session.engine.connect") as mock_connect:
            mock_connect.side_effect = OperationalError("connection failed", None, None)

            with pytest.raises(OperationalError):
                check_db_connectivity(max_retries=2, retry_interval=0.01)

            assert mock_connect.call_count == 2


def test_get_db_clean_lifecycle():
    from app.db.session import get_db

    with patch("app.db.session.SessionLocal") as mock_session_cls:
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        gen = get_db()
        db = next(gen)
        assert db == mock_session
        mock_session.close.assert_not_called()

        with pytest.raises(StopIteration):
            next(gen)

        mock_session.rollback.assert_not_called()
        mock_session.close.assert_called_once()


def test_get_db_rollback_on_unhandled_exception():
    from app.db.session import get_db

    with patch("app.db.session.SessionLocal") as mock_session_cls:
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        gen = get_db()
        db = next(gen)
        assert db == mock_session

        with pytest.raises(RuntimeError, match="simulated error"):
            gen.throw(RuntimeError("simulated error"))

        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()


def test_create_app_engine_pool_tuning_and_timeouts():
    from app.db.session import create_app_engine
    with patch("app.db.session.create_engine") as mock_ce:
        create_app_engine("postgresql://postgres:secret@db:5432/test")
        mock_ce.assert_called_once()
        _, kwargs = mock_ce.call_args
        assert kwargs["pool_pre_ping"] is True
        assert kwargs["pool_size"] == 10
        assert kwargs["max_overflow"] == 20
        assert kwargs["pool_timeout"] == 30.0
        assert kwargs["pool_recycle"] == 1800
        assert kwargs["connect_args"] == {"connect_timeout": 10}


def test_dispose_db_calls_engine_dispose():
    from app.db.session import dispose_db

    with patch("app.db.session.engine.dispose") as mock_dispose:
        dispose_db()
        mock_dispose.assert_called_once()


