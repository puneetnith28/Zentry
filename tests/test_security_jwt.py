from datetime import timedelta
import uuid
import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.api.dependencies import get_current_user, get_current_active_superuser
from app.core.config import get_settings
from app.core.security import create_access_token, decode_access_token
from app.db.models import User


def test_create_and_decode_access_token():
    user_id = str(uuid.uuid4())
    token = create_access_token(data={"sub": user_id, "role": "admin"})

    payload = decode_access_token(token)
    assert payload["sub"] == user_id
    assert payload["role"] == "admin"
    assert "exp" in payload
    assert "iat" in payload


def test_expired_access_token():
    user_id = str(uuid.uuid4())
    # Create token that expired 10 minutes ago
    token = create_access_token(
        data={"sub": user_id},
        expires_delta=timedelta(minutes=-10),
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_tampered_access_token():
    token = create_access_token(data={"sub": "123"})
    parts = token.split(".")
    # Modify payload
    tampered_token = f"{parts[0]}.eyJuZXdfc3ViIjoiOTk5In0.{parts[2]}"

    with pytest.raises(jwt.InvalidSignatureError):
        decode_access_token(tampered_token)


def test_get_current_user_no_credentials():
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=None, db=None)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Authentication required"


def test_get_current_user_invalid_token():
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid.token.here")
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=creds, db=None)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Could not validate credentials"


class MockQuery:
    def __init__(self, user):
        self._user = user

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._user


class MockDB:
    def __init__(self, user):
        self._user = user

    def query(self, model):
        return MockQuery(self._user)


def test_get_current_user_success_and_inactive():
    user_id = uuid.uuid4()
    token = create_access_token(data={"sub": str(user_id)})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    # Active user
    user = User(
        id=user_id,
        email="active@example.com",
        hashed_password="hash",
        is_active=True,
        is_superuser=False,
    )
    db = MockDB(user)
    authenticated = get_current_user(credentials=creds, db=db)
    assert authenticated.id == user_id
    assert authenticated.email == "active@example.com"

    # Inactive user
    inactive_user = User(
        id=user_id,
        email="inactive@example.com",
        hashed_password="hash",
        is_active=False,
        is_superuser=False,
    )
    inactive_db = MockDB(inactive_user)
    with pytest.raises(HTTPException) as exc:
        get_current_user(credentials=creds, db=inactive_db)
    assert exc.value.status_code == 403
    assert exc.value.detail == "Inactive user account"


def test_get_current_active_superuser():
    normal_user = User(
        id=uuid.uuid4(),
        email="user@example.com",
        hashed_password="hash",
        is_active=True,
        is_superuser=False,
    )
    with pytest.raises(HTTPException) as exc:
        get_current_active_superuser(current_user=normal_user)
    assert exc.value.status_code == 403

    admin_user = User(
        id=uuid.uuid4(),
        email="admin@example.com",
        hashed_password="hash",
        is_active=True,
        is_superuser=True,
    )
    assert get_current_active_superuser(current_user=admin_user) == admin_user
