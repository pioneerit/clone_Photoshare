import unittest
from unittest.mock import MagicMock, AsyncMock, Mock, patch

import pytest

from src.database.models import User
from src.config import detail
from src.services.auth import auth_service
from tests.mock_redis_methods import MockRedis


def test_create_user(client, user, monkeypatch):
    mock_send_email = MagicMock()
    monkeypatch.setattr('fastapi_limiter.FastAPILimiter.redis', AsyncMock())
    monkeypatch.setattr('fastapi_limiter.FastAPILimiter.identifier', AsyncMock())
    monkeypatch.setattr('fastapi_limiter.FastAPILimiter.http_callback', AsyncMock())
    monkeypatch.setattr("src.routes.auth.send_email", mock_send_email)
    response = client.post("/api/auth/signup", json=user)
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["user"]["email"] == user.get('email')
    assert "id" in payload["user"]


def test_repeat_create_user(client, user, monkeypatch):
    mock_send_email = MagicMock()
    monkeypatch.setattr('fastapi_limiter.FastAPILimiter.redis', AsyncMock())
    monkeypatch.setattr('fastapi_limiter.FastAPILimiter.identifier', AsyncMock())
    monkeypatch.setattr('fastapi_limiter.FastAPILimiter.http_callback', AsyncMock())
    monkeypatch.setattr("src.routes.auth.send_email", mock_send_email)
    response = client.post("/api/auth/signup", json=user)
    assert response.status_code == 409, response.text
    payload = response.json()
    assert payload["detail"] == detail.ACCOUNT_AlREADY_EXISTS


def test_login_user_not_active(client, session, user):
    current_user: User = session.query(User).filter(User.email == user.get('email')).first()
    current_user.confirmed = True
    current_user.is_active = False
    session.commit()
    response = client.post(
        "/api/auth/login",
        data={"username": user.get('email'), "password": user.get('password')},
    )
    # USER_NOT_ACTIVE
    assert response.status_code == 403, response.text
    data = response.json()
    assert data["detail"] == detail.USER_NOT_ACTIVE


def test_login_user_not_confirmed_email(client, user, session):
    current_user: User = session.query(User).filter(User.email == user.get("email")).first()
    current_user.confirmed = False
    current_user.is_active = True
    session.commit()
    response = client.post("/api/auth/login", data={"username": user.get("email"), "password": user.get("password")})
    assert response.status_code == 401, response.text
    payload = response.json()
    assert payload["detail"] == detail.EMAIL_NOT_CONFIRMED


def test_login_user(client, user, session):
    current_user: User = session.query(User).filter(User.email == user.get("email")).first()
    current_user.confirmed = True
    current_user.is_active = True
    session.commit()
    response = client.post("/api/auth/login", data={"username": user.get("email"), "password": user.get("password")})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["token_type"] == "bearer"


def test_login_user_with_wrong_password(client, user, session):
    current_user: User = session.query(User).filter(User.email == user.get("email")).first()
    current_user.confirmed = True
    current_user.is_active = True
    session.commit()
    response = client.post("/api/auth/login", data={"username": user.get("email"), "password": "password"})
    assert response.status_code == 401, response.text
    payload = response.json()
    assert payload["detail"] == detail.INVALID_PASSWORD


def test_login_user_with_wrong_email(client, user, session):
    current_user: User = session.query(User).filter(User.email == user.get("email")).first()
    current_user.confirmed = True
    current_user.is_active = True
    session.commit()
    response = client.post("/api/auth/login", data={"username": "eaxample@test.com", "password": user.get("password")})
    assert response.status_code == 401, response.text
    payload = response.json()
    assert payload["detail"] == detail.INVALID_EMAIL


# @pytest.mark.asyncio
# @patch.object(auth_service, "blocklist")

# @pytest.fixture()
# def test_logout(client, session, user, monkeypatch):
#     monkeypatch.setattr("src.service.auth.Auth.is_blocklisted", value=False)
#     current_user: User = session.query(User).filter(User.email == user.get("email")).first()
#     current_user.confirmed = True
#     current_user.is_active = True
#     session.commit()
#     response = client.post("/api/auth/login", data={"username": user.get("email"), "password": user.get("password")})
#     assert response.status_code == 200, response.text
#     payload = response.json()
#     assert payload["token_type"] == "bearer"
#     headers = {"Authorization": f"Bearer {payload['access_token']}"}
#     response = client.post("/api/auth/logout", headers=headers)
#     assert response.status_code == 200, response.text
#     payload = response.json()
#     assert payload["detail"] == detail.USER_IS_LOGOUT
# @patch("redis.Redis")
@patch("redis.Redis")
def test_logout(mock_redis, client, session, user):
    redis_cache = {
        "foo": "bar",
        "foobar": {"Foo": "Bar"}
    }

    mock_redis_obj = MockRedis(redis_cache)

    # binding a side_effect of a MagicMock instance with redis methods we defined in the MockRedis class.
    mock_redis_method = MagicMock()
    mock_redis_method.hget = Mock(side_effect=mock_redis_obj.get)
    mock_redis_method.hget = Mock(side_effect=mock_redis_obj.hget)
    mock_redis_method.set = Mock(side_effect=mock_redis_obj.set)
    mock_redis_method.hset = Mock(side_effect=mock_redis_obj.hset)
    mock_redis_method.exists = Mock(side_effect=mock_redis_obj.exists)

    # StrictRedis mock return_values is set as above mock_redis_method.
    mock_redis.return_value = mock_redis_method

    current_user: User = session.query(User).filter(User.email == user.get("email")).first()
    current_user.confirmed = True
    current_user.is_active = True
    session.commit()
    response = client.post("/api/auth/login", data={"username": user.get("email"), "password": user.get("password")})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["token_type"] == "bearer"
    headers = {"Authorization": f"Bearer {payload['access_token']}"}
    response = client.post("/api/auth/logout", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["detail"] == detail.USER_IS_LOGOUT


def test_refresh_token_ok(client, session, user):
    current_user: User = session.query(User).filter(User.email == user.get('email')).first()
    headers = {'Authorization': f'Bearer {current_user.refresh_token}'}
    response = client.get('api/auth/refresh_token', headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()['token_type'] == 'bearer'  # m.TOKEN_TYPE
    assert response.json()['access_token'] is not None
    assert response.json()['refresh_token'] is not None


def test_invalid_refresh_token_ok(client, session, user):
    current_user: User = session.query(User).filter(User.email == user.get('email')).first()
    headers = {'Authorization': f'Bearer {"ghjg"}'}
    response = client.get('api/auth/refresh_token', headers=headers)
    assert response.status_code == 401, response.text


if __name__ == '__main__':
    unittest.main()
