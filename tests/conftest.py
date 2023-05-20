import sys
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from main import app
from src.database.models import Base
from src.database.db import get_db

import src.services.auth as auth_module
from tests.mock_redis_methods import MockRedis

sys.path.append(os.getcwd())

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(autouse=True)
def mock_redis():
    with patch.object(auth_module, 'redis', new_callable=MockRedis, create=True):
        yield

@pytest.fixture(scope="module")
def session():
    # Create the database

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def client(session):
    # Dependency override

    def override_get_db():
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    yield TestClient(app)


@pytest.fixture(scope="module")
def user():
    return {
        "username": "boroda",
        "email": "boroda@example.com",
        "password": "12345678",
        "is_active": "True",
        "avatar": "http://someurl.jpeg",
        "roles": "Admin"
    }
