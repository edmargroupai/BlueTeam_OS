from __future__ import annotations

import os
from collections.abc import Generator

import pytest

os.environ.setdefault("BTOS_ENV", "development")
os.environ.setdefault("BTOS_SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("BTOS_DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("BTOS_DEV_SEED", "true")
os.environ.setdefault("BTOS_DEV_PASSWORD", "test-password-change-me")
os.environ.setdefault("BTOS_AI_ENABLED", "false")
# Keep unit tests off the local dataplane (Kafka bootstrap hangs for ~30s when configured).
os.environ["BTOS_KAFKA_BOOTSTRAP"] = ""
os.environ["BTOS_CLICKHOUSE_URL"] = ""
os.environ["BTOS_OPENSEARCH_URL"] = ""
os.environ["BTOS_REDIS_URL"] = ""
os.environ["BTOS_S3_ENDPOINT"] = ""

from app.core.config import get_settings  # noqa: E402
from app.core.db import get_engine, reset_engine  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models.base import Base  # noqa: E402
from app.services.seed import DEMO_TENANT_ID, PLATFORM_TENANT_ID  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

get_settings.cache_clear()


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    get_settings.cache_clear()
    reset_engine()
    app = create_app()
    Base.metadata.create_all(bind=get_engine())
    with TestClient(app) as test_client:
        yield test_client
    reset_engine()
    get_settings.cache_clear()


@pytest.fixture()
def demo_tenant() -> str:
    return DEMO_TENANT_ID


@pytest.fixture()
def platform_tenant() -> str:
    return PLATFORM_TENANT_ID


def login(client: TestClient, email: str, password: str = "test-password-change-me") -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_headers(token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant_id}
