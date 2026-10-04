"""Shared fixtures. Unit/API tests run with SQLite + fakeredis + in-memory vectors + the mock LLM mounted via ASGI,
so `pytest` needs no services. Tests marked `integration` need real Postgres/Redis (AEGIS_TEST_DATABASE_URL)."""
from __future__ import annotations

import os
from pathlib import Path

import fakeredis
import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import ROOT, Settings
from app.detectors.embeddings import HashingEmbedder
from app.detectors.rules import RuleSet
from app.detectors.semantic import MemoryVectorStore, SemanticDetector
from app.main import create_app
from app.policy import PolicyEngine
from app.services import build_services
from mock_llm.main import app as mock_app

ADMIN = {"X-Admin-Key": "test-admin"}
AUTH = {"Authorization": "Bearer test-key"}


@pytest.fixture(scope="session")
def rules() -> RuleSet:
    return RuleSet.load(ROOT / "rules.yaml")


@pytest.fixture(scope="session")
def policy_engine() -> PolicyEngine:
    return PolicyEngine(ROOT / "policy.yaml")


@pytest.fixture(scope="session")
def semantic() -> SemanticDetector:
    d = SemanticDetector(HashingEmbedder(), MemoryVectorStore())
    d.seed(ROOT / "app" / "data" / "attack_corpus.jsonl")
    return d


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(database_url=f"sqlite:///{tmp_path}/t.db", redis_url="redis://unused", admin_api_key="test-admin",
                    demo_api_key="test-key", demo_limited_key="limited-key", eval_api_key="", embedder="hash",
                    exfil_allowed_domains="allowed.example", upstream_url="http://mock")


@pytest.fixture
def client(settings: Settings):
    services = build_services(settings, redis_client=fakeredis.FakeRedis(decode_responses=True),
                              http_transport=httpx.ASGITransport(app=mock_app))
    with TestClient(create_app(settings, services)) as c:
        c.services = services  # type: ignore[attr-defined]
        yield c


def chat(client: TestClient, content: str, headers: dict | None = None, **extra):
    body = {"model": "mock-gpt", "messages": [{"role": "user", "content": content}], **extra}
    return client.post("/v1/chat/completions", json=body, headers=headers or AUTH)


requires_pg = pytest.mark.skipif(not os.getenv("AEGIS_TEST_DATABASE_URL"), reason="set AEGIS_TEST_DATABASE_URL (and REDIS) for integration tests")
