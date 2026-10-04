"""Service container: wires config, DB, detectors, policy, Redis, audit log and the upstream HTTP client."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import redis as redis_lib
from sqlalchemy.engine import Engine

from app.audit import AuditLog
from app.config import Settings
from app.db import KeyStore, is_postgres, kv_get, kv_set, make_engine, run_migrations, seed_keys, wait_for_db
from app.detectors.embeddings import get_embedder
from app.detectors.rules import RuleSet
from app.detectors.semantic import MemoryVectorStore, PgVectorStore, SemanticDetector, VectorStore
from app.metrics import Metrics
from app.policy import PolicyEngine
from app.ratelimit import RateLimiter

log = logging.getLogger("aegis.services")


@dataclass
class Services:
    settings: Settings
    engine: Engine
    keys: KeyStore
    audit: AuditLog
    limiter: RateLimiter
    policy: PolicyEngine
    rules: RuleSet
    semantic: SemanticDetector
    metrics: Metrics
    http: httpx.AsyncClient

    def reload(self) -> dict[str, Any]:
        """Hot-reload policy.yaml and rules.yaml. Raises (and keeps the old config) if either is invalid."""
        new_rules = RuleSet.load(self.settings.rules_path)
        info = self.policy.reload()
        self.rules = new_rules
        return {**info, "rules": len(new_rules.rules)}


def build_services(settings: Settings, *, engine: Engine | None = None, redis_client: Any = None,
                   http_transport: httpx.AsyncBaseTransport | None = None,
                   vector_store: VectorStore | None = None) -> Services:
    engine = engine or make_engine(settings.database_url)
    wait_for_db(engine)
    run_migrations(engine)
    keys = KeyStore(engine)
    seed_keys(keys, settings)

    embedder = get_embedder(settings.embedder)
    store = vector_store or (PgVectorStore(engine) if is_postgres(engine) else MemoryVectorStore())
    semantic = SemanticDetector(embedder, store)
    corpus_sig = hashlib.sha256(Path(settings.corpus_path).read_bytes() + embedder.name.encode()).hexdigest()
    if isinstance(store, MemoryVectorStore) or kv_get(engine, "corpus_sig") != corpus_sig or store.count() == 0:
        n = semantic.seed(settings.corpus_path)
        if not isinstance(store, MemoryVectorStore):
            kv_set(engine, "corpus_sig", corpus_sig)
        log.info("seeded attack corpus: %d entries (%s)", n, embedder.name)

    r = redis_client or redis_lib.Redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=2)
    http = httpx.AsyncClient(base_url=settings.upstream_url.rstrip("/"), timeout=settings.upstream_timeout,
                             transport=http_transport)
    return Services(settings=settings, engine=engine, keys=keys,
                    audit=AuditLog(engine, settings.store_full_text), limiter=RateLimiter(r, settings),
                    policy=PolicyEngine(settings.policy_path), rules=RuleSet.load(settings.rules_path),
                    semantic=semantic, metrics=Metrics(), http=http)
