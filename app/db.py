"""Database access: engine, SQL migrations (PostgreSQL), table definitions, API-key store, bootstrap."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import BigInteger, Boolean, Column, Float, Integer, MetaData, String, Table, Text, create_engine, select, text
from sqlalchemy.engine import Engine

from app.config import ROOT, Settings

log = logging.getLogger("aegis.db")
metadata = MetaData()

api_keys = Table(
    "api_keys", metadata,
    Column("id", String, primary_key=True), Column("key_hash", String, unique=True, nullable=False),
    Column("name", String, nullable=False), Column("is_active", Boolean, nullable=False, default=True),
    Column("policy_override", Text), Column("rpm_limit", Integer), Column("token_budget", BigInteger),
    Column("escalation", Boolean, nullable=False, default=True), Column("created_at", String, nullable=False),
)
audit_events = Table(
    "audit_events", metadata,
    Column("seq", BigInteger, primary_key=True, autoincrement=False), Column("ts", String, nullable=False),
    Column("api_key_id", String, nullable=False), Column("request_id", String, nullable=False),
    Column("direction", String, nullable=False), Column("decision", String, nullable=False),
    Column("risk_score", Float, nullable=False), Column("would_block", Boolean, nullable=False),
    Column("mode", String, nullable=False), Column("matched_rules", Text, nullable=False),
    Column("categories", Text, nullable=False), Column("redactions", Text, nullable=False),
    Column("latency_ms", Text, nullable=False), Column("content_hash", String, nullable=False),
    Column("snippet", Text, nullable=False), Column("full_text", Text), Column("prev_hash", String, nullable=False),
    Column("entry_hash", String, nullable=False),
)
kv = Table("kv", metadata, Column("key", String, primary_key=True), Column("value", Text, nullable=False))


def make_engine(url: str) -> Engine:
    kwargs: dict[str, Any] = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        from sqlalchemy.pool import StaticPool  # noqa: PLC0415

        kwargs = {"connect_args": {"check_same_thread": False}, "poolclass": StaticPool}
    else:
        kwargs.update(pool_size=10, max_overflow=10)
    return create_engine(url, **kwargs)


def is_postgres(engine: Engine) -> bool:
    return engine.dialect.name == "postgresql"


def wait_for_db(engine: Engine, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while True:
        try:
            with engine.connect() as c:
                c.execute(text("SELECT 1"))
            return
        except Exception as exc:  # noqa: BLE001
            if time.time() > deadline:
                raise RuntimeError(f"database not reachable after {timeout}s: {exc}") from exc
            log.info("waiting for database...")
            time.sleep(1.0)


def run_migrations(engine: Engine, directory: Path | None = None) -> list[str]:
    """PostgreSQL: apply migrations/*.sql in order, once each. SQLite (unit tests): create tables from metadata."""
    if not is_postgres(engine):
        metadata.create_all(engine)
        return []
    directory = directory or ROOT / "migrations"
    applied: list[str] = []
    with engine.begin() as c:
        c.execute(text("SELECT pg_advisory_xact_lock(7274710)"))  # serialise concurrent starters
        c.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"))
        done = {r[0] for r in c.execute(text("SELECT name FROM schema_migrations"))}
        for f in sorted(directory.glob("*.sql")):
            if f.name in done:
                continue
            c.exec_driver_sql(f.read_text(encoding="utf-8"))
            c.execute(text("INSERT INTO schema_migrations VALUES (:n, :t)"), {"n": f.name, "t": _now()})
            applied.append(f.name)
    return applied


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class Principal:
    def __init__(self, key_id: str, name: str, policy_override: dict[str, Any] | None, rpm_limit: int | None,
                 token_budget: int | None, escalation: bool):
        self.key_id, self.name, self.policy_override = key_id, name, policy_override
        self.rpm_limit, self.token_budget, self.escalation = rpm_limit, token_budget, escalation


class KeyStore:
    def __init__(self, engine: Engine):
        self.engine = engine

    def upsert(self, key_id: str, raw_key: str, name: str, *, policy_override: dict[str, Any] | None = None,
               rpm_limit: int | None = None, token_budget: int | None = None, escalation: bool = True) -> None:
        values = dict(id=key_id, key_hash=hash_key(raw_key), name=name, is_active=True,
                      policy_override=json.dumps(policy_override) if policy_override else None,
                      rpm_limit=rpm_limit, token_budget=token_budget, escalation=escalation, created_at=_now())
        with self.engine.begin() as c:
            c.execute(api_keys.delete().where(api_keys.c.id == key_id))
            c.execute(api_keys.insert().values(**values))

    def authenticate(self, raw_key: str) -> Principal | None:
        with self.engine.connect() as c:
            row = c.execute(select(api_keys).where(api_keys.c.key_hash == hash_key(raw_key),
                                                  api_keys.c.is_active.is_(True))).mappings().first()
        if not row:
            return None
        po = json.loads(row["policy_override"]) if row["policy_override"] else None
        return Principal(row["id"], row["name"], po, row["rpm_limit"], row["token_budget"], bool(row["escalation"]))


def seed_keys(store: KeyStore, s: Settings) -> None:
    if s.demo_api_key:
        store.upsert("demo", s.demo_api_key, "Demo client")
    if s.demo_limited_key:
        store.upsert("demo-limited", s.demo_limited_key, "Demo client (3 req/min)", rpm_limit=3)
    if s.eval_api_key:  # unlimited, no escalation; one key per policy mode so the harness can test each mode
        for suffix, mode in (("", None), ("-monitor", "monitor"), ("-strict", "strict")):
            store.upsert(f"eval{suffix}", s.eval_api_key + suffix, f"Evaluation harness{suffix}",
                         policy_override={"mode": mode} if mode else None, rpm_limit=10_000_000,
                         token_budget=10_000_000_000, escalation=False)


def kv_get(engine: Engine, key: str) -> str | None:
    with engine.connect() as c:
        r = c.execute(select(kv.c.value).where(kv.c.key == key)).first()
    return r[0] if r else None


def kv_set(engine: Engine, key: str, value: str) -> None:
    with engine.begin() as c:
        c.execute(kv.delete().where(kv.c.key == key))
        c.execute(kv.insert().values(key=key, value=value))
