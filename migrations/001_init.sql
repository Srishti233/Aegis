-- Aegis initial schema (PostgreSQL + pgvector).
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS api_keys (
    id              TEXT PRIMARY KEY,
    key_hash        TEXT NOT NULL UNIQUE,          -- SHA-256 of the key; raw keys are never stored
    name            TEXT NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    policy_override TEXT,                          -- JSON, merged over the policy for this key
    rpm_limit       INTEGER,                       -- NULL = use global default
    token_budget    BIGINT,                        -- NULL = use global default
    escalation      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    seq           BIGINT PRIMARY KEY,              -- gapless, assigned under a lock
    ts            TEXT NOT NULL,                   -- ISO-8601 UTC (text so hashing is byte-exact)
    api_key_id    TEXT NOT NULL,
    request_id    TEXT NOT NULL,
    direction     TEXT NOT NULL,                   -- input | output
    decision      TEXT NOT NULL,                   -- allow | redact | block
    risk_score    DOUBLE PRECISION NOT NULL,
    would_block   BOOLEAN NOT NULL,
    mode          TEXT NOT NULL,
    matched_rules TEXT NOT NULL,                   -- JSON array
    categories    TEXT NOT NULL,                   -- JSON array
    redactions    TEXT NOT NULL,                   -- JSON object type -> count
    latency_ms    TEXT NOT NULL,                   -- JSON object stage -> ms
    content_hash  TEXT NOT NULL,
    snippet       TEXT NOT NULL,                   -- redacted, truncated
    full_text     TEXT,                            -- only when STORE_FULL_TEXT=true
    prev_hash     TEXT NOT NULL,
    entry_hash    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_request_idx ON audit_events (request_id);

CREATE TABLE IF NOT EXISTS attack_corpus (
    id        SERIAL PRIMARY KEY,
    kind      TEXT NOT NULL,                       -- input | output
    category  TEXT NOT NULL,
    text      TEXT NOT NULL,
    embedding vector(384) NOT NULL
);
CREATE INDEX IF NOT EXISTS attack_corpus_hnsw ON attack_corpus USING hnsw (embedding vector_cosine_ops);

CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
