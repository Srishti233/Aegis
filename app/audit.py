"""Tamper-evident audit log: every row commits to the previous row's hash.

entry_hash = SHA256(prev_hash + canonical_json(entry))   (entry excludes prev_hash / entry_hash themselves)
Editing, deleting or reordering any row breaks the chain from that point on, and /admin/audit/verify reports
the first broken sequence number. Truncating the *tail* is only detectable by comparing the head hash with an
externally anchored copy (e.g. the planned on-chain anchoring).
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.engine import Engine

from app.db import audit_events as T
from app.db import is_postgres

GENESIS = "0" * 64
JSON_COLS = ("matched_rules", "categories", "redactions", "latency_ms")
HASHED_FIELDS = ("seq", "ts", "api_key_id", "request_id", "direction", "decision", "risk_score", "would_block",
                 "mode", "matched_rules", "categories", "redactions", "latency_ms", "content_hash", "snippet",
                 "full_text")


def canonical(entry: dict[str, Any]) -> str:
    return json.dumps({k: entry[k] for k in HASHED_FIELDS}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical(entry)).encode("utf-8")).hexdigest()


def _row_to_entry(row: Any) -> dict[str, Any]:
    e = {k: row[k] for k in HASHED_FIELDS}
    for c in JSON_COLS:
        e[c] = json.loads(e[c])
    e["risk_score"] = round(float(e["risk_score"]), 4)
    e["would_block"] = bool(e["would_block"])
    return e


class AuditLog:
    def __init__(self, engine: Engine, store_full_text: bool = False):
        self.engine = engine
        self.store_full_text = store_full_text
        self._lock = threading.Lock()

    def append(self, *, api_key_id: str, request_id: str, direction: str, decision: str, risk_score: float,
               would_block: bool, mode: str, matched_rules: list[str], categories: list[str],
               redactions: dict[str, int], latency_ms: dict[str, float], content_hash: str, snippet: str,
               full_text: str | None = None) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="microseconds"), "api_key_id": api_key_id,
            "request_id": request_id, "direction": direction, "decision": decision,
            "risk_score": round(float(risk_score), 4), "would_block": bool(would_block), "mode": mode,
            "matched_rules": list(matched_rules), "categories": list(categories), "redactions": dict(redactions),
            "latency_ms": {k: round(v, 3) for k, v in latency_ms.items()}, "content_hash": content_hash,
            "snippet": snippet, "full_text": full_text if self.store_full_text else None,
        }
        with self._lock, self.engine.begin() as conn:
            if is_postgres(self.engine):
                conn.execute(text("SELECT pg_advisory_xact_lock(7274711)"))  # serialise across workers
            last = conn.execute(select(T.c.seq, T.c.entry_hash).order_by(T.c.seq.desc()).limit(1)).first()
            seq, prev = (last[0] + 1, last[1]) if last else (1, GENESIS)
            entry["seq"] = seq
            entry_hash = compute_hash(prev, entry)
            row = dict(entry)
            for c in JSON_COLS:
                row[c] = json.dumps(row[c], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            conn.execute(T.insert().values(**row, prev_hash=prev, entry_hash=entry_hash))
        entry.update(prev_hash=prev, entry_hash=entry_hash)
        return entry

    def verify(self) -> dict[str, Any]:
        """Walk the whole chain. Returns {intact, checked, first_break_seq, reason, head_hash}."""
        prev, checked, expected_seq = GENESIS, 0, 1
        with self.engine.connect() as conn:
            rows = conn.execute(select(T).order_by(T.c.seq)).mappings()
            for row in rows:
                if row["seq"] != expected_seq:
                    return self._report(False, checked, expected_seq, f"sequence gap: expected {expected_seq}, found {row['seq']}", prev)
                if row["prev_hash"] != prev:
                    return self._report(False, checked, row["seq"], "prev_hash does not match previous entry", prev)
                if compute_hash(prev, _row_to_entry(row)) != row["entry_hash"]:
                    return self._report(False, checked, row["seq"], "entry content does not match its hash (row was modified)", prev)
                prev, checked, expected_seq = row["entry_hash"], checked + 1, expected_seq + 1
        return self._report(True, checked, None, None, prev)

    @staticmethod
    def _report(intact: bool, checked: int, brk: int | None, reason: str | None, head: str) -> dict[str, Any]:
        return {"intact": intact, "entries_checked": checked, "first_break_seq": brk, "reason": reason, "head_hash": head}

    def head(self) -> dict[str, Any]:
        with self.engine.connect() as conn:
            r = conn.execute(select(T.c.seq, T.c.entry_hash, T.c.ts).order_by(T.c.seq.desc()).limit(1)).first()
        return {"seq": r[0], "entry_hash": r[1], "ts": r[2]} if r else {"seq": 0, "entry_hash": GENESIS, "ts": None}

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(T).order_by(T.c.seq.desc()).limit(limit)).mappings().all()
        return [{k: v for k, v in _row_to_entry(r).items() if k != "full_text"} | {"entry_hash": r["entry_hash"]} for r in rows]
