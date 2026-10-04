"""Helpers shared by the input and output pipelines."""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from app.detectors.secrets import redact, scan_secrets
from app.detectors.types import SecretFinding
from app.policy import ResolvedPolicy

DECISION_ORDER = {"allow": 0, "redact": 1, "block": 2}


def worst(*decisions: str) -> str:
    return max(decisions, key=lambda d: DECISION_ORDER[d])


@contextmanager
def timed(stages: dict[str, float], name: str) -> Iterator[None]:
    t = time.perf_counter()
    try:
        yield
    finally:
        stages[name] = stages.get(name, 0.0) + (time.perf_counter() - t) * 1000.0


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def text_parts(content: Any) -> list[tuple[int | None, str]]:
    """Return [(part_index_or_None, text)] for an OpenAI message `content` (string or list of parts)."""
    if isinstance(content, str):
        return [(None, content)]
    if isinstance(content, list):
        return [(i, p["text"]) for i, p in enumerate(content)
                if isinstance(p, dict) and p.get("type") == "text" and isinstance(p.get("text"), str)]
    return []


def apply_secret_policy(text: str, policy: ResolvedPolicy) -> tuple[list[SecretFinding], str, bool]:
    """Scan, assign actions per policy, return (findings, redacted_text, has_block)."""
    raw = scan_secrets(text)
    findings = [SecretFinding(f.type, f.start, f.end, policy.secret_action(f.type)) for f in raw]
    has_block = any(f.action == "block" for f in findings)
    return findings, redact(text, findings), has_block
