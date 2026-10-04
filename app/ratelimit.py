"""Redis rate limiting: sliding-window RPM, hourly token budget, strike-based escalation and cooldown."""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

from app.config import Settings

log = logging.getLogger("aegis.ratelimit")


@dataclass
class LimitResult:
    allowed: bool = True
    kind: str | None = None  # rpm | tokens
    retry_after: int = 0
    limit: int = 0
    remaining: int = 0
    cooldown: bool = False
    degraded: bool = False


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class RateLimiter:
    WINDOW = 60.0
    STRIKE_TTL = 3600

    def __init__(self, redis_client: Any, settings: Settings):
        self.r, self.s = redis_client, settings

    def ping(self) -> bool:
        try:
            return bool(self.r.ping())
        except Exception:  # noqa: BLE001
            return False

    def check(self, key_id: str, rpm: int | None, token_budget: int | None, est_tokens: int) -> LimitResult:
        rpm = rpm or self.s.rate_limit_rpm
        budget = token_budget or self.s.token_budget_per_hour
        now = time.time()
        try:
            cooldown = bool(self.r.exists(f"aegis:cooldown:{key_id}"))
            eff_rpm = max(1, rpm // 4) if cooldown else rpm

            tok_key = f"aegis:tok:{key_id}:{int(now // 3600)}"
            used = int(self.r.get(tok_key) or 0)
            if used + est_tokens > budget:
                return LimitResult(False, "tokens", int(3600 - now % 3600) + 1, budget, 0, cooldown)

            zkey, member = f"aegis:rpm:{key_id}", f"{now:.6f}:{uuid.uuid4().hex[:8]}"
            pipe = self.r.pipeline(transaction=True)
            pipe.zremrangebyscore(zkey, 0, now - self.WINDOW)
            pipe.zadd(zkey, {member: now})
            pipe.zcard(zkey)
            pipe.zrange(zkey, 0, 0, withscores=True)
            pipe.expire(zkey, int(self.WINDOW) + 5)
            _, _, count, oldest, _ = pipe.execute()
            if count > eff_rpm:
                self.r.zrem(zkey, member)
                retry = int(max(1.0, (oldest[0][1] + self.WINDOW) - now)) + 1 if oldest else int(self.WINDOW)
                return LimitResult(False, "rpm", retry, eff_rpm, 0, cooldown)

            pipe = self.r.pipeline(transaction=True)
            pipe.incrby(tok_key, est_tokens)
            pipe.expire(tok_key, 3700)
            pipe.execute()
            return LimitResult(True, None, 0, eff_rpm, max(0, eff_rpm - count), cooldown)
        except Exception as exc:  # noqa: BLE001
            log.error("rate limiter backend error: %s", exc)
            if self.s.rate_limit_fail_open:
                return LimitResult(True, degraded=True)
            return LimitResult(False, "unavailable", 5)

    def strikes(self, key_id: str) -> int:
        try:
            return int(self.r.get(f"aegis:strikes:{key_id}") or 0)
        except Exception:  # noqa: BLE001
            return 0

    def record_block(self, key_id: str) -> int:
        """Called whenever a request/response from this key is blocked."""
        try:
            k = f"aegis:strikes:{key_id}"
            n = int(self.r.incr(k))
            self.r.expire(k, self.STRIKE_TTL)
            if n >= self.s.strike_threshold:
                self.r.set(f"aegis:cooldown:{key_id}", "1", ex=self.s.cooldown_seconds)
            return n
        except Exception:  # noqa: BLE001
            return 0

    def risk_bonus(self, key_id: str, max_bonus: float) -> float:
        n = self.strikes(key_id)
        return min(max_bonus, 0.1 * n)

    def in_cooldown(self, key_id: str) -> bool:
        try:
            return bool(self.r.exists(f"aegis:cooldown:{key_id}"))
        except Exception:  # noqa: BLE001
            return False
