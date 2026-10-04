import fakeredis
import pytest

from app.config import Settings
from app.ratelimit import RateLimiter, estimate_tokens


@pytest.fixture
def rl():
    return RateLimiter(fakeredis.FakeRedis(decode_responses=True), Settings(strike_threshold=3, cooldown_seconds=100))


def test_rpm_window_blocks_and_reports_retry_after(rl):
    results = [rl.check("k", 3, None, 1) for _ in range(5)]
    assert [r.allowed for r in results] == [True, True, True, False, False]
    assert results[3].kind == "rpm" and 1 <= results[3].retry_after <= 61


def test_keys_are_isolated(rl):
    for _ in range(3):
        rl.check("a", 3, None, 1)
    assert not rl.check("a", 3, None, 1).allowed and rl.check("b", 3, None, 1).allowed


def test_token_budget(rl):
    assert rl.check("k", 100, 1000, 600).allowed
    r = rl.check("k", 100, 1000, 600)
    assert not r.allowed and r.kind == "tokens" and r.retry_after > 0


def test_strikes_escalate_to_cooldown_and_tighten_limits(rl):
    assert rl.risk_bonus("k", 0.3) == 0
    for _ in range(3):
        rl.record_block("k")
    assert rl.in_cooldown("k") and rl.risk_bonus("k", 0.3) == pytest.approx(0.3)
    assert rl.risk_bonus("k", 0.15) == 0.15  # capped by policy
    allowed = [rl.check("k", 8, None, 1).allowed for _ in range(4)]
    assert allowed == [True, True, False, False]  # 8 rpm -> 2 rpm during cooldown


def test_fail_open_and_closed_when_redis_is_down():
    class Down:
        def __getattr__(self, name):
            raise ConnectionError("down")
    open_ = RateLimiter(Down(), Settings(rate_limit_fail_open=True)).check("k", 1, None, 1)
    assert open_.allowed and open_.degraded
    closed = RateLimiter(Down(), Settings(rate_limit_fail_open=False)).check("k", 1, None, 1)
    assert not closed.allowed
    assert RateLimiter(Down(), Settings()).ping() is False


def test_estimate_tokens():
    assert estimate_tokens("") == 1 and estimate_tokens("a" * 400) == 100
