import pytest
from sqlalchemy import text

from app.audit import GENESIS, AuditLog
from app.db import make_engine, run_migrations


@pytest.fixture
def log():
    e = make_engine("sqlite://")
    run_migrations(e)
    return AuditLog(e)


def add(log, i, **kw):
    base = dict(api_key_id="k", request_id=f"r{i}", direction="input", decision="allow", risk_score=0.1234567,
                would_block=False, mode="balanced", matched_rules=["IO-001"], categories=["x"], redactions={"EMAIL": 1},
                latency_ms={"total": 1.23456}, content_hash="h", snippet="hello")
    base.update(kw)
    return log.append(**base)


def test_empty_chain_is_intact(log):
    assert log.verify()["intact"] and log.head()["entry_hash"] == GENESIS


def test_chain_links_and_verifies(log):
    a, b = add(log, 1), add(log, 2)
    assert a["prev_hash"] == GENESIS and b["prev_hash"] == a["entry_hash"]
    v = log.verify()
    assert v["intact"] and v["entries_checked"] == 2 and v["head_hash"] == b["entry_hash"]


def test_modified_row_is_detected_at_the_right_seq(log):
    for i in range(5):
        add(log, i)
    with log.engine.begin() as c:
        c.execute(text("UPDATE audit_events SET decision='allow', risk_score=0.0 WHERE seq=3"))
        c.execute(text("UPDATE audit_events SET decision='block' WHERE seq=3"))
    v = log.verify()
    assert not v["intact"] and v["first_break_seq"] == 3 and "modified" in v["reason"]


def test_deleted_row_is_detected(log):
    for i in range(5):
        add(log, i)
    with log.engine.begin() as c:
        c.execute(text("DELETE FROM audit_events WHERE seq=2"))
    v = log.verify()
    assert not v["intact"] and v["first_break_seq"] == 2 and "gap" in v["reason"]


def test_reordered_hash_is_detected(log):
    for i in range(4):
        add(log, i)
    with log.engine.begin() as c:
        c.execute(text("UPDATE audit_events SET prev_hash='deadbeef' WHERE seq=3"))
    v = log.verify()
    assert not v["intact"] and v["first_break_seq"] == 3


def test_raw_text_not_stored_by_default_but_snippet_is(log):
    add(log, 1, full_text="SECRET PROMPT")
    row = log.recent(1)[0]
    assert row["snippet"] == "hello" and "SECRET" not in str(row)
    with log.engine.connect() as c:
        assert c.execute(text("SELECT full_text FROM audit_events")).scalar() is None


def test_full_text_flag_and_chain_still_valid():
    e = make_engine("sqlite://")
    run_migrations(e)
    lg = AuditLog(e, store_full_text=True)
    add(lg, 1, full_text="debug text")
    with e.connect() as c:
        assert c.execute(text("SELECT full_text FROM audit_events")).scalar() == "debug text"
    assert lg.verify()["intact"]
