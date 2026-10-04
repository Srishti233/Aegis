import pytest

from app.config import ROOT
from app.policy import PolicyEngine, deep_merge


def test_default_mode_and_monitor_does_not_enforce(policy_engine):
    assert policy_engine.resolve().mode == "balanced"
    assert policy_engine.resolve(mode="monitor").enforce is False
    assert policy_engine.resolve(mode="strict").block_threshold < policy_engine.resolve(mode="balanced").block_threshold


def test_per_key_override(policy_engine):
    p = policy_engine.resolve({"mode": "strict", "block_threshold": 0.2, "secret_actions": {"EMAIL": "block"}})
    assert p.mode == "strict" and p.block_threshold == 0.2
    assert p.secret_action("EMAIL") == "block" and p.secret_action("PHONE") == "redact"  # strict mode default kept


def test_unknown_mode_and_invalid_action(policy_engine):
    with pytest.raises(ValueError):
        policy_engine.resolve(mode="paranoid")
    with pytest.raises(ValueError):
        policy_engine.resolve({"secret_actions": {"EMAIL": "explode"}})


def test_deep_merge_does_not_mutate():
    a = {"x": {"y": 1}}
    b = deep_merge(a, {"x": {"z": 2}})
    assert a == {"x": {"y": 1}} and b == {"x": {"y": 1, "z": 2}}


def test_hot_reload_and_validation(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text((ROOT / "policy.yaml").read_text())
    eng = PolicyEngine(f)
    f.write_text(f.read_text().replace("block_threshold: 0.40", "block_threshold: 0.77", 1))
    eng.reload()
    assert eng.resolve(mode="balanced").block_threshold == 0.77
    f.write_text(f.read_text().replace("OPENAI_KEY: redact", "OPENAI_KEY: nuke"))
    with pytest.raises(ValueError):
        eng.reload()
    assert eng.resolve(mode="balanced").block_threshold == 0.77  # old config kept after failed reload
