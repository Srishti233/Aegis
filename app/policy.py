"""Policy engine: policy.yaml -> ResolvedPolicy, with per-API-key overrides and hot reload."""
from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

VALID_ACTIONS = {"block", "redact", "flag"}
MODES = ("monitor", "balanced", "strict")


def deep_merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


@dataclass(frozen=True)
class ResolvedPolicy:
    mode: str
    enforce: bool
    block_threshold: float
    flag_threshold: float
    w_semantic: float
    w_heuristic: float
    sem_low: float
    sem_high: float
    out_sem_low: float
    out_sem_high: float
    category_thresholds: dict[str, float]
    secret_actions: dict[str, str]
    output_actions: dict[str, Any]
    max_escalation_bonus: float
    raw: dict[str, Any] = field(default_factory=dict, compare=False)

    def secret_action(self, secret_type: str) -> str:
        return self.secret_actions.get(secret_type, self.secret_actions.get("default", "flag"))


class PolicyEngine:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {}
        self.reload()

    def reload(self) -> dict[str, Any]:
        data = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        self._validate(data)
        with self._lock:
            self._data = data
        return {"mode_default": data["default_mode"], "modes": sorted(data["modes"])}

    @staticmethod
    def _validate(data: dict[str, Any]) -> None:
        if data.get("default_mode") not in data.get("modes", {}):
            raise ValueError("default_mode must be defined under modes")
        for name, m in data["modes"].items():
            merged = deep_merge(data["defaults"], m or {})
            for t, a in merged["secret_actions"].items():
                if a not in VALID_ACTIONS:
                    raise ValueError(f"mode {name}: invalid action {a!r} for {t}")
            for key in ("block_threshold", "flag_threshold"):
                if not 0 <= float(merged[key]) <= 1:
                    raise ValueError(f"mode {name}: {key} must be within 0..1")

    @property
    def data(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data)

    def resolve(self, override: dict[str, Any] | None = None, mode: str | None = None) -> ResolvedPolicy:
        data = self.data
        override = dict(override or {})
        mode = mode or override.pop("mode", None) or data["default_mode"]
        override.pop("mode", None)
        if mode not in data["modes"]:
            raise ValueError(f"unknown policy mode {mode!r}")
        cfg = deep_merge(deep_merge(data["defaults"], data["modes"][mode] or {}), override)
        for t, a in cfg["secret_actions"].items():
            if a not in VALID_ACTIONS:
                raise ValueError(f"invalid secret action {a!r} for {t}")
        return ResolvedPolicy(
            mode=mode,
            enforce=bool(cfg["enforce"]),
            block_threshold=float(cfg["block_threshold"]),
            flag_threshold=float(cfg["flag_threshold"]),
            w_semantic=float(cfg["weights"]["semantic"]),
            w_heuristic=float(cfg["weights"]["heuristic"]),
            sem_low=float(cfg["semantic"]["low"]),
            sem_high=float(cfg["semantic"]["high"]),
            out_sem_low=float(cfg["output_semantic"]["low"]),
            out_sem_high=float(cfg["output_semantic"]["high"]),
            category_thresholds={k: float(v) for k, v in (cfg.get("category_thresholds") or {}).items()},
            secret_actions=dict(cfg["secret_actions"]),
            output_actions=dict(cfg["output_actions"]),
            max_escalation_bonus=float(cfg["escalation"]["max_bonus"]),
            raw=cfg,
        )
