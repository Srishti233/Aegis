"""YAML-driven regex rule detector."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.detectors.normalizer import View
from app.detectors.types import RuleHit

_DISCUSSION = re.compile(
    r"prompt[- ]injection|jailbreak|attack|phrase|example|what\s+(?:does|is|do)|explain|detect|defen[cs]e|"
    r"mitigat|security|red[- ]team|sanitiz|classif|research|paper|why\s+do",
    re.I,
)
_QUOTES = "\"'“”‘’«»`"
ENCODED_VIEW_BONUS_ID = "ENC-001"
ENCODED_VIEW_BONUS_WEIGHT = 0.5


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: float
    description: str
    direction: str
    pattern: re.Pattern[str]


class RuleSet:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        ids = [r.id for r in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule ids in rules file")

    @classmethod
    def load(cls, path: str | Path) -> "RuleSet":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        rules: list[Rule] = []
        for raw in data["rules"]:
            if not 0 < float(raw["weight"]) <= 1:
                raise ValueError(f"rule {raw['id']}: weight must be in (0,1]")
            if raw["direction"] not in ("input", "output"):
                raise ValueError(f"rule {raw['id']}: bad direction")
            rules.append(
                Rule(
                    id=raw["id"],
                    category=raw["category"],
                    weight=float(raw["weight"]),
                    description=raw["description"],
                    direction=raw["direction"],
                    pattern=re.compile(raw["pattern"], re.I | re.S),
                )
            )
        return cls(rules)

    def scan(self, views: list[View], direction: str = "input") -> list[RuleHit]:
        """Scan every view. One hit per rule id (the strongest). Hits found only in decoded/transformed
        views also produce an ENC-001 hit, since hiding an attack in an encoding is itself suspicious."""
        discussion = any(_DISCUSSION.search(v.text) for v in views[:1])
        best: dict[str, RuleHit] = {}
        for view in views:
            for rule in self.rules:
                if rule.direction != direction:
                    continue
                m = rule.pattern.search(view.text)
                if not m:
                    continue
                weight, damp = rule.weight, False
                if discussion and view.label == "plain" and _is_quoted(view.text, m.start(), m.end()):
                    weight, damp = round(weight * 0.2, 4), True
                hit = RuleHit(rule.id, rule.category, weight, view.label, m.group(0)[:80], damp)
                cur = best.get(rule.id)
                if cur is None or hit.weight > cur.weight or (hit.view == "plain" and cur.view != "plain"):
                    best[rule.id] = hit
        hits = list(best.values())
        transformed = [h for h in hits if h.view != "plain" and h.weight >= 0.5 and direction == "input"]
        if transformed and not any(h.view == "plain" for h in hits if h.category != "encoded_payload"):
            hits.append(RuleHit(ENCODED_VIEW_BONUS_ID, "encoded_payload", ENCODED_VIEW_BONUS_WEIGHT, transformed[0].view,
                                f"attack found in {transformed[0].view} view"))
        return sorted(hits, key=lambda h: (-h.weight, h.rule_id))


def _is_quoted(text: str, start: int, end: int) -> bool:
    """True if the match sits inside a quoted span: an opening quote just before it and a closing quote after."""
    before = text[max(0, start - 3):start]
    after = text[end:end + 60]
    return any(c in _QUOTES for c in before) and any(c in _QUOTES for c in after)


def noisy_or(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - w
    return 1.0 - p
