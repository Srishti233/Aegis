"""Cheap statistical / structural heuristics that complement the rules."""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from app.detectors.normalizer import _script

_CONTROL = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass|obey|pretend|reveal|jailbreak(?:ed)?|unfiltered|uncensored|"
    r"unrestricted|comply)\b", re.I)
_DIRECTIVE = re.compile(r"\byou\s+(?:must|will|shall|are\s+to|are\s+now|have\s+to)\b", re.I)
_ADDRESSES_AI = re.compile(r"^\W*(?:ai|assistant|llm|model|chatbot|agent|gpt|you)\b", re.I)
_DOC_MARKERS = re.compile(
    r"<\s*(?:document|context|email|webpage|search_result)\b|\b(?:begin|start)\s+(?:of\s+)?(?:the\s+)?"
    r"(?:document|retrieved|context|email|web\s*page)\b|\bretrieved\s+(?:document|context|passage)s?\b|"
    r"(?m:^\s*(?:from|subject|to):\s)", re.I)


@dataclass
class HeuristicResult:
    score: float = 0.0
    signals: dict[str, float] = field(default_factory=dict)


def _letters_by_script(text: str) -> Counter[str]:
    c: Counter[str] = Counter()
    for ch in text[:5000]:
        s = _script(ch)
        if s:
            c[s] += 1
    return c


def run_heuristics(text: str, role: str = "user", rule_override_hits: int = 0) -> HeuristicResult:
    sig: dict[str, float] = {}

    control = len(_CONTROL.findall(text)) + len(_DIRECTIVE.findall(text))
    if control >= 2:
        sig["control_density"] = min(1.0, (control - 1) / 4)

    retrieved = role in ("tool", "function") or bool(_DOC_MARKERS.search(text))
    if retrieved:
        lines = [ln for ln in re.split(r"[\n.!?]+", text) if ln.strip()]
        inst = sum(1 for ln in lines if _ADDRESSES_AI.search(ln) and (_CONTROL.search(ln) or _DIRECTIVE.search(ln)))
        inst += sum(1 for ln in lines if _CONTROL.search(ln) and not _ADDRESSES_AI.search(ln))
        if inst >= 1:
            sig["instructions_in_retrieved_content"] = 0.5 if inst < 3 else 0.9

    if len(text) > 2000:
        words = re.findall(r"\w+", text.lower())
        if len(words) > 300:
            if len(set(words)) / len(words) < 0.2:
                sig["repetition"] = 0.7
            else:
                grams = Counter(zip(*(words[i:] for i in range(5)), strict=False))
                if grams and grams.most_common(1)[0][1] / len(words) > 0.25:
                    sig["repetition"] = 0.7
            if len(text) > 12000 and "repetition" in sig:
                sig["repetition"] = 0.9

    if rule_override_hits:
        scripts = _letters_by_script(text)
        total = sum(scripts.values())
        if total >= 30 and sum(1 for n in scripts.values() if n / total >= 0.08) >= 2:
            sig["script_mixing_with_override"] = 0.7

    return HeuristicResult(max(sig.values(), default=0.0), sig)
