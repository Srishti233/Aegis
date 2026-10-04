"""Secret and PII scanner with validators (Luhn, entropy) and typed redaction placeholders."""
from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from app.detectors.types import SecretFinding


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _card_ok(m: re.Match[str]) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    return 13 <= len(digits) <= 19 and digits[0] in "3456" and luhn_ok(digits) and len(set(digits)) > 1


def _phone_ok(m: re.Match[str]) -> bool:
    s = m.group(0)
    digits = re.sub(r"\D", "", s)
    if not 10 <= len(digits) <= 13:
        return False
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s.strip()):
        return False  # IPv4 address
    if re.fullmatch(r"[\d.]+", s.strip()) and any(len(g) < 3 for g in s.strip().split(".")):
        return False  # version numbers / dotted decimals
    # require a separator, a '+' prefix or parentheses so plain 10-digit numbers (ids, counters) don't match
    return bool(re.search(r"[\s().-]", s.strip()) or s.startswith("+"))


def _ssn_ok(m: re.Match[str]) -> bool:
    area = m.group(0)[:3]
    return area not in ("000", "666") and not area.startswith("9") and m.group(0)[4:6] != "00" and m.group(0)[7:] != "0000"


def _entropy_ok(m: re.Match[str]) -> bool:
    tok = m.group(0)
    has = (any(c.islower() for c in tok), any(c.isupper() for c in tok), any(c.isdigit() for c in tok))
    return sum(has) >= 3 and shannon_entropy(tok) >= 4.3 and not tok.startswith(("http", "www"))


@dataclass(frozen=True)
class _Pattern:
    type: str
    regex: re.Pattern[str]
    validator: Callable[[re.Match[str]], bool] | None = None
    group: int = 0  # which regex group is the secret (so 'api_key=' prefixes are kept)


def _p(t: str, rx: str, v: Callable[[re.Match[str]], bool] | None = None, group: int = 0, flags: int = 0) -> _Pattern:
    return _Pattern(t, re.compile(rx, flags), v, group)


# Order matters: earlier patterns win overlaps.
PATTERNS: list[_Pattern] = [
    _p("PRIVATE_KEY", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)"),
    _p("JWT", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    _p("OPENAI_KEY", r"\bsk-(?:proj-|svcacct-|ant-(?:api\d+-)?)?[A-Za-z0-9_-]{20,}\b"),
    _p("AWS_KEY", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"),
    _p("AWS_KEY", r"(?i)aws_?secret_?access_?key[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})", group=1),
    _p("GITHUB_TOKEN", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    _p("GOOGLE_KEY", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _p("STRIPE_KEY", r"\b(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}\b"),
    _p("SLACK_TOKEN", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    _p("GENERIC_SECRET", r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd|pwd)[\"']?\s*[=:]\s*[\"']?([^\s\"'<>]{12,})", group=1),
    _p("CREDIT_CARD", r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])", _card_ok),
    _p("GOV_ID", r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])", _ssn_ok),
    _p("GOV_ID", r"(?<!\d)(?<!\d\s)[2-9]\d{3}\s\d{4}\s\d{4}(?!\d)(?!\s\d)"),  # Aadhaar-style (4-4-4)
    _p("GOV_ID", r"\b[A-Z]{5}\d{4}[A-Z]\b"),  # Indian PAN
    _p("GOV_ID", r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"),  # UK National Insurance
    _p("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
    _p("PHONE", r"(?<![\w.])(?<!\d[\s-])(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?!\w)(?![\s-]\d)", _phone_ok),
    _p("HIGH_ENTROPY", r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{32,}(?![A-Za-z0-9+/_=-])", _entropy_ok),
]


def scan_secrets(text: str) -> list[SecretFinding]:
    found: list[SecretFinding] = []
    taken: list[tuple[int, int]] = []
    for pat in PATTERNS:
        for m in pat.regex.finditer(text):
            if pat.validator and not pat.validator(m):
                continue
            s, e = m.span(pat.group)
            if s == e or any(s < b and a < e for a, b in taken):
                continue
            taken.append((s, e))
            found.append(SecretFinding(pat.type, s, e))
    return sorted(found, key=lambda f: f.start)


def redact(text: str, findings: list[SecretFinding], only_actions: tuple[str, ...] = ("redact",)) -> str:
    out = text
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        if f.action in only_actions:
            out = out[:f.start] + f.placeholder + out[f.end:]
    return out
