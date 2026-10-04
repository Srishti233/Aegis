"""Output pipeline: leakage (secrets/PII, canary), jailbreak-success signals, exfiltration URLs."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlparse

from app.detectors.normalizer import View, normalize
from app.detectors.rules import RuleSet, noisy_or
from app.detectors.secrets import shannon_entropy
from app.detectors.semantic import SemanticDetector, similarity_to_score
from app.pipeline.common import apply_secret_policy, timed
from app.policy import ResolvedPolicy

_MD_IMG = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)")
_MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)")
_HTML_URL = re.compile(r"""<(?:img|iframe|script|link|a)\b[^>]*?(?:src|href)\s*=\s*["']?(https?://[^"'\s>]+)""", re.I)


@dataclass
class OutputResult:
    decision: str = "allow"
    would_block: bool = False
    risk: float = 0.0
    reason_code: str | None = None
    categories: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    redactions: dict[str, int] = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)
    texts: list[str] = field(default_factory=list)  # sanitized, aligned with the input segments
    explanation: str = ""
    stage_ms: dict[str, float] = field(default_factory=dict)


def _host_allowed(host: str | None, allowed: set[str]) -> bool:
    if not host:
        return False
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in allowed)


def _carries_data(url: str) -> bool:
    p = urlparse(url)
    if p.username or p.password:
        return True
    if any(len(v) >= 8 for _, v in parse_qsl(p.query, keep_blank_values=True)) or len(p.fragment) >= 8:
        return True
    return any(len(seg) >= 24 and shannon_entropy(seg) >= 3.5 for seg in p.path.split("/"))


def find_exfiltration(text: str, allowed_domains: set[str]) -> list[str]:
    """URLs in images/links/HTML that point off the allowlist AND appear to carry data."""
    bad: list[str] = []
    for rx in (_MD_IMG, _MD_LINK, _HTML_URL):
        for m in rx.finditer(text):
            url = m.group(1)
            if not _host_allowed(urlparse(url).hostname, allowed_domains) and _carries_data(url):
                bad.append(url[:120])
    return bad


def canary_leaked(text: str, canary: str | None) -> bool:
    if not canary:
        return False
    squashed = re.sub(r"[\s\-_:\[\]]", "", normalize(text).clean.lower())
    return re.sub(r"[\s\-_:\[\]]", "", canary.lower()) in squashed


def run_output(segments: list[str], policy: ResolvedPolicy, rules: RuleSet, semantic: SemanticDetector,
               canary: str | None, allowed_domains: set[str]) -> OutputResult:
    stages: dict[str, float] = {}
    res = OutputResult()
    reasons: list[str] = []
    weights: list[float] = []
    hit_cats: set[str] = set()
    flags: set[str] = set()
    secret_block = False

    for text in segments:
        with timed(stages, "secrets"):
            findings, redacted, blocked = apply_secret_policy(text, policy)
        secret_block |= blocked
        for f in findings:
            flags.add(f"{f.type}:{f.action}")
            if f.action == "redact":
                res.redactions[f.type] = res.redactions.get(f.type, 0) + 1
        res.texts.append(redacted if policy.enforce else text)

        with timed(stages, "canary"):
            if canary_leaked(text, canary):
                reasons.append("system_prompt_leak")
                weights.append(1.0)
                hit_cats.add("system_prompt_leak")
        with timed(stages, "rules"):
            clean = normalize(text).clean
            hits = rules.scan([View("plain", clean)], "output")
        for h in hits:
            weights.append(h.weight)
            hit_cats.add(h.category)
            res.rule_ids.append(h.rule_id)
        with timed(stages, "semantic"):
            sem = semantic.score(clean, "output")
            sem_score = similarity_to_score(sem.max_similarity, policy.out_sem_low, policy.out_sem_high)
            if sem_score > 0:
                weights.append(policy.w_semantic * sem_score)
                hit_cats.add("jailbreak_success")
        with timed(stages, "exfil"):
            bad = find_exfiltration(text, allowed_domains)
        if bad:
            reasons.append("exfiltration")
            weights.append(0.9)
            hit_cats.add("exfiltration")
            flags.add("exfil_url")

    risk = noisy_or(weights) if weights else 0.0
    act = policy.output_actions
    if "system_prompt_leak" in reasons and act.get("canary_leak") == "block":
        res.reason_code = "system_prompt_leak"
    elif "exfiltration" in reasons and act.get("exfiltration") == "block":
        res.reason_code = "exfiltration"
    elif ({"jailbreak_success", "system_prompt_leak"} & hit_cats and risk >= float(act.get("jailbreak_threshold", 0.6))
          and act.get("jailbreak_success") == "block"):
        res.reason_code = "jailbreak_success"
    elif secret_block:
        res.reason_code = "secret_in_output"

    res.would_block = res.reason_code is not None
    if res.would_block and policy.enforce:
        res.decision = "block"
        res.texts = []
    elif res.redactions and policy.enforce:
        res.decision = "redact"
    res.risk = round(risk, 4)
    res.categories = sorted(hit_cats)
    res.flags = sorted(flags)
    res.rule_ids = sorted(set(res.rule_ids))
    res.explanation = f"risk={risk:.2f}; reason={res.reason_code}; categories={sorted(hit_cats)}"
    res.stage_ms = {k: round(v, 3) for k, v in stages.items()}
    res.stage_ms["total"] = round(sum(stages.values()), 3)
    return res
