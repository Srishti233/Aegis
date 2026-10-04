"""Small shared data types for detectors."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    category: str
    weight: float
    view: str  # which normalized view matched: plain, base64, rot13, ...
    snippet: str
    dampened: bool = False


@dataclass(frozen=True)
class SecretFinding:
    type: str  # e.g. OPENAI_KEY, EMAIL, CREDIT_CARD
    start: int
    end: int
    action: str = "flag"  # block | redact | flag (filled in by policy)

    @property
    def placeholder(self) -> str:
        return f"[REDACTED_{self.type}]"


@dataclass
class Neighbor:
    category: str
    text: str
    similarity: float


@dataclass
class SemanticResult:
    max_similarity: float = 0.0
    hits: list[Neighbor] = field(default_factory=list)
    chunks: int = 0
