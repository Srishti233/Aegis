"""Environment-driven configuration. Every setting can be overridden with an env var of the same name."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # infrastructure
    database_url: str = "postgresql+psycopg://aegis:aegis@localhost:5432/aegis"
    redis_url: str = "redis://localhost:6379/0"

    # upstream (any OpenAI-compatible endpoint; the bundled mock needs no key)
    upstream_url: str = "http://localhost:9000"
    upstream_api_key: str = ""
    default_model: str = "mock-gpt"
    upstream_timeout: float = 60.0

    # keys (change all of these outside a demo!)
    admin_api_key: str = "aegis-admin-change-me"
    demo_api_key: str = "aegis-demo-key"
    demo_limited_key: str = "aegis-demo-limited"  # 3 requests/minute, used by the demo script
    eval_api_key: str = "aegis-eval-key"  # unlimited, no escalation, used by eval/run_eval.py

    # detection config
    policy_path: str = str(ROOT / "policy.yaml")
    rules_path: str = str(ROOT / "rules.yaml")
    corpus_path: str = str(ROOT / "app" / "data" / "attack_corpus.jsonl")
    embedder: str = "hash"  # hash | minilm | auto
    canary_enabled: bool = True
    exfil_allowed_domains: str = ""  # comma separated, e.g. "example.com,cdn.mycompany.com"

    # audit
    store_full_text: bool = False  # if true, raw prompt/response text is stored (debug only)

    # rate limiting
    rate_limit_rpm: int = 60
    token_budget_per_hour: int = 200_000
    strike_threshold: int = 3
    cooldown_seconds: int = 300
    rate_limit_fail_open: bool = True

    @property
    def allowed_domains(self) -> set[str]:
        return {d.strip().lower() for d in self.exfil_allowed_domains.split(",") if d.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
