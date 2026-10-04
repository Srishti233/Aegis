"""Prometheus metrics (own registry so tests can build many apps)."""
from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0)


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.requests = Counter("aegis_requests_total", "Requests handled", ["endpoint", "decision"], registry=self.registry)
        self.blocks = Counter("aegis_blocks_total", "Blocked by category", ["direction", "category"], registry=self.registry)
        self.redactions = Counter("aegis_redactions_total", "Redactions by type", ["type"], registry=self.registry)
        self.rate_limit_hits = Counter("aegis_rate_limit_hits_total", "429 responses", ["kind"], registry=self.registry)
        self.stage_latency = Histogram("aegis_stage_latency_seconds", "Latency per pipeline stage",
                                       ["direction", "stage"], buckets=BUCKETS, registry=self.registry)
        self.overhead = Histogram("aegis_added_latency_seconds", "Gateway time excluding upstream",
                                  buckets=BUCKETS, registry=self.registry)
        self.upstream_errors = Counter("aegis_upstream_errors_total", "Upstream failures", registry=self.registry)
        self.auth_failures = Counter("aegis_auth_failures_total", "Rejected API keys", registry=self.registry)

    def observe_stages(self, direction: str, stage_ms: dict[str, float]) -> None:
        for stage, ms in stage_ms.items():
            self.stage_latency.labels(direction, stage).observe(ms / 1000.0)

    def render(self) -> bytes:
        return generate_latest(self.registry)
