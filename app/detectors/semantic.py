"""Semantic attack detector: nearest-neighbour search against an attack corpus (pgvector or in-memory)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Protocol

import numpy as np
from sqlalchemy import text as sql
from sqlalchemy.engine import Engine

from app.detectors.embeddings import Embedder
from app.detectors.types import Neighbor, SemanticResult


class VectorStore(Protocol):
    def search(self, vec: np.ndarray, kind: str, k: int) -> list[Neighbor]: ...
    def count(self) -> int: ...
    def replace_all(self, entries: list[dict], vectors: np.ndarray) -> None: ...


class MemoryVectorStore:
    """Exact cosine search with numpy. Used in unit tests and in-process evaluation."""

    def __init__(self) -> None:
        self.entries: list[dict] = []
        self.matrix = np.zeros((0, 384), dtype=np.float32)

    def replace_all(self, entries: list[dict], vectors: np.ndarray) -> None:
        self.entries, self.matrix = list(entries), vectors.astype(np.float32)

    def count(self) -> int:
        return len(self.entries)

    def search(self, vec: np.ndarray, kind: str, k: int) -> list[Neighbor]:
        if not self.entries:
            return []
        sims = self.matrix @ vec
        order = np.argsort(-sims)
        out: list[Neighbor] = []
        for i in order:
            e = self.entries[int(i)]
            if e["kind"] == kind:
                out.append(Neighbor(e["category"], e["text"], float(sims[i])))
                if len(out) >= k:
                    break
        return out


def _vec_literal(v: np.ndarray) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in v.tolist()) + "]"


class PgVectorStore:
    """pgvector cosine-distance search (`<=>`)."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def count(self) -> int:
        with self.engine.connect() as c:
            return int(c.execute(sql("SELECT count(*) FROM attack_corpus")).scalar_one())

    def replace_all(self, entries: list[dict], vectors: np.ndarray) -> None:
        with self.engine.begin() as c:
            c.execute(sql("DELETE FROM attack_corpus"))
            for e, v in zip(entries, vectors, strict=False):
                c.execute(
                    sql("INSERT INTO attack_corpus (kind, category, text, embedding) VALUES (:k, :c, :t, CAST(:v AS vector))"),
                    {"k": e["kind"], "c": e["category"], "t": e["text"], "v": _vec_literal(v)},
                )

    def search(self, vec: np.ndarray, kind: str, k: int) -> list[Neighbor]:
        q = sql(
            "SELECT category, text, 1 - (embedding <=> CAST(:v AS vector)) AS sim FROM attack_corpus "
            "WHERE kind = :k ORDER BY embedding <=> CAST(:v AS vector) LIMIT :n"
        )
        with self.engine.connect() as c:
            rows = c.execute(q, {"v": _vec_literal(vec), "k": kind, "n": k}).all()
        return [Neighbor(r[0], r[1], float(r[2])) for r in rows]


def load_corpus(path: str | Path) -> list[dict]:
    entries = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            e = json.loads(line)
            e.setdefault("kind", "input")
            entries.append(e)
    return entries


class SemanticDetector:
    def __init__(self, embedder: Embedder, store: VectorStore, window_words: int = 40, stride: int = 20,
                 max_chunks: int = 16, top_k: int = 3):
        self.embedder, self.store = embedder, store
        self.window, self.stride, self.max_chunks, self.top_k = window_words, stride, max_chunks, top_k

    def seed(self, corpus_path: str | Path) -> int:
        entries = load_corpus(corpus_path)
        vecs = self.embedder.embed([e["text"] for e in entries])
        self.store.replace_all(entries, vecs)
        return len(entries)

    def chunks(self, text: str) -> list[str]:
        """Short texts are embedded whole. Long texts get individual sentences (an injected instruction is
        usually one sentence, which a 40-word window would dilute) plus sliding windows."""
        words = text.split()
        if len(words) <= self.window:
            return [text]
        sentences = [x.strip() for x in re.split(r"(?<=[.!?])\s+|\n+", text) if len(x.split()) >= 4][:16]
        windows = [" ".join(words[i:i + self.window]) for i in range(0, len(words) - self.window + self.stride, self.stride)]
        if len(windows) > 8:
            step = len(windows) / 8
            windows = [windows[int(i * step)] for i in range(8)]
        return (sentences + windows)[: self.max_chunks + 12]

    def score(self, text: str, kind: str = "input") -> SemanticResult:
        if not text.strip():
            return SemanticResult()
        chunks = self.chunks(text)
        vecs = self.embedder.embed(chunks)
        best: list[Neighbor] = []
        for v in vecs:
            best.extend(self.store.search(v, kind, self.top_k))
        best.sort(key=lambda n: -n.similarity)
        # de-duplicate by corpus text
        seen, hits = set(), []
        for n in best:
            if n.text not in seen:
                seen.add(n.text)
                hits.append(n)
        return SemanticResult(hits[0].similarity if hits else 0.0, hits[: self.top_k], len(chunks))


def similarity_to_score(sim: float, low: float, high: float) -> float:
    if high <= low:
        return 1.0 if sim >= high else 0.0
    return float(min(1.0, max(0.0, (sim - low) / (high - low))))


_WS = re.compile(r"\s+")
