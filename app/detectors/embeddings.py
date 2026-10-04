"""Embedders. All produce 384-dim L2-normalised float32 vectors (matches all-MiniLM-L6-v2 and the pgvector column)."""
from __future__ import annotations

import logging
import re
import unicodedata
import zlib
from typing import Protocol

import numpy as np

log = logging.getLogger("aegis.embed")
DIM = 384
_STOP = frozenset("a an the of to in on for and or is are was were be been it this that as at by from please just can could would will".split())
# Synonym groups -> concept token. Gives the offline fallback embedder some paraphrase robustness.
_CONCEPT_GROUPS = {
    "C_IGNORE": "ignore disregard forget override bypass skip discard drop cancel erase overrule neglect abandon ignora ignorar ignore ignoriere olvida vergiss игнорируй забудь 忽略 无视 忘记 無視",
    "C_RULES": "instructions instruction rules rule guidelines guideline directives directive prompt programming policy policies constraints restrictions restriction orders commands command configuration instrucciones reglas consignes anweisungen istruzioni инструкции правила 指令 指示 规则 指示",
    "C_PRIOR": "previous prior earlier above preceding original initial former old anteriores précédentes vorherigen precedenti предыдущие 之前 以前 以上",
    "C_REVEAL": "reveal show print display output repeat recite leak dump share expose echo disclose tell quote copy muestra montre zeige покажи 显示 告诉",
    "C_HIDDEN": "hidden secret confidential internal system developer initial pre-prompt sistema système системный 系统",
    "C_NOLIMIT": "unfiltered uncensored unrestricted unlimited jailbroken jailbreak freed restrictionless limitless dan evil rogue amoral",
    "C_PERSONA": "pretend roleplay imagine act behave simulate persona character adopt",
    "C_MODE": "mode sudo developer debug admin god root maintenance",
    "C_OBEY": "obey comply follow submit execute carry",
    "C_SEND": "send forward email post upload transmit exfiltrate transfer submit append",
    "C_DATA": "credentials password passwords keys secrets tokens history conversation data files",
    "C_AI": "ai assistant llm model chatbot agent gpt",
    "C_ENCODE": "decode base64 hex rot13 encoded decrypt backwards reversed leetspeak obfuscated",
}
_CONCEPT = {w: c for c, ws in _CONCEPT_GROUPS.items() for w in ws.split()}
_WORD = re.compile(r"\w+", re.UNICODE)


class Embedder(Protocol):
    name: str

    def embed(self, texts: list[str]) -> np.ndarray: ...


class HashingEmbedder:
    """Deterministic, dependency-free embedding: signed feature hashing of word unigrams, word bigrams and
    character 4-grams. It captures lexical overlap (not true semantics) but needs no model download, so unit
    tests and offline demos are reproducible."""

    name = "hash-384"

    def embed(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), DIM), dtype=np.float32)
        for i, t in enumerate(texts):
            self._fill(out[i], t)
        norms = np.linalg.norm(out, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return out / norms

    @staticmethod
    def _add(vec: np.ndarray, feat: str, w: float) -> None:
        h = zlib.crc32(feat.encode("utf-8"))
        vec[h % DIM] += w if (h >> 20) & 1 else -w

    def _fill(self, vec: np.ndarray, text: str) -> None:
        t = unicodedata.normalize("NFKC", text).lower()
        words = _WORD.findall(t)
        for w in words:
            if w not in _STOP:
                self._add(vec, "u:" + w, 1.0)
            c = _CONCEPT.get(w)
            if c:
                self._add(vec, "k:" + c, 1.6)
        cw = [_CONCEPT.get(w, w) for w in words]
        for a, b in zip(words, words[1:], strict=False):
            self._add(vec, f"b:{a} {b}", 0.7)
        for a, b in zip(cw, cw[1:], strict=False):
            if a.startswith("C_") or b.startswith("C_"):
                self._add(vec, f"kb:{a} {b}", 1.4)
        joined = " ".join(words)
        for j in range(max(0, len(joined) - 3)):
            self._add(vec, "c:" + joined[j:j + 4], 0.2)


class MiniLMEmbedder:
    """sentence-transformers all-MiniLM-L6-v2 (free, runs on CPU). Optional dependency."""

    name = "all-MiniLM-L6-v2"

    def __init__(self) -> None:
        from sentence_transformers import SentenceTransformer  # noqa: PLC0415

        self._model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

    def embed(self, texts: list[str]) -> np.ndarray:
        return np.asarray(self._model.encode(texts, normalize_embeddings=True, convert_to_numpy=True), dtype=np.float32)


def get_embedder(kind: str) -> Embedder:
    kind = kind.lower()
    if kind == "hash":
        return HashingEmbedder()
    if kind in ("minilm", "auto"):
        try:
            return MiniLMEmbedder()
        except Exception as exc:  # noqa: BLE001 - missing package or no network for first download
            if kind == "minilm":
                raise
            log.warning("MiniLM unavailable (%s); falling back to hashing embedder", exc)
            return HashingEmbedder()
    raise ValueError(f"unknown embedder {kind!r}")
