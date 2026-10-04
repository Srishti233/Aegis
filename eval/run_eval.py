"""Aegis evaluation harness.

  python eval/run_eval.py --tune                 # grid-search thresholds on the TUNING split only -> eval/tuned.json
  python eval/run_eval.py                        # in-process eval, all modes (no services needed)
  python eval/run_eval.py --http http://localhost:8000   # also run through the live gateway + latency comparison
  python eval/run_eval.py --check                # exit 1 if held-out results regress past eval/thresholds.json

Detection = request blocked (in monitor mode: `would_block`). False positive = benign request blocked.
Thresholds come from policy.yaml; they were tuned on the tuning split only. Headline numbers are the held-out TEST split.
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import Settings  # noqa: E402
from app.detectors.embeddings import get_embedder  # noqa: E402
from app.detectors.rules import RuleSet  # noqa: E402
from app.detectors.semantic import MemoryVectorStore, SemanticDetector, similarity_to_score  # noqa: E402
from app.pipeline.input import analyze_text, run_input  # noqa: E402
from app.policy import PolicyEngine  # noqa: E402

EVAL = ROOT / "eval"


def load(name: str) -> list[dict]:
    return [json.loads(line) for line in (EVAL / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def to_messages(item: dict) -> list[dict]:
    if item.get("role") == "tool":
        return [{"role": "user", "content": item.get("prefix", "Summarize this.")}, {"role": "tool", "content": item["text"]}]
    return [{"role": "user", "content": item["text"]}]


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    return v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))]


def confusion(attacks: list[dict], benign: list[dict]) -> dict:
    tp = sum(a["flagged"] for a in attacks)
    fn = len(attacks) - tp
    fp = sum(b["flagged"] for b in benign)
    tn = len(benign) - fp
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / len(attacks) if attacks else 0.0
    return {"attacks": len(attacks), "benign": len(benign), "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "detection_rate": round(rec, 4), "false_positive_rate": round(fp / len(benign), 4) if benign else 0.0,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0}


def summarize(attacks: list[dict], benign: list[dict]) -> dict:
    out = {"overall": confusion(attacks, benign), "per_category": {}, "hard_negatives": {}}
    for cat in sorted({a["category"] for a in attacks}):
        sub = [a for a in attacks if a["category"] == cat]
        out["per_category"][cat] = {"n": len(sub), "detected": sum(a["flagged"] for a in sub),
                                    "detection_rate": round(sum(a["flagged"] for a in sub) / len(sub), 4)}
    hard = [b for b in benign if b["kind"] == "hard_negative"]
    out["hard_negatives"] = {"n": len(hard), "false_positives": sum(b["flagged"] for b in hard),
                             "false_positive_rate": round(sum(b["flagged"] for b in hard) / len(hard), 4) if hard else 0.0}
    out["misses"] = [{"id": a["id"], "category": a["category"], "variant": a["variant"], "risk": a["risk"], "text": a["text"][:110]}
                     for a in attacks if not a["flagged"]]
    out["false_positives"] = [{"id": b["id"], "kind": b["kind"], "risk": b["risk"], "rules": b["rules"], "text": b["text"][:110]}
                              for b in benign if b["flagged"]]
    return out


def build_detectors(embedder_name: str) -> tuple[RuleSet, SemanticDetector, PolicyEngine]:
    s = Settings()
    sem = SemanticDetector(get_embedder(embedder_name), MemoryVectorStore())
    sem.seed(s.corpus_path)
    return RuleSet.load(s.rules_path), sem, PolicyEngine(s.policy_path)


def run_inprocess(items: list[dict], mode: str, rules, sem, engine) -> list[dict]:
    pol = engine.resolve(mode=mode)
    out = []
    for it in items:
        t = time.perf_counter()
        r = run_input(to_messages(it), pol, rules, sem)
        ms = (time.perf_counter() - t) * 1000
        out.append({**it, "flagged": r.would_block, "risk": r.risk, "rules": r.rule_ids, "ms": ms})
    return out


def run_http(items: list[dict], base: str, key: str) -> list[dict]:
    out = []
    with httpx.Client(base_url=base, timeout=30) as c:
        for it in items:
            r = c.post("/v1/chat/completions", json={"model": "mock-gpt", "messages": to_messages(it)},
                       headers={"Authorization": f"Bearer {key}"})
            blocked = r.headers.get("x-aegis-decision") == "block" or r.headers.get("x-aegis-would-block") == "true"
            out.append({**it, "flagged": blocked, "risk": float(r.headers.get("x-aegis-risk-score", 0)), "rules": [],
                        "overhead_ms": float(r.headers.get("x-aegis-overhead-ms", 0))})
    return out


def split(rows: list[dict], which: str) -> list[dict]:
    return [r for r in rows if r["split"] == which]


def tune(rules, sem, engine) -> dict:
    """Grid-search block threshold / semantic mapping / semantic weight on the TUNING split only."""
    base = engine.resolve(mode="balanced")
    feats = []
    for it in load("attacks.jsonl") + load("benign.jsonl"):
        if it["split"] != "tune":
            continue
        a = analyze_text(it["text"], it.get("role", "user"), rules, sem, base, {})
        sim = a.sem_hits[0]["similarity"] if a.sem_hits else 0.0
        feats.append((("category" in it), a.rule_score, sim, a.heuristic_score))
    best = None
    for thr, low, width, ws, wh in itertools.product([x / 100 for x in range(40, 91, 5)], [0.5, 0.6, 0.7, 0.8],
                                                     [0.1, 0.2, 0.3], [0.0, 0.5, 0.9], [0.3, 0.5, 0.7]):
        tp = fp = fn = tn = 0
        for is_attack, rs, sim, hs in feats:
            risk = 1 - (1 - rs) * (1 - ws * similarity_to_score(sim, low, low + width)) * (1 - wh * hs)
            hit = risk >= thr
            tp += is_attack and hit; fn += is_attack and not hit; fp += (not is_attack) and hit; tn += (not is_attack) and not hit
        prec = tp / (tp + fp) if tp + fp else 1.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        fpr = fp / (fp + tn)
        score = (f1 - 0.5 * max(0.0, fpr - 0.03), -fpr, -abs(thr - 0.6))
        if best is None or score > best[0]:
            best = (score, dict(block_threshold=thr, semantic_low=low, semantic_high=round(low + width, 2),
                                w_semantic=ws, w_heuristic=wh, tune_f1=round(f1, 4), tune_fpr=round(fpr, 4), tune_recall=round(rec, 4)))
    return best[1]


def latency_http(base: str, key: str, upstream: str, n: int = 200) -> dict:
    prompts = [b["text"] for b in load("benign.jsonl") if b["kind"] in ("regular", "templated", "hard_negative")]
    prompts = list(itertools.islice(itertools.cycle(prompts), n))
    gw, direct, overhead = [], [], []
    with httpx.Client(timeout=30) as c:
        for p in prompts[:10]:  # warm-up
            c.post(f"{base}/v1/chat/completions", json={"messages": [{"role": "user", "content": p}]}, headers={"Authorization": f"Bearer {key}"})
        for p in prompts:
            body = {"model": "mock-gpt", "messages": [{"role": "user", "content": p}]}
            t = time.perf_counter()
            r = c.post(f"{upstream}/v1/chat/completions", json=body)
            direct.append((time.perf_counter() - t) * 1000)
            t = time.perf_counter()
            r = c.post(f"{base}/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {key}"})
            gw.append((time.perf_counter() - t) * 1000)
            overhead.append(float(r.headers.get("x-aegis-overhead-ms", 0)))
    paired = [g - d for g, d in zip(gw, direct, strict=False)]
    f = lambda v: {"p50": round(pct(v, 50), 2), "p95": round(pct(v, 95), 2), "p99": round(pct(v, 99), 2)}  # noqa: E731
    return {"n": len(prompts), "direct_mock_ms": f(direct), "via_gateway_ms": f(gw),
            "added_latency_paired_ms": f(paired), "gateway_reported_overhead_ms": f(overhead)}


def md_table(summary: dict) -> str:
    o = summary["overall"]
    lines = ["| detection | false positives | precision | recall | F1 | hard-negative FPR |", "|---|---|---|---|---|---|",
             f"| {o['tp']}/{o['attacks']} ({o['detection_rate']:.1%}) | {o['fp']}/{o['benign']} ({o['false_positive_rate']:.1%}) | "
             f"{o['precision']:.3f} | {o['recall']:.3f} | {o['f1']:.3f} | "
             f"{summary['hard_negatives']['false_positives']}/{summary['hard_negatives']['n']} |"]
    return "\n".join(lines)


def render_md(res: dict) -> str:
    L = ["# Aegis evaluation results", "", f"Embedder: `{res['embedder']}`. Generated by `eval/run_eval.py`. Nothing here is hand-edited.", "",
         f"Tuned parameters (from the tuning split only): `{json.dumps(res.get('tuned'))}`", ""]
    for runner in ("inprocess", "http"):
        if runner not in res:
            continue
        L += [f"## {'In-process pipeline' if runner == 'inprocess' else 'Through the HTTP gateway'}", ""]
        for mode, d in res[runner].items():
            L += [f"### mode = {mode}", "", "**Held-out test split**", "", md_table(d["test"]), "",
                  "**Tuning split** (thresholds were fitted here, so this is optimistic)", "", md_table(d["tune"]), ""]
    if "inprocess" in res:
        t = res["inprocess"]["balanced"]["test"]
        L += ["## Per-category detection (balanced, held-out test)", "", "| category | detected | rate |", "|---|---|---|"]
        L += [f"| {c} | {v['detected']}/{v['n']} | {v['detection_rate']:.1%} |" for c, v in t["per_category"].items()]
        L += ["", "## Confusion summary (balanced, held-out test)", "", "| | predicted block | predicted allow |", "|---|---|---|",
              f"| **attack** | {t['overall']['tp']} | {t['overall']['fn']} |", f"| **benign** | {t['overall']['fp']} | {t['overall']['tn']} |", "",
              "## Misses (balanced, held-out test)", ""]
        L += [f"- `{m['id']}` [{m['category']}/{m['variant']}] risk={m['risk']}: {m['text']!r}" for m in t["misses"]] or ["none"]
        L += ["", "## False positives (balanced, held-out test)", ""]
        L += [f"- `{m['id']}` [{m['kind']}] risk={m['risk']} rules={m['rules']}: {m['text']!r}" for m in t["false_positives"]] or ["none"]
    if "pipeline_latency_ms" in res:
        L += ["", "## In-process pipeline latency (input pipeline only, ms per request)", "", f"`{json.dumps(res['pipeline_latency_ms'])}`"]
    if "latency" in res:
        L += ["", "## Gateway latency vs calling the mock upstream directly", "", "```json", json.dumps(res["latency"], indent=2), "```",
              "", f"Measured on: {res.get('machine', 'unknown')}."]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tune", action="store_true")
    ap.add_argument("--http", help="gateway base URL, e.g. http://localhost:8000")
    ap.add_argument("--upstream", default="http://localhost:9000")
    ap.add_argument("--key", default=Settings().eval_api_key)
    ap.add_argument("--embedder", default="hash")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--machine", default="")
    args = ap.parse_args()

    rules, sem, engine = build_detectors(args.embedder)
    if args.tune:
        best = tune(rules, sem, engine)
        (EVAL / "tuned.json").write_text(json.dumps(best, indent=2) + "\n")
        print("Best on tuning split:", json.dumps(best))
        print("Copy these into policy.yaml (defaults.block_threshold, weights.*, semantic.low/high).")
        return 0

    attacks, benign = load("attacks.jsonl"), load("benign.jsonl")
    tuned = json.loads((EVAL / "tuned.json").read_text()) if (EVAL / "tuned.json").exists() else None
    res: dict = {"embedder": args.embedder, "tuned": tuned, "inprocess": {}}
    for mode in ("monitor", "balanced", "strict"):
        ra, rb = run_inprocess(attacks, mode, rules, sem, engine), run_inprocess(benign, mode, rules, sem, engine)
        res["inprocess"][mode] = {w: summarize(split(ra, w), split(rb, w)) for w in ("test", "tune")}
        if mode == "balanced":
            ms = [r["ms"] for r in ra + rb]
            res["pipeline_latency_ms"] = {"p50": round(pct(ms, 50), 2), "p95": round(pct(ms, 95), 2), "p99": round(pct(ms, 99), 2)}
    if args.http:
        res["http"] = {}
        for mode, suffix in (("monitor", "-monitor"), ("balanced", ""), ("strict", "-strict")):
            ra, rb = run_http(attacks, args.http, args.key + suffix), run_http(benign, args.http, args.key + suffix)
            res["http"][mode] = {w: summarize(split(ra, w), split(rb, w)) for w in ("test", "tune")}
        res["latency"] = latency_http(args.http, args.key, args.upstream)
        res["machine"] = args.machine
        # consistency: in-process and HTTP (pgvector) should agree
        a, b = res["inprocess"]["balanced"]["test"]["overall"], res["http"]["balanced"]["test"]["overall"]
        res["inprocess_vs_http_agree"] = (a["tp"], a["fp"]) == (b["tp"], b["fp"])
    (EVAL / "results.json").write_text(json.dumps(res, indent=2, ensure_ascii=False) + "\n")
    (EVAL / "results.md").write_text(render_md(res), encoding="utf-8")
    o = res["inprocess"]["balanced"]["test"]["overall"]
    print(f"balanced / held-out test: detection {o['detection_rate']:.1%}  FPR {o['false_positive_rate']:.1%}  "
          f"precision {o['precision']:.3f}  (n_attacks={o['attacks']}, n_benign={o['benign']})")
    if args.check:
        th = json.loads((EVAL / "thresholds.json").read_text())
        ok = o["detection_rate"] >= th["min_detection_rate"] and o["false_positive_rate"] <= th["max_false_positive_rate"]
        print("CHECK", "PASSED" if ok else "FAILED", th)
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
