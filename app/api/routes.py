"""HTTP routes: OpenAI-compatible proxy, admin API, health, metrics, dashboard."""
from __future__ import annotations

import hmac
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.api.errors import oai_error
from app.db import Principal
from app.detectors.secrets import redact, scan_secrets
from app.pipeline.common import sha256_text, text_parts, worst
from app.pipeline.input import inject_canary, new_canary, run_input
from app.pipeline.output import run_output
from app.services import Services

router = APIRouter()
DASHBOARD = Path(__file__).resolve().parent.parent / "static" / "dashboard.html"


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    model: str | None = None
    messages: list[dict[str, Any]] = Field(min_length=1)
    stream: bool = False


def svc(request: Request) -> Services:
    return request.app.state.services


def _bearer(request: Request) -> str | None:
    h = request.headers.get("authorization", "")
    return h[7:].strip() if h.lower().startswith("bearer ") else None


def is_admin(request: Request, s: Services) -> bool:
    supplied = request.headers.get("x-admin-key") or _bearer(request) or ""
    return hmac.compare_digest(supplied.encode(), s.settings.admin_api_key.encode())


def _hdrs(rid: str, decision: str, risk: float, overhead_ms: float | None = None,
          would_block: bool = False) -> dict[str, str]:
    h = {"X-Aegis-Request-Id": rid, "X-Aegis-Decision": decision, "X-Aegis-Risk-Score": f"{risk:.4f}",
         "X-Aegis-Would-Block": "true" if would_block else "false"}
    if overhead_ms is not None:
        h["X-Aegis-Overhead-Ms"] = f"{overhead_ms:.2f}"
    return h


def _safe_policy(s: Services, p: Principal):
    try:
        return s.policy.resolve(p.policy_override)
    except ValueError:
        return s.policy.resolve(None)


def _sse(resp: dict[str, Any]) -> Any:
    """Replay a fully scanned (buffered) completion as OpenAI-style SSE chunks."""
    cid = resp.get("id", "chatcmpl-" + uuid.uuid4().hex[:12])
    base = {"id": cid, "object": "chat.completion.chunk", "created": resp.get("created", int(time.time())),
            "model": resp.get("model", "unknown")}

    def chunk(idx: int, delta: dict[str, Any], finish: str | None = None) -> str:
        return "data: " + json.dumps({**base, "choices": [{"index": idx, "delta": delta, "finish_reason": finish}]}) + "\n\n"

    for ch in resp.get("choices", []):
        i, msg = ch.get("index", 0), ch.get("message", {})
        yield chunk(i, {"role": "assistant", "content": ""})
        content = msg.get("content")
        if isinstance(content, str):
            pieces = re.findall(r"\S+\s*", content) or ([content] if content else [])
            for j in range(0, len(pieces), 3):
                yield chunk(i, {"content": "".join(pieces[j:j + 3])})
        for ti, tc in enumerate(msg.get("tool_calls") or []):
            yield chunk(i, {"tool_calls": [{"index": ti, **tc}]})
        yield chunk(i, {}, ch.get("finish_reason") or "stop")
    yield "data: [DONE]\n\n"


@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    s = svc(request)
    t0 = time.perf_counter()
    rid = "aeg_" + uuid.uuid4().hex[:16]

    principal = await run_in_threadpool(s.keys.authenticate, _bearer(request) or "")
    if principal is None:
        s.metrics.auth_failures.inc()
        return oai_error(401, "Invalid or missing API key.", code="invalid_api_key", type_="authentication_error", rid=rid)

    try:
        body = await request.json()
        req = ChatRequest.model_validate(body)
        if not all(isinstance(m.get("role"), str) for m in req.messages):
            raise ValueError("every message needs a string 'role'")
    except (ValueError, ValidationError) as exc:
        return oai_error(400, f"Invalid request: {str(exc)[:200]}", code="invalid_request", type_="invalid_request_error", rid=rid)

    policy = _safe_policy(s, principal)
    kid = principal.key_id

    est = sum(len(t) for m in req.messages for _, t in text_parts(m.get("content"))) // 4
    est += min(int(body.get("max_tokens") or 0), 4096) if isinstance(body.get("max_tokens"), int) else 0
    lim = await run_in_threadpool(s.limiter.check, kid, principal.rpm_limit, principal.token_budget, max(1, est))
    if not lim.allowed:
        s.metrics.rate_limit_hits.labels(lim.kind or "unknown").inc()
        s.metrics.requests.labels("chat", "rate_limited").inc()
        return oai_error(429, f"Rate limit exceeded ({lim.kind}). Retry in {lim.retry_after}s.", code="rate_limit_exceeded",
                         type_="rate_limit_error", rid=rid,
                         headers={"Retry-After": str(lim.retry_after), "X-Aegis-Decision": "block"})

    bonus = await run_in_threadpool(s.limiter.risk_bonus, kid, policy.max_escalation_bonus) if principal.escalation else 0.0

    # ---- input pipeline
    ires = await run_in_threadpool(run_input, req.messages, policy, s.rules, s.semantic, bonus)
    s.metrics.observe_stages("input", ires.stage_ms)
    full_in = json.dumps(req.messages) if s.settings.store_full_text else None
    await run_in_threadpool(
        s.audit.append, api_key_id=kid, request_id=rid, direction="input", decision=ires.decision, risk_score=ires.risk,
        would_block=ires.would_block, mode=policy.mode, matched_rules=ires.rule_ids, categories=ires.categories,
        redactions=ires.redactions, latency_ms=ires.stage_ms, content_hash=ires.content_hash, snippet=ires.snippet,
        full_text=full_in)
    for t, n in ires.redactions.items():
        s.metrics.redactions.labels(t).inc(n)

    if ires.decision == "block":
        await run_in_threadpool(s.limiter.record_block, kid)
        cat = (ires.categories or [ires.reason_code or "unknown"])[0]
        s.metrics.blocks.labels("input", cat).inc()
        s.metrics.requests.labels("chat", "block").inc()
        overhead = (time.perf_counter() - t0) * 1000
        s.metrics.overhead.observe(overhead / 1000)
        msg = ("Request blocked by Aegis: possible prompt injection." if ires.reason_code == "prompt_injection"
               else "Request blocked by Aegis: it contains a secret that policy forbids sending upstream.")
        return oai_error(400, msg, code=ires.reason_code or "blocked", rid=rid,
                         headers=_hdrs(rid, "block", ires.risk, overhead, True),
                         aegis={"request_id": rid, "direction": "input", "reason": ires.reason_code,
                                "categories": ires.categories, "rule_ids": ires.rule_ids, "risk_score": ires.risk,
                                "explanation": ires.explanation})

    # ---- upstream (always non-streaming so the response can be scanned before anything reaches the client)
    canary = new_canary() if s.settings.canary_enabled else None
    fwd_msgs = inject_canary(ires.messages, canary) if canary else ires.messages
    payload = {**body, "messages": fwd_msgs, "stream": False, "model": req.model or s.settings.default_model}
    payload.pop("stream_options", None)
    up_headers = {"Authorization": f"Bearer {s.settings.upstream_api_key}"} if s.settings.upstream_api_key else {}
    t_up = time.perf_counter()
    try:
        up = await s.http.post("/v1/chat/completions", json=payload, headers=up_headers)
    except httpx.HTTPError as exc:
        s.metrics.upstream_errors.inc()
        return oai_error(502, f"Upstream LLM unreachable: {type(exc).__name__}", code="upstream_unavailable",
                         type_="upstream_error", rid=rid)
    upstream_ms = (time.perf_counter() - t_up) * 1000
    if up.status_code >= 400:
        s.metrics.upstream_errors.inc()
        if up.status_code < 500:
            return JSONResponse(up.json() if up.headers.get("content-type", "").startswith("application/json")
                                else {"error": {"message": up.text[:300]}}, status_code=up.status_code,
                                headers=_hdrs(rid, ires.decision, ires.risk))
        return oai_error(502, f"Upstream LLM error (HTTP {up.status_code}).", code="upstream_error", type_="upstream_error", rid=rid)
    try:
        resp = up.json()
        choices = resp["choices"]
    except (ValueError, KeyError, TypeError):
        s.metrics.upstream_errors.inc()
        return oai_error(502, "Upstream returned a malformed completion.", code="upstream_malformed", type_="upstream_error", rid=rid)

    # ---- output pipeline
    refs: list[tuple[str, int, int | None]] = []
    segments: list[str] = []
    for ci, ch in enumerate(choices):
        m = ch.get("message", {}) or {}
        if isinstance(m.get("content"), str):
            refs.append(("content", ci, None)); segments.append(m["content"])
        elif isinstance(m.get("content"), list):
            for pi, p in enumerate(m["content"]):
                if isinstance(p, dict) and isinstance(p.get("text"), str):
                    refs.append(("part", ci, pi)); segments.append(p["text"])
        for ti, tc in enumerate(m.get("tool_calls") or []):
            a = (tc.get("function") or {}).get("arguments")
            if isinstance(a, str):
                refs.append(("args", ci, ti)); segments.append(a)
    ores = await run_in_threadpool(run_output, segments, policy, s.rules, s.semantic, canary, s.settings.allowed_domains)
    s.metrics.observe_stages("output", ores.stage_ms)
    joined = "\n".join(segments)
    out_snip = redact(joined[:300], scan_secrets(joined[:300]), ("block", "redact", "flag"))[:120]
    if ores.would_block:  # never persist content that was blocked (it may be a leaked system prompt)
        out_snip = "[output withheld: " + (ores.reason_code or "blocked") + "]"
    if canary:
        out_snip = out_snip.replace(canary, "[CANARY]")
    await run_in_threadpool(
        s.audit.append, api_key_id=kid, request_id=rid, direction="output", decision=ores.decision,
        risk_score=ores.risk, would_block=ores.would_block, mode=policy.mode, matched_rules=ores.rule_ids,
        categories=ores.categories, redactions=ores.redactions, latency_ms=ores.stage_ms,
        content_hash=sha256_text(joined), snippet=out_snip, full_text=joined if s.settings.store_full_text and not ores.would_block else None)
    for t, n in ores.redactions.items():
        s.metrics.redactions.labels(t).inc(n)

    decision = worst(ires.decision, ores.decision)
    risk = max(ires.risk, ores.risk)
    overhead = (time.perf_counter() - t0) * 1000 - upstream_ms
    s.metrics.overhead.observe(max(overhead, 0) / 1000)

    if ores.decision == "block":
        await run_in_threadpool(s.limiter.record_block, kid)
        cat = ores.reason_code or "unknown"
        s.metrics.blocks.labels("output", cat).inc()
        s.metrics.requests.labels("chat", "block").inc()
        text = {"system_prompt_leak": "the model tried to reveal its hidden instructions",
                "jailbreak_success": "the model output indicates a successful jailbreak",
                "exfiltration": "the model output embeds data in a URL pointing to a non-allowlisted domain",
                "secret_in_output": "the model output contained a secret that policy forbids returning"}.get(cat, "policy violation")
        return oai_error(400, f"Response blocked by Aegis: {text}.", code=cat, rid=rid,
                         headers=_hdrs(rid, "block", risk, overhead, True),
                         aegis={"request_id": rid, "direction": "output", "reason": cat, "categories": ores.categories,
                                "rule_ids": ores.rule_ids, "risk_score": ores.risk, "explanation": ores.explanation})

    if policy.enforce and ores.redactions:
        for (kind, ci, idx), new_text in zip(refs, ores.texts, strict=False):
            m = choices[ci]["message"]
            if kind == "content":
                m["content"] = new_text
            elif kind == "part":
                m["content"][idx]["text"] = new_text
            else:
                m["tool_calls"][idx]["function"]["arguments"] = new_text
    s.metrics.requests.labels("chat", decision).inc()
    headers = _hdrs(rid, decision, risk, overhead, ires.would_block or ores.would_block)
    if request.headers.get("x-aegis-debug") == "1":
        headers["X-Aegis-Explanation"] = (ires.explanation or "-")[:300].replace("\n", " ")
    if req.stream:
        return StreamingResponse(_sse(resp), media_type="text/event-stream", headers=headers)
    return JSONResponse(resp, headers=headers)


@router.get("/v1/models")
async def list_models(request: Request) -> Response:
    s = svc(request)
    rid = "aeg_" + uuid.uuid4().hex[:16]
    principal = await run_in_threadpool(s.keys.authenticate, _bearer(request) or "")
    if principal is None:
        s.metrics.auth_failures.inc()
        return oai_error(401, "Invalid or missing API key.", code="invalid_api_key", type_="authentication_error", rid=rid)
    up_headers = {"Authorization": f"Bearer {s.settings.upstream_api_key}"} if s.settings.upstream_api_key else {}
    try:
        up = await s.http.get("/v1/models", headers=up_headers)
        return JSONResponse(up.json(), status_code=up.status_code, headers={"X-Aegis-Request-Id": rid})
    except (httpx.HTTPError, ValueError) as exc:
        return oai_error(502, f"Upstream LLM unreachable: {type(exc).__name__}", code="upstream_unavailable",
                         type_="upstream_error", rid=rid)


# ---------------------------------------------------------------- ops
@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def ready(request: Request) -> Response:
    s = svc(request)

    def check() -> dict[str, bool]:
        from sqlalchemy import text  # noqa: PLC0415
        try:
            with s.engine.connect() as c:
                c.execute(text("SELECT 1"))
            db = True
        except Exception:  # noqa: BLE001
            db = False
        return {"database": db, "redis": s.limiter.ping(), "corpus": s.semantic.store.count() > 0}

    checks = await run_in_threadpool(check)
    ok = all(checks.values())
    return JSONResponse({"status": "ready" if ok else "not_ready", **checks}, status_code=200 if ok else 503)


@router.get("/metrics")
async def metrics(request: Request) -> Response:
    return Response(svc(request).metrics.render(), media_type="text/plain; version=0.0.4")


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> str:
    return DASHBOARD.read_text(encoding="utf-8")


def _admin_guard(request: Request) -> Response | None:
    if not is_admin(request, svc(request)):
        return oai_error(401, "Admin key required.", code="admin_required", type_="authentication_error")
    return None


@router.get("/admin/audit/verify")
async def audit_verify(request: Request) -> Response:
    if (g := _admin_guard(request)) is not None:
        return g
    return JSONResponse(await run_in_threadpool(svc(request).audit.verify))


@router.get("/admin/audit/head")
async def audit_head(request: Request) -> Response:
    if (g := _admin_guard(request)) is not None:
        return g
    return JSONResponse(await run_in_threadpool(svc(request).audit.head))


@router.get("/admin/audit/recent")
async def audit_recent(request: Request, limit: int = 50) -> Response:
    if (g := _admin_guard(request)) is not None:
        return g
    return JSONResponse(await run_in_threadpool(svc(request).audit.recent, max(1, min(limit, 500))))


@router.get("/admin/policy")
async def get_policy(request: Request) -> Response:
    if (g := _admin_guard(request)) is not None:
        return g
    return JSONResponse(svc(request).policy.data)


@router.post("/admin/policy/reload")
async def reload_policy(request: Request) -> Response:
    if (g := _admin_guard(request)) is not None:
        return g
    try:
        return JSONResponse({"reloaded": True, **svc(request).reload()})
    except Exception as exc:  # noqa: BLE001 - invalid files must not take the gateway down
        return JSONResponse({"reloaded": False, "error": str(exc)[:300], "note": "previous config kept"}, status_code=400)


@router.get("/admin/stats")
async def stats(request: Request) -> Response:
    if (g := _admin_guard(request)) is not None:
        return g
    s = svc(request)
    rows = await run_in_threadpool(s.audit.recent, 5000)
    inputs = [r for r in rows if r["direction"] == "input"]
    by_cat: dict[str, int] = {}
    decisions = {"allow": 0, "redact": 0, "block": 0}
    lat: dict[str, float] = {}
    for r in rows:
        if r["direction"] == "input":
            decisions[r["decision"]] += 1
        elif r["decision"] == "block":
            decisions["block"] += 1
        if r["decision"] == "block":
            for c in (r["categories"][:1] or ["other"]):
                by_cat[c] = by_cat.get(c, 0) + 1
        lat[r["request_id"]] = lat.get(r["request_id"], 0.0) + float(r["latency_ms"].get("total", 0.0))
    return JSONResponse({
        "requests": len(inputs), "decisions": decisions, "blocks_by_category": by_cat,
        "avg_pipeline_latency_ms": round(sum(lat.values()) / len(lat), 3) if lat else 0.0,
        "recent": rows[:25], "mode_default": s.policy.data["default_mode"], "window": "last 5000 audit events",
    })
