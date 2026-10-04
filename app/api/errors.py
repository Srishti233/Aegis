from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse


def oai_error(status: int, message: str, *, code: str, type_: str = "aegis_block", rid: str | None = None,
              headers: dict[str, str] | None = None, aegis: dict[str, Any] | None = None) -> JSONResponse:
    """OpenAI-style error body. `type` is `aegis_block` for policy blocks."""
    err: dict[str, Any] = {"message": message, "type": type_, "param": None, "code": code}
    if aegis:
        err["aegis"] = aegis
    h = dict(headers or {})
    if rid:
        h.setdefault("X-Aegis-Request-Id", rid)
    return JSONResponse({"error": err}, status_code=status, headers=h)
