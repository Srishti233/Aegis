"""Aegis application factory."""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.config import Settings, get_settings
from app.services import Services, build_services

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if services is None:
            app.state.services = build_services(settings or get_settings())
        yield
        await app.state.services.http.aclose()

    app = FastAPI(title="Aegis LLM Firewall", version="1.0.0", lifespan=lifespan)
    if services is not None:
        app.state.services = services
    app.include_router(router)
    return app


app = create_app()
