from __future__ import annotations

from app.bootstrap import ensure_paths

ensure_paths()

from contextlib import asynccontextmanager

from blueteam_common.errors import BlueTeamError
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

import app.models  # noqa: F401
from app.api import api_router
from app.core.config import get_settings
from app.core.db import get_engine, get_session_factory
from app.core.errors import blueteam_error_handler, http_error_handler, unhandled_error_handler
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware
from app.core.schema_patches import ensure_schema_patches
from app.models.base import Base
from app.services.seed import seed_if_empty


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        engine = get_engine()
        Base.metadata.create_all(bind=engine)
        ensure_schema_patches(engine)
        session = get_session_factory()()
        try:
            seed_if_empty(session)
            from app.services.seed import ensure_dev_credentials

            ensure_dev_credentials(session)
            from app.services.rules import sync_catalog_revisions

            sync_catalog_revisions(session)
            session.commit()
        finally:
            session.close()
        yield

    application = FastAPI(
        title="Blue Team OS Center API",
        version="0.1.0",
        description="Control plane for Blue Team OS. Detection logic lives in Python engines, not the UI.",
        lifespan=lifespan,
    )
    application.add_middleware(RequestContextMiddleware)
    cors_origins = settings.cors_allow_origins()
    cors_kwargs: dict = {
        "allow_origins": cors_origins,
        "allow_credentials": True,
        "allow_methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "allow_headers": ["Authorization", "Content-Type", "X-Tenant-ID", "X-API-Key", "X-Request-ID"],
    }
    regex = settings.cors_allow_origin_regex()
    if regex:
        cors_kwargs["allow_origin_regex"] = regex
    application.add_middleware(CORSMiddleware, **cors_kwargs)
    application.add_exception_handler(BlueTeamError, blueteam_error_handler)
    application.add_exception_handler(StarletteHTTPException, http_error_handler)
    application.add_exception_handler(Exception, unhandled_error_handler)
    application.include_router(api_router)
    return application


app = create_app()
