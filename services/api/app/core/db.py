from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

_engine = None
_SessionLocal = None


def _ensure_sqlite_dir(url: str) -> None:
    if url.startswith("sqlite:///./"):
        path = Path(url.replace("sqlite:///./", ""))
        path.parent.mkdir(parents=True, exist_ok=True)


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        _ensure_sqlite_dir(settings.database_url)
        connect_args = {}
        engine_kwargs: dict = {"future": True}
        if settings.database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
            if settings.database_url.endswith(":memory:"):
                from sqlalchemy.pool import StaticPool

                engine_kwargs["poolclass"] = StaticPool
        engine_kwargs["connect_args"] = connect_args
        _engine = create_engine(settings.database_url, **engine_kwargs)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), autoflush=False, autocommit=False, future=True)
    return _SessionLocal


def reset_engine() -> None:
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
    get_settings.cache_clear()


def get_db() -> Generator[Session, None, None]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
