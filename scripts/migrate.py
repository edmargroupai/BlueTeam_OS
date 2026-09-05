"""Apply control-plane schema and optional seed. Uses BTOS_DATABASE_URL."""

from __future__ import annotations

from app.bootstrap import ensure_paths

ensure_paths()

from app.core.db import get_engine, get_session_factory
from app.models.base import Base
from app.services.rules import sync_catalog_revisions
from app.services.seed import seed_if_empty


def main() -> None:
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    session = get_session_factory()()
    try:
        seed_if_empty(session)
        sync_catalog_revisions(session)
        session.commit()
        print(f"migrated {engine.url.render_as_string(hide_password=True)}")
    finally:
        session.close()


if __name__ == "__main__":
    main()
