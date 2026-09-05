"""Create control-plane schema from SQLAlchemy metadata.

Revision ID: 0001_control_plane
Revises:
Create Date: 2026-09-05
"""

from __future__ import annotations

from typing import Sequence, Union

from app.bootstrap import ensure_paths

ensure_paths()

import app.models  # noqa: F401
from app.models.base import Base

revision: str = "0001_control_plane"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from alembic import op

    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    from alembic import op

    Base.metadata.drop_all(bind=op.get_bind())
