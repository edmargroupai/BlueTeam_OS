"""Additive schema patches for hosted Postgres that already ran create_all."""

from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


INCIDENT_COLUMNS: dict[str, str] = {
    "severity": "VARCHAR(32) DEFAULT 'medium'",
    "assignee_user_id": "VARCHAR(40)",
    "assignee_email": "VARCHAR(240)",
    "source_alert_id": "VARCHAR(40)",
    "related_entity_ids": "JSON",
    "notes": "JSON",
    "tasks": "JSON",
    "timeline": "JSON",
    "root_cause": "TEXT",
    "lessons_learned": "TEXT",
}


def ensure_schema_patches(engine: Engine) -> list[str]:
    applied: list[str] = []
    inspector = inspect(engine)
    if "incidents" not in inspector.get_table_names():
        return applied
    existing = {col["name"] for col in inspector.get_columns("incidents")}
    dialect = engine.dialect.name
    with engine.begin() as conn:
        for name, ddl in INCIDENT_COLUMNS.items():
            if name in existing:
                continue
            if dialect == "sqlite":
                # SQLite ADD COLUMN cannot use non-constant JSON default in older versions; nullable OK.
                col_type = "TEXT" if ddl.startswith("JSON") or ddl.startswith("TEXT") else "VARCHAR(40)"
                if name == "severity":
                    conn.execute(text(f"ALTER TABLE incidents ADD COLUMN {name} VARCHAR(32) DEFAULT 'medium'"))
                else:
                    conn.execute(text(f"ALTER TABLE incidents ADD COLUMN {name} {col_type}"))
            else:
                conn.execute(text(f"ALTER TABLE incidents ADD COLUMN IF NOT EXISTS {name} {ddl}"))
            applied.append(f"incidents.{name}")
    return applied
