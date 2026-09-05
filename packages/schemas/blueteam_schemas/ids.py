"""Prefixed public identifiers. Prefixes make evidence references auditable at a glance."""

from __future__ import annotations

import uuid
from typing import Literal

Prefix = Literal[
    "ten",
    "usr",
    "rol",
    "mem",
    "key",
    "evt",
    "dlq",
    "fnd",
    "alt",
    "inc",
    "evi",
    "coc",
    "clm",
    "aud",
    "ses",
    "req",
    "brn",
    "qck",
    "ent",
    "rel",
    "stl",
    "rlv",
    "sup",
    "exc",
    "obj",
]


def new_id(prefix: Prefix) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def is_prefixed(value: str, prefix: Prefix) -> bool:
    return value.startswith(f"{prefix}_") and len(value) == len(prefix) + 1 + 32
