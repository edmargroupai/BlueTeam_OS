"""Real libYARA path. Import fails unless an established binding is installed."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

MAX_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT_S = 5.0
_CACHE: dict[str, Any] = {}


@dataclass(frozen=True)
class LibYaraMatch:
    rule_id: str
    matched_strings: list[str]
    meta: dict[str, str]
    engine: str = "libyara"
    duration_ms: float = 0.0


def libyara_available() -> bool:
    try:
        import yara  # noqa: F401

        return True
    except ImportError:
        return False


def compile_rule(rule_text: str) -> Any:
    import yara

    digest = hashlib.sha256(rule_text.encode("utf-8")).hexdigest()
    cached = _CACHE.get(digest)
    if cached is not None:
        return cached
    compiled = yara.compile(source=rule_text)
    _CACHE[digest] = compiled
    return compiled


def scan_bytes(
    content: bytes,
    rule_text: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
    filename: str | None = None,
) -> LibYaraMatch | None:
    if len(content) > MAX_BYTES:
        raise ValueError(f"scan payload exceeds {MAX_BYTES} bytes")
    started = time.perf_counter()
    compiled = compile_rule(rule_text)
    matches = compiled.match(data=content, timeout=timeout)
    duration_ms = (time.perf_counter() - started) * 1000
    if not matches:
        return None
    first = matches[0]
    strings = []
    for item in getattr(first, "strings", []) or []:
        ident = getattr(item, "identifier", None)
        if ident is None and isinstance(item, tuple) and len(item) > 1:
            ident = item[1]
        elif ident is None:
            ident = str(item)
        strings.append(str(ident).lstrip("$"))
    meta = {str(key): str(value) for key, value in (getattr(first, "meta", {}) or {}).items()}
    return LibYaraMatch(
        rule_id=first.rule,
        matched_strings=strings,
        meta=meta,
        duration_ms=round(duration_ms, 3),
    )
