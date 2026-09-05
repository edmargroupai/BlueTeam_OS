"""YARA scan. Production prefers libYARA; subset remains a labeled fallback."""

from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blueteam_yara.libyara import libyara_available
from blueteam_yara.libyara import scan_bytes as libyara_scan

RULE_HEAD = re.compile(r"rule\s+([A-Za-z_][A-Za-z0-9_]*)")
STRING_DEF = re.compile(r'\$([A-Za-z0-9_]+)\s*=\s*"((?:\\.|[^"\\])*)"')
CONDITION = re.compile(r"condition:\s*(.+)", re.S)
META_LINE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"', re.M)

FORBIDDEN = ("import ", "entrypoint", "for all", "for any", "at ", "int8(", "uint32(")
MAX_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class YaraMatch:
    rule_id: str
    matched_strings: list[str]
    engine: str
    meta: dict[str, str] = field(default_factory=dict)
    duration_ms: float = 0.0
    rule_version: str = "1.0.0"
    source: str = "security-languages/yara"


def validate_rule(text: str) -> str:
    if not RULE_HEAD.search(text):
        raise ValueError("YARA rule must declare a rule identifier")
    if "strings:" not in text or "condition:" not in text:
        raise ValueError("YARA rule requires strings and condition sections")
    for token in FORBIDDEN:
        if token in text:
            raise ValueError(f"unsupported YARA feature in subset matcher: {token.strip()}")
    name = RULE_HEAD.search(text)
    assert name
    return name.group(1)


def rule_metadata(text: str) -> dict[str, str]:
    return {match.group(1): match.group(2) for match in META_LINE.finditer(text)}


def _strings(text: str) -> dict[str, str]:
    decoded = {}
    for match in STRING_DEF.finditer(text):
        decoded[match.group(1)] = bytes(match.group(2), "utf-8").decode("unicode_escape")
    return decoded


def _subset_scan(content: bytes, rule_text: str) -> YaraMatch | None:
    started = time.perf_counter()
    rule_id = validate_rule(rule_text)
    strings = _strings(rule_text)
    if not strings:
        raise ValueError("no string identifiers found")
    cond_match = CONDITION.search(rule_text)
    condition = (cond_match.group(1) if cond_match else "").split("}")[0].strip()
    haystack = content.decode("latin-1", "ignore")
    found = [
        name
        for name, value in strings.items()
        if value.encode("utf-8") in content or value in haystack
    ]
    if "all of them" in condition:
        ok = len(found) == len(strings)
    elif "any of them" in condition or not condition:
        ok = bool(found)
    else:
        raise ValueError("unsupported condition — use 'all of them' or 'any of them'")
    duration_ms = (time.perf_counter() - started) * 1000
    if not ok:
        return None
    meta = rule_metadata(rule_text)
    return YaraMatch(
        rule_id=rule_id,
        matched_strings=found,
        engine="blueteam_yara.subset",
        meta=meta,
        duration_ms=round(duration_ms, 3),
        rule_version=meta.get("version", "1.0.0"),
    )


def scan_bytes(content: bytes, rule_text: str, *, prefer_libyara: bool = True) -> YaraMatch | None:
    if len(content) > MAX_BYTES:
        raise ValueError(f"scan payload exceeds {MAX_BYTES} bytes")
    if prefer_libyara and libyara_available():
        match = libyara_scan(content, rule_text)
        if match is None:
            return None
        return YaraMatch(
            rule_id=match.rule_id,
            matched_strings=match.matched_strings,
            engine="libyara",
            meta=match.meta,
            duration_ms=match.duration_ms,
            rule_version=match.meta.get("version", "1.0.0"),
        )
    return _subset_scan(content, rule_text)


def load_rules(root: Path) -> dict[str, str]:
    rules: dict[str, str] = {}
    for path in root.rglob("*.yar"):
        text = path.read_text(encoding="utf-8")
        rules[validate_rule(text)] = text
    return rules


def scan_b64(params: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(params.get("rule_id") or "")
    payload = base64.b64decode(str(params.get("content_b64") or ""), validate=True)
    root = Path(__file__).resolve().parents[3] / "security-languages" / "yara"
    rules = load_rules(root)
    if rule_id not in rules:
        raise ValueError(f"unknown approved YARA rule {rule_id}")
    match = scan_bytes(payload, rules[rule_id])
    engine = match.engine if match else ("libyara" if libyara_available() else "blueteam_yara.subset")
    return {
        "rule_id": rule_id,
        "filename": params.get("filename"),
        "matched": match is not None,
        "matched_strings": match.matched_strings if match else [],
        "engine": engine,
        "rule_version": match.rule_version if match else rule_metadata(rules[rule_id]).get("version", "1.0.0"),
        "duration_ms": match.duration_ms if match else 0.0,
        "source": "security-languages/yara",
        "evidence": {
            "kind": "yara.match" if match else "yara.clean",
            "rule_id": rule_id,
            "engine": engine,
            "filename": params.get("filename"),
            "matched_strings": match.matched_strings if match else [],
        }
        if match
        else None,
    }


def active_engine() -> str:
    return "libyara" if libyara_available() else "blueteam_yara.subset"
