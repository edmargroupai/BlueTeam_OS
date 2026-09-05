"""Syslog RFC3164 / RFC5424 adapter. HTTP transport of syslog lines, not a UDP daemon."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_schemas.events import CanonicalEvent, CanonicalHost, CanonicalUser

RFC5424 = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d+)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$"
)
RFC3164 = re.compile(
    r"^<(?P<pri>\d+)>(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_syslog_line(line: str, tenant_id: str) -> CanonicalEvent:
    text = line.strip()
    if not text:
        raise ValueError("empty syslog line")
    parsed: dict[str, Any]
    match = RFC5424.match(text)
    if match:
        parsed = match.groupdict()
        timestamp = _ts(parsed["ts"])
        host = parsed["host"]
        app = parsed["app"]
        message = parsed["rest"]
        if message.startswith("- "):
            message = message[2:]
        elif message.startswith("["):
            message = message.split("]", 1)[-1].strip()
    else:
        match = RFC3164.match(text)
        if match:
            parsed = match.groupdict()
            timestamp = utcnow()
            host = parsed["host"]
            app = "syslog"
            message = parsed["rest"]
        else:
            parsed = {"raw": text}
            timestamp = utcnow()
            host = "unknown"
            app = "syslog"
            message = text

    user = None
    user_match = re.search(r"(?:user|account|for)\s+([A-Za-z0-9_.-]+)", message, re.I)
    if user_match:
        user = CanonicalUser(name=user_match.group(1))
    ips = IP_RE.findall(message)
    outcome = "failure" if re.search(r"fail|denied|invalid|refused", message, re.I) else "success"
    category = "authentication" if re.search(r"password|login|auth|sshd", message, re.I) else "log"
    return CanonicalEvent(
        id=new_id("evt"),
        tenant_id=tenant_id,
        timestamp=timestamp,
        ingested_at=utcnow(),
        source="syslog",
        source_type=str(app or "syslog"),
        event_type="syslog",
        category=category,
        user=user,
        host=CanonicalHost(name=host if host not in {"-", "unknown"} else None),
        src_ip=ips[0] if ips else None,
        dst_ip=ips[1] if len(ips) > 1 else None,
        action="log",
        outcome=outcome,  # type: ignore[arg-type]
        raw_event={"syslog_raw": text, "message": message, **{k: v for k, v in parsed.items() if k != "rest"}},
        attributes={"adapter": "syslog", "message": message[:400]},
    )


def _ts(value: str) -> datetime:
    if value in {"-", ""}:
        return utcnow()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
