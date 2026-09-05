from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta

from blueteam_schemas.events import CanonicalEvent


class EventWindow:
    def __init__(self, events: Sequence[CanonicalEvent]) -> None:
        self._events = list(events)

    def query(
        self,
        *,
        tenant_id: str,
        since: datetime,
        until: datetime | None = None,
        event_type: str | None = None,
        category: str | None = None,
        outcome: str | None = None,
        src_ip: str | None = None,
        user_name: str | None = None,
        action: str | None = None,
    ) -> list[CanonicalEvent]:
        matched: list[CanonicalEvent] = []
        for event in self._events:
            if event.tenant_id != tenant_id:
                continue
            if event.timestamp < since:
                continue
            if until is not None and event.timestamp > until:
                continue
            if event_type and event.event_type != event_type:
                continue
            if category and event.category != category:
                continue
            if outcome and event.outcome != outcome:
                continue
            if src_ip and event.src_ip != src_ip:
                continue
            if user_name and (event.user is None or event.user.name != user_name):
                continue
            if action and event.action != action:
                continue
            matched.append(event)
        return matched


class DetectionContext:
    """Injected window and prior-finding fingerprints. Rules must not fetch remotely."""

    def __init__(
        self,
        window: EventWindow,
        open_fingerprints: Iterable[str] | None = None,
        *,
        scheduled: bool = False,
    ) -> None:
        self.window = window
        self.open_fingerprints = set(open_fingerprints or [])
        self.scheduled = scheduled

    def events_in_window(
        self,
        event: CanonicalEvent,
        seconds: int,
        **filters: str | None,
    ) -> list[CanonicalEvent]:
        since = event.timestamp - timedelta(seconds=seconds)
        return self.window.query(
            tenant_id=event.tenant_id,
            since=since,
            until=event.timestamp,
            **{k: v for k, v in filters.items() if v is not None},
        )

    def already_open(self, fingerprint: str) -> bool:
        return fingerprint in self.open_fingerprints
