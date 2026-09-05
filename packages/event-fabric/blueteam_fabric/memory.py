"""In-process fabric used when Redpanda is not configured. Same contract as Kafka."""

from __future__ import annotations

from collections import defaultdict, deque
from threading import Lock
from typing import Any

from blueteam_fabric.envelope import FabricEnvelope
from blueteam_fabric.topics import ALL_TOPICS, DEADLETTER


class InMemoryFabric:
    backend = "memory"

    def __init__(self) -> None:
        self._topics: dict[str, deque[FabricEnvelope]] = {name: deque() for name in ALL_TOPICS}
        self._consumed: set[str] = set()
        self._offsets: dict[str, int] = defaultdict(int)
        self._published: dict[str, int] = defaultdict(int)
        self._lag: dict[str, int] = defaultdict(int)
        self._lock = Lock()

    def ensure_topics(self) -> list[str]:
        return list(ALL_TOPICS)

    def publish(self, message: FabricEnvelope) -> str:
        if message.topic not in self._topics:
            raise ValueError(f"unknown topic {message.topic}")
        with self._lock:
            self._topics[message.topic].append(message)
            self._published[message.topic] += 1
            self._lag[message.topic] = len(self._topics[message.topic])
        return message.event_id

    def consume(
        self,
        topic: str,
        *,
        max_records: int = 100,
        group: str = "default",
    ) -> list[FabricEnvelope]:
        if topic not in self._topics:
            raise ValueError(f"unknown topic {topic}")
        batch: list[FabricEnvelope] = []
        with self._lock:
            while self._topics[topic] and len(batch) < max_records:
                item = self._topics[topic].popleft()
                key = f"{group}:{item.idempotency_key}"
                if key in self._consumed:
                    continue
                self._consumed.add(key)
                self._offsets[f"{group}:{topic}"] += 1
                batch.append(item)
            self._lag[topic] = len(self._topics[topic])
        return batch

    def dead_letter(self, message: FabricEnvelope, reason: str) -> str:
        poisoned = message.model_copy(
            update={
                "topic": DEADLETTER,
                "poison": True,
                "attempt": message.attempt + 1,
                "idempotency_key": f"dlq:{message.idempotency_key}",
                "payload": {**message.payload, "dlq_reason": reason, "original_topic": message.topic},
            }
        )
        return self.publish(poisoned)

    def lag(self) -> dict[str, int]:
        with self._lock:
            return dict(self._lag)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "backend": self.backend,
                "published": dict(self._published),
                "offsets": dict(self._offsets),
                "lag": dict(self._lag),
                "idempotent_keys": len(self._consumed),
            }
