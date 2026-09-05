"""Collector → raw → normalize → detect. Sync ingest stays the source of truth."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from blueteam_detection.context import DetectionContext, EventWindow
from blueteam_detection.registry import DetectionRegistry
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from blueteam_fabric.envelope import FabricEnvelope, envelope
from blueteam_fabric.memory import InMemoryFabric
from blueteam_fabric.topics import DEADLETTER, FINDINGS, HEALTH, NORMALIZED, RAW


class NormalizationError(ValueError):
    pass


class EventPipeline:
    def __init__(
        self,
        fabric: Any,
        *,
        normalizer: Callable[[dict[str, Any], str], CanonicalEvent],
        registry: DetectionRegistry | None = None,
        max_attempts: int = 3,
    ) -> None:
        self.fabric = fabric
        self.normalizer = normalizer
        self.registry = registry
        self.max_attempts = max_attempts
        self.normalized: list[CanonicalEvent] = []
        self.findings: list[Finding] = []

    def ingest_raw(self, tenant_id: str, payload: dict[str, Any]) -> FabricEnvelope:
        message = envelope(RAW, tenant_id, payload, event_id=payload.get("id"))
        self.fabric.publish(message)
        return message

    def drain_raw(self, *, group: str = "normalizer") -> dict[str, int]:
        accepted = 0
        dead = 0
        for message in self._consume_all(RAW, group):
            try:
                event = self.normalizer(message.payload, message.tenant_id)
                if event.tenant_id != message.tenant_id:
                    raise NormalizationError("tenant mismatch after normalize")
                if not event.schema_version:
                    raise NormalizationError("schema_version missing after normalize")
                self.normalized.append(event)
                self.fabric.publish(
                    envelope(NORMALIZED, event.tenant_id, event.model_dump(mode="json"), event_id=event.id)
                )
                accepted += 1
            except Exception as exc:
                if message.attempt + 1 >= self.max_attempts:
                    self.fabric.dead_letter(message, f"poison: {exc}")
                    dead += 1
                else:
                    retry = message.model_copy(update={"attempt": message.attempt + 1})
                    self.fabric.publish(retry)
        return {"normalized": accepted, "dead_lettered": dead}

    def _consume_all(self, topic: str, group: str) -> list[FabricEnvelope]:
        batch: list[FabricEnvelope] = []
        while True:
            chunk = self.fabric.consume(topic, max_records=500, group=group)
            if not chunk:
                break
            batch.extend(chunk)
        return batch

    def drain_normalized(self, *, group: str = "detection") -> int:
        if self.registry is None:
            return 0
        created = 0
        for message in self._consume_all(NORMALIZED, group):
            event = CanonicalEvent.model_validate(message.payload)
            window = EventWindow(self.normalized)
            context = DetectionContext(window)
            produced = self.registry.evaluate(event, context)
            for finding in produced:
                context.open_fingerprints.add(finding.fingerprint)
                self.findings.append(finding)
                self.fabric.publish(
                    envelope(FINDINGS, finding.tenant_id, finding.model_dump(mode="json"), event_id=finding.id)
                )
                created += 1
        return created

    def publish_health(self, tenant_id: str, body: dict[str, Any]) -> str:
        return self.fabric.publish(envelope(HEALTH, tenant_id, body, event_id=body.get("id")))

    def run_once(self, tenant_id: str, payloads: list[dict[str, Any]]) -> dict[str, Any]:
        for payload in payloads:
            self.ingest_raw(tenant_id, payload)
        norm = self.drain_raw()
        findings = self.drain_normalized()
        return {
            "backend": getattr(self.fabric, "backend", "unknown"),
            "normalized": norm["normalized"],
            "dead_lettered": norm["dead_lettered"],
            "findings": findings,
            "lag": self.fabric.lag(),
            "dlq_topic": DEADLETTER,
        }


def default_memory_pipeline(
    normalizer: Callable[[dict[str, Any], str], CanonicalEvent],
    registry: DetectionRegistry | None = None,
) -> EventPipeline:
    return EventPipeline(InMemoryFabric(), normalizer=normalizer, registry=registry)
