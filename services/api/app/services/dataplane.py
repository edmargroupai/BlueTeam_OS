"""Optional data-plane dual-write. Sync ingest remains authoritative."""

from __future__ import annotations

from typing import Any

from blueteam_common.hashing import canonical_json
from blueteam_schemas.events import CanonicalEvent

from app.core.config import get_settings


def best_effort_project(event: CanonicalEvent, raw_payload: dict[str, Any] | None = None) -> dict[str, str]:
    settings = get_settings()
    status = {
        "clickhouse": "unconfigured",
        "redpanda": "unconfigured",
        "opensearch": "unconfigured",
        "object_storage": "unconfigured",
    }
    raw = canonical_json(raw_payload or event.raw_event or event.model_dump(mode="json")).encode("utf-8")
    try:
        from blueteam_objects.store import open_store

        store = open_store(
            root=settings.object_store_root,
            endpoint=settings.s3_endpoint,
            bucket=settings.s3_bucket,
            access_key=settings.s3_access_key,
            secret_key=settings.s3_secret_key,
        )
        ref = store.put(event.tenant_id, f"raw/{event.id}.json", raw)
        event.attributes["raw_object_uri"] = ref.uri
        status["object_storage"] = f"written:{ref.backend}"
    except Exception as exc:
        status["object_storage"] = f"skipped:{type(exc).__name__}"
    if settings.clickhouse_url:
        try:
            from blueteam_clickhouse.client import connect

            client = connect(settings.clickhouse_url)
            client.insert_events([event])
            status["clickhouse"] = "written"
        except Exception as exc:
            status["clickhouse"] = f"skipped:{type(exc).__name__}"
    if settings.kafka_bootstrap:
        try:
            from blueteam_fabric.envelope import envelope
            from blueteam_fabric.kafka import KafkaFabric
            from blueteam_fabric.topics import RAW

            fabric = KafkaFabric(settings.kafka_bootstrap)
            fabric.ensure_topics()
            fabric.publish(envelope(RAW, event.tenant_id, event.model_dump(mode="json"), event_id=event.id))
            status["redpanda"] = "published"
        except Exception as exc:
            status["redpanda"] = f"skipped:{type(exc).__name__}"
    if settings.opensearch_url:
        try:
            from blueteam_dataplane.search import OpenSearchStore

            search = OpenSearchStore(settings.opensearch_url)
            search.index_event(event.tenant_id, event.id, event.model_dump(mode="json"))
            status["opensearch"] = "indexed"
        except Exception as exc:
            status["opensearch"] = f"skipped:{type(exc).__name__}"
    return status
