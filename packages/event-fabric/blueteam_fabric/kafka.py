"""Redpanda/Kafka backend. Only used when a bootstrap server actually answers."""

from __future__ import annotations

import json
from typing import Any

from blueteam_fabric.envelope import FabricEnvelope
from blueteam_fabric.topics import ALL_TOPICS, DEADLETTER

MAX_RETRIES = 3


class KafkaUnavailable(RuntimeError):
    pass


def kafka_client_available() -> bool:
    try:
        import kafka  # noqa: F401

        return True
    except ImportError:
        return False


class KafkaFabric:
    backend = "redpanda"

    def __init__(self, bootstrap: str) -> None:
        if not bootstrap:
            raise KafkaUnavailable("kafka bootstrap is empty")
        if not kafka_client_available():
            raise KafkaUnavailable("kafka-python is not installed")
        from kafka import KafkaAdminClient, KafkaConsumer, KafkaProducer
        from kafka.admin import NewTopic
        from kafka.errors import TopicAlreadyExistsError

        self.bootstrap = bootstrap
        self._admin_cls = KafkaAdminClient
        self._producer_cls = KafkaProducer
        self._consumer_cls = KafkaConsumer
        self._new_topic = NewTopic
        self._exists = TopicAlreadyExistsError
        self._consumed: set[str] = set()
        try:
            admin = KafkaAdminClient(bootstrap_servers=bootstrap, request_timeout_ms=4000)
            admin.close()
        except Exception as exc:
            raise KafkaUnavailable(f"Redpanda not reachable at {bootstrap}: {exc}") from exc

    def ensure_topics(self) -> list[str]:
        admin = self._admin_cls(bootstrap_servers=self.bootstrap, request_timeout_ms=8000)
        try:
            topics = [self._new_topic(name=name, num_partitions=1, replication_factor=1) for name in ALL_TOPICS]
            try:
                admin.create_topics(topics)
            except self._exists:
                pass
            except Exception as exc:
                if "already exists" not in str(exc).lower() and "TopicExists" not in type(exc).__name__:
                    raise
            return list(ALL_TOPICS)
        finally:
            admin.close()

    def _producer(self):
        return self._producer_cls(
            bootstrap_servers=self.bootstrap,
            value_serializer=lambda value: json.dumps(value).encode("utf-8"),
            key_serializer=lambda value: value.encode("utf-8"),
            acks="all",
            retries=MAX_RETRIES,
        )

    def publish(self, message: FabricEnvelope) -> str:
        producer = self._producer()
        try:
            producer.send(
                message.topic,
                key=message.partition_key or message.tenant_id,
                value=message.model_dump(mode="json"),
            )
            producer.flush(timeout=8)
        finally:
            producer.close()
        return message.event_id

    def consume(
        self,
        topic: str,
        *,
        max_records: int = 100,
        group: str = "blueteam-runtime",
    ) -> list[FabricEnvelope]:
        consumer = self._consumer_cls(
            topic,
            bootstrap_servers=self.bootstrap,
            group_id=group,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            consumer_timeout_ms=2000,
            value_deserializer=lambda raw: json.loads(raw.decode("utf-8")),
        )
        batch: list[FabricEnvelope] = []
        try:
            records = consumer.poll(timeout_ms=2000, max_records=max_records)
            for packets in records.values():
                for record in packets:
                    payload = record.value
                    key = f"{group}:{payload.get('idempotency_key')}"
                    if key in self._consumed:
                        continue
                    self._consumed.add(key)
                    batch.append(FabricEnvelope.model_validate(payload))
            consumer.commit()
        finally:
            consumer.close()
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
        from kafka import KafkaAdminClient, KafkaConsumer
        from kafka.structs import TopicPartition

        admin = KafkaAdminClient(bootstrap_servers=self.bootstrap, request_timeout_ms=4000)
        consumer = KafkaConsumer(bootstrap_servers=self.bootstrap, group_id="blueteam-runtime")
        try:
            result: dict[str, int] = {}
            for topic in ALL_TOPICS:
                partitions = consumer.partitions_for_topic(topic) or set()
                lag = 0
                for partition in partitions:
                    tp = TopicPartition(topic, partition)
                    end = consumer.end_offsets([tp]).get(tp, 0)
                    committed = consumer.committed(tp) or 0
                    lag += max(0, end - committed)
                result[topic] = lag
            return result
        finally:
            consumer.close()
            admin.close()

    def stats(self) -> dict[str, Any]:
        return {"backend": self.backend, "bootstrap": self.bootstrap, "lag": self.lag()}
