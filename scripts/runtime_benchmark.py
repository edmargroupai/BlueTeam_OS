"""Measure local runtime slices. Prints the actual host — no generic claims."""

from __future__ import annotations

import platform
import time
from pathlib import Path

from app.bootstrap import ensure_paths

ensure_paths()

from blueteam_fabric.memory import InMemoryFabric
from blueteam_fabric.pipeline import EventPipeline
from blueteam_network.normalize import normalize_zeek
from blueteam_yara.engine import scan_bytes

from detections.python.catalog import build_default_registry

TENANT = "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    from app.services.normalizer import normalize_generic

    print(f"hardware={platform.machine()} os={platform.platform()} python={platform.python_version()}")
    payloads = []
    for idx in range(200):
        event = normalize_zeek(
            {
                "_path": "conn",
                "ts": "2026-09-05T10:00:00Z",
                "uid": f"Cbench{idx}",
                "id": {"orig_h": "10.0.0.44", "resp_h": f"10.0.2.{idx % 20}", "orig_p": 4000, "resp_p": 22},
                "proto": "tcp",
            },
            TENANT,
        )
        payloads.append(event.model_dump(mode="json"))
    pipeline = EventPipeline(InMemoryFabric(), normalizer=normalize_generic, registry=build_default_registry())
    started = time.perf_counter()
    result = pipeline.run_once(TENANT, payloads)
    elapsed = time.perf_counter() - started
    print(f"ingest_events={len(payloads)} seconds={elapsed:.4f} events_per_sec={len(payloads)/elapsed:.1f}")
    print(f"normalization_and_detection={result}")
    rule = (ROOT / "security-languages/yara/webshells/webshell_eval.yar").read_text(encoding="utf-8")
    sample = (ROOT / "security-languages/yara/corpus/known-malicious/webshell_sample.php.txt").read_bytes()
    yara_started = time.perf_counter()
    match = scan_bytes(sample, rule)
    print(f"yara_engine={match.engine if match else 'none'} duration_ms={(time.perf_counter()-yara_started)*1000:.3f}")


if __name__ == "__main__":
    main()
