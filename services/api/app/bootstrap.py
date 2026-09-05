from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXTRA = [
    ROOT,
    ROOT / "packages" / "schemas",
    ROOT / "packages" / "python-common",
    ROOT / "packages" / "detection-sdk",
    ROOT / "packages" / "playbook-sdk",
    ROOT / "packages" / "quality-engine",
    ROOT / "packages" / "blue-range",
    ROOT / "packages" / "execution-broker",
    ROOT / "packages" / "sigma-compiler",
    ROOT / "packages" / "yara-engine",
    ROOT / "packages" / "blueql",
    ROOT / "packages" / "rego-engine",
    ROOT / "packages" / "sql-hunts",
    ROOT / "packages" / "event-fabric",
    ROOT / "packages" / "clickhouse-store",
    ROOT / "packages" / "network-adapters",
    ROOT / "packages" / "endpoint-adapters",
    ROOT / "packages" / "correlation",
    ROOT / "packages" / "entity-graph",
    ROOT / "packages" / "self-improvement",
    ROOT / "packages" / "object-store",
    ROOT / "packages" / "enrichment",
    ROOT / "packages" / "ingest-adapters",
    ROOT / "packages" / "dataplane-clients",
    ROOT / "services" / "api",
]


def ensure_paths() -> None:
    for path in EXTRA:
        text = str(path)
        if text not in sys.path:
            sys.path.insert(0, text)


ensure_paths()
