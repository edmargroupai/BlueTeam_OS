"""Lightweight observability counters — no vendor OTel required for PARTIAL."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any


@dataclass
class MetricsRegistry:
    counters: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    gauges: dict[str, float] = field(default_factory=dict)
    timings: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))

    def incr(self, name: str, value: float = 1.0) -> None:
        self.counters[name] += value

    def gauge(self, name: str, value: float) -> None:
        self.gauges[name] = value

    def observe(self, name: str, seconds: float) -> None:
        self.timings[name].append(seconds)

    def as_prometheus(self) -> str:
        lines = ["# HELP btos_info Blue Team OS control-plane metrics", "# TYPE btos_info gauge", "btos_info 1"]
        for name, value in sorted(self.counters.items()):
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {value}")
        for name, value in sorted(self.gauges.items()):
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")
        for name, samples in sorted(self.timings.items()):
            if not samples:
                continue
            avg = sum(samples) / len(samples)
            lines.append(f"# TYPE {name}_avg gauge")
            lines.append(f"{name}_avg {avg}")
            lines.append(f"# TYPE {name}_count counter")
            lines.append(f"{name}_count {len(samples)}")
        return "\n".join(lines) + "\n"

    def snapshot(self) -> dict[str, Any]:
        return {
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "timings": {
                key: {"count": len(vals), "avg": (sum(vals) / len(vals) if vals else 0)}
                for key, vals in self.timings.items()
            },
        }


METRICS = MetricsRegistry()


class Timer:
    def __init__(self, name: str) -> None:
        self.name = name
        self._start = 0.0

    def __enter__(self) -> Timer:
        self._start = perf_counter()
        return self

    def __exit__(self, *args: object) -> None:
        METRICS.observe(self.name, perf_counter() - self._start)
