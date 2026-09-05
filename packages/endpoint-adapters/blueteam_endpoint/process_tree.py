"""Process lineage from telemetry only. Missing parents are not invented."""

from __future__ import annotations

from typing import Any

from blueteam_schemas.events import CanonicalEvent


def build_process_tree(events: list[CanonicalEvent]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    for event in events:
        if not event.process or not (event.process.pid or event.process.name):
            continue
        node_id = _node_id(event)
        nodes[node_id] = {
            "id": node_id,
            "event_id": event.id,
            "name": event.process.name,
            "pid": event.process.pid,
            "path": event.process.path,
            "command_line": event.process.command_line,
            "host": event.host.name if event.host else None,
            "timestamp": event.timestamp.isoformat(),
        }
        parent_id = _parent_id(event)
        if parent_id:
            if parent_id not in nodes:
                # Record the observed parent identity without fabricating a missing event.
                nodes[parent_id] = {
                    "id": parent_id,
                    "event_id": None,
                    "name": event.parent_process.name if event.parent_process else None,
                    "pid": event.parent_process.pid if event.parent_process else None,
                    "path": event.parent_process.path if event.parent_process else None,
                    "command_line": event.parent_process.command_line if event.parent_process else None,
                    "host": event.host.name if event.host else None,
                    "timestamp": event.timestamp.isoformat(),
                    "inferred_from_child": True,
                }
            edges.append({"parent": parent_id, "child": node_id, "event_id": event.id})
    return {"nodes": list(nodes.values()), "edges": edges, "manufactured_edges": False}


def _node_id(event: CanonicalEvent) -> str:
    host = event.host.id or event.host.name if event.host else "host"
    pid = event.process.pid if event.process else None
    name = event.process.name if event.process else "unknown"
    if pid is not None:
        return f"{host}:{pid}:{name}"
    return f"{host}:{event.id}:{name}"


def _parent_id(event: CanonicalEvent) -> str | None:
    parent = event.parent_process
    if parent is None or not (parent.pid or parent.name):
        return None
    host = event.host.id or event.host.name if event.host else "host"
    if parent.pid is not None:
        return f"{host}:{parent.pid}:{parent.name or 'parent'}"
    return f"{host}:name:{parent.name}"
