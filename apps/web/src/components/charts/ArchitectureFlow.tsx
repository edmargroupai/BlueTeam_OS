"use client";

import { useMemo } from "react";
import {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { tokens } from "@/lib/tokens.generated";
import { StateBox } from "@/components/AppShell";

type ArchNode = {
  id: string;
  kind: string;
  name: string;
  attributes?: Record<string, unknown>;
};

type ArchEdge = {
  id?: string;
  source: string;
  target: string;
  relation: string;
};

const KIND_COLOR: Record<string, string> = {
  zone: tokens.color.accent,
  control: tokens.color.low,
  sensor: tokens.color.medium,
  asset: tokens.color.high,
  identity: tokens.color.info,
  trust_boundary: tokens.color.critical,
};

export function ArchitectureFlow({
  nodes: archNodes,
  edges: archEdges,
}: {
  nodes: ArchNode[];
  edges: ArchEdge[];
}) {
  const { nodes, edges } = useMemo(() => {
    const byKind = new Map<string, ArchNode[]>();
    for (const node of archNodes) {
      const list = byKind.get(node.kind) ?? [];
      list.push(node);
      byKind.set(node.kind, list);
    }
    const kindOrder = Array.from(byKind.keys()).sort();
    const flowNodes: Node[] = [];
    kindOrder.forEach((kind, col) => {
      (byKind.get(kind) ?? []).forEach((node, row) => {
        flowNodes.push({
          id: node.id,
          position: { x: col * 220, y: row * 90 },
          data: { label: `${node.name}\n(${node.kind})` },
          style: {
            background: tokens.color.surfaceRaised,
            border: `1px solid ${KIND_COLOR[kind] ?? tokens.color.border}`,
            color: tokens.color.text,
            fontFamily: tokens.font.mono,
            fontSize: 11,
            padding: 10,
            width: 170,
            whiteSpace: "pre-line",
          },
        });
      });
    });

    const flowEdges: Edge[] = archEdges.map((edge, idx) => ({
      id: edge.id || `${edge.source}->${edge.target}:${edge.relation}:${idx}`,
      source: edge.source,
      target: edge.target,
      label: edge.relation,
      markerEnd: { type: MarkerType.ArrowClosed, color: tokens.color.muted },
      style: { stroke: tokens.color.border },
      labelStyle: { fill: tokens.color.muted, fontSize: 10, fontFamily: tokens.font.mono },
    }));

    return { nodes: flowNodes, edges: flowEdges };
  }, [archNodes, archEdges]);

  if (archNodes.length === 0) {
    return <StateBox kind="empty" text="Architecture graph has no nodes." />;
  }

  return (
    <div>
      <div style={{ height: 380, border: "1px solid var(--border)", background: "var(--surface-raised)" }}>
        <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }}>
          <Background color={tokens.color.border} gap={18} />
          <MiniMap nodeColor={tokens.color.accent} maskColor="rgba(11,14,20,0.7)" />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <table className="btos-table" aria-label="Architecture graph accessible summary">
        <thead>
          <tr>
            <th>Node</th>
            <th>Kind</th>
            <th>Name</th>
          </tr>
        </thead>
        <tbody>
          {archNodes.map((node) => (
            <tr key={node.id}>
              <td className="mono">{node.id}</td>
              <td className="mono">{node.kind}</td>
              <td>{node.name}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
