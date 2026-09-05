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

type Step = {
  id: string;
  action_type: string;
  tier: number;
  depends_on: string[];
  rollback_action?: string | null;
};

export function PlaybookFlow({ steps }: { steps: Step[] }) {
  const { nodes, edges } = useMemo(() => {
    const byId = new Map(steps.map((step) => [step.id, step]));
    const levels = new Map<string, number>();

    function levelOf(id: string, seen = new Set<string>()): number {
      if (levels.has(id)) return levels.get(id)!;
      if (seen.has(id)) return 0;
      seen.add(id);
      const step = byId.get(id);
      if (!step || step.depends_on.length === 0) {
        levels.set(id, 0);
        return 0;
      }
      const lvl = Math.max(...step.depends_on.map((dep) => levelOf(dep, seen))) + 1;
      levels.set(id, lvl);
      return lvl;
    }

    steps.forEach((step) => levelOf(step.id));
    const buckets = new Map<number, Step[]>();
    for (const step of steps) {
      const lvl = levels.get(step.id) ?? 0;
      const list = buckets.get(lvl) ?? [];
      list.push(step);
      buckets.set(lvl, list);
    }

    const flowNodes: Node[] = [];
    for (const [lvl, list] of buckets) {
      list.forEach((step, idx) => {
        flowNodes.push({
          id: step.id,
          position: { x: lvl * 220, y: idx * 100 },
          data: {
            label: `${step.id}\n${step.action_type}\nT${step.tier}`,
          },
          style: {
            background: tokens.color.surfaceRaised,
            border: `1px solid ${tokens.color.border}`,
            color: tokens.color.text,
            fontFamily: tokens.font.mono,
            fontSize: 11,
            padding: 10,
            width: 180,
            whiteSpace: "pre-line",
          },
        });
      });
    }

    const flowEdges: Edge[] = [];
    for (const step of steps) {
      for (const dep of step.depends_on) {
        flowEdges.push({
          id: `${dep}->${step.id}`,
          source: dep,
          target: step.id,
          markerEnd: { type: MarkerType.ArrowClosed, color: tokens.color.muted },
          style: { stroke: tokens.color.border },
        });
      }
    }

    return { nodes: flowNodes, edges: flowEdges };
  }, [steps]);

  if (steps.length === 0) {
    return <StateBox kind="empty" text="Playbook has no steps to graph." />;
  }

  return (
    <div>
      <div style={{ height: 320, border: "1px solid var(--border)", background: "var(--surface-raised)" }}>
        <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }}>
          <Background color={tokens.color.border} gap={18} />
          <MiniMap
            nodeColor={tokens.color.accent}
            maskColor="rgba(11,14,20,0.7)"
            style={{ background: tokens.color.surface }}
          />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <table className="btos-table" aria-label="Playbook DAG accessible summary">
        <thead>
          <tr>
            <th>Step</th>
            <th>Action</th>
            <th>Tier</th>
            <th>Depends on</th>
          </tr>
        </thead>
        <tbody>
          {steps.map((step) => (
            <tr key={step.id}>
              <td className="mono">{step.id}</td>
              <td className="mono">{step.action_type}</td>
              <td className="mono">T{step.tier}</td>
              <td className="mono">{step.depends_on.join(", ") || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
