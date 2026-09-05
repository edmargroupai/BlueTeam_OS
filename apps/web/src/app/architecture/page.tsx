"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { ArchitectureFlow } from "@/components/charts/ArchitectureFlow";
import { ApiError, api } from "@/lib/api";

type ArchGraph = {
  version: number;
  nodes: { id: string; kind: string; name: string; attributes?: Record<string, unknown> }[];
  edges: { source: string; target: string; relation: string }[];
};

type Gap = { control?: string; technique?: string; gap: string };

export default function ArchitecturePage() {
  const [graph, setGraph] = useState<ArchGraph | null>(null);
  const [gaps, setGaps] = useState<Gap[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      api<ArchGraph>("/api/v1/architecture"),
      api<{ gaps: Gap[] }>("/api/v1/architecture/gaps"),
    ])
      .then(([g, gap]) => {
        setGraph(g);
        setGaps(gap.gaps);
      })
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed"));
  }, []);

  return (
    <AppShell
      title="Defensive Architecture"
      description="Typed zones, trust boundaries, assets, identities, controls, and sensors with deterministic detection-gap analysis."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {graph ? (
        <>
          <Panel title={`GRAPH v${graph.version}`}>
            <ArchitectureFlow nodes={graph.nodes} edges={graph.edges} />
          </Panel>
          <Panel title="DETECTION GAPS">
            {gaps.length === 0 ? (
              <StateBox kind="empty" text="No detection gaps against current control coverage list." />
            ) : (
              <table className="btos-table">
                <thead>
                  <tr>
                    <th>Gap</th>
                    <th>Control</th>
                    <th>Technique</th>
                  </tr>
                </thead>
                <tbody>
                  {gaps.map((item, idx) => (
                    <tr key={`${item.gap}-${idx}`}>
                      <td className="mono">{item.gap}</td>
                      <td>{item.control ?? "—"}</td>
                      <td className="mono">{item.technique ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </>
      ) : (
        <StateBox kind="loading" text="Loading architecture…" />
      )}
    </AppShell>
  );
}
