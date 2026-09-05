"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

export default function ArchitecturePage() {
  const [graph, setGraph] = useState<Record<string, unknown> | null>(null);
  const [gaps, setGaps] = useState<{ gaps: unknown[] } | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      api<Record<string, unknown>>("/api/v1/architecture"),
      api<{ gaps: unknown[] }>("/api/v1/architecture/gaps"),
    ])
      .then(([g, gap]) => {
        setGraph(g);
        setGaps(gap);
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
        <Panel title={`GRAPH v${String(graph.version)}`}>
          <pre style={{ fontFamily: "var(--font-mono)", fontSize: 12, whiteSpace: "pre-wrap" }}>
            {JSON.stringify(graph, null, 2)}
          </pre>
        </Panel>
      ) : (
        <StateBox kind="loading" text="Loading architecture…" />
      )}
      {gaps ? <Panel title="GAPS">{gaps.gaps.length} gaps</Panel> : null}
    </AppShell>
  );
}
