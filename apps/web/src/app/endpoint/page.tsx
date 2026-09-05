"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { api } from "@/lib/api";

type Tree = {
  nodes: { id: string; name?: string; pid?: number; event_id?: string | null; inferred_from_child?: boolean }[];
  edges: { parent: string; child: string; event_id: string }[];
  manufactured_edges: boolean;
};

export default function EndpointPage() {
  const [tree, setTree] = useState<Tree | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Tree>("/api/v1/investigate/process-tree")
      .then(setTree)
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <AppShell
      title="Endpoint Investigation"
      description="Process lineage is generated from telemetry. Missing parents are marked inferred and are never drawn as invented edges."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!tree ? <StateBox kind="loading" text="Loading process tree…" /> : null}
      {tree && tree.nodes.length === 0 ? (
        <StateBox kind="empty" text="No process events. Ingest Sysmon, Wazuh, osquery, or Linux audit records." />
      ) : null}
      {tree ? (
        <Panel title="PROCESS GRAPH">
          <div>Manufactured edges: {String(tree.manufactured_edges)}</div>
          {tree.edges.map((edge) => (
            <div key={`${edge.parent}->${edge.child}`} style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
              {edge.parent} → {edge.child} ({edge.event_id})
            </div>
          ))}
        </Panel>
      ) : null}
    </AppShell>
  );
}
