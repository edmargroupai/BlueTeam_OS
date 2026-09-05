"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { EntityGraphView } from "@/components/charts/EntityGraphView";
import { api } from "@/lib/api";

type Entity = {
  id: string;
  entity_type: string;
  display_name: string;
  criticality: string;
  risk_score: number;
  risk_components: { source: string; kind: string; points: number; explanation: string }[];
  event_ids: string[];
};

type Rel = {
  id: string;
  src_id: string;
  dst_id: string;
  relation: string;
  event_ids: string[];
  manufactured: boolean;
};

export default function GraphPage() {
  const [entities, setEntities] = useState<Entity[] | null>(null);
  const [rels, setRels] = useState<Rel[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api<{ entities: Entity[]; relationships: Rel[]; manufactured_edges: boolean }>("/api/v1/graph")
      .then((body) => {
        setEntities(body.entities);
        setRels(body.relationships);
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <AppShell
      title="Entity Graph"
      description="Cytoscape view of observed entities and relationships. Manufactured edges are excluded. Accessible table summarises risk."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!entities ? <StateBox kind="loading" text="Loading entity graph…" /> : null}
      {entities ? (
        <Panel title="OBSERVED GRAPH">
          <EntityGraphView entities={entities} relationships={rels} />
        </Panel>
      ) : null}
    </AppShell>
  );
}
