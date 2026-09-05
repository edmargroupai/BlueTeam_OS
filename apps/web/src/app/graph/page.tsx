"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
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

type Rel = { id: string; src_id: string; dst_id: string; relation: string; event_ids: string[]; manufactured: boolean };

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
      description="Users, hosts, IPs, domains, and processes extracted from stored telemetry. Edges are observed only. Risk components cite findings."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!entities ? <StateBox kind="loading" text="Loading entity graph…" /> : null}
      {entities && entities.length === 0 ? (
        <StateBox kind="empty" text="No entities. Ingest telemetry so the graph can be projected from events." />
      ) : null}
      {entities?.map((entity) => (
        <Panel key={entity.id} title={`${entity.entity_type} · ${entity.display_name}`}>
          <div>
            Risk {entity.risk_score} · criticality {entity.criticality}
          </div>
          <div style={{ color: "var(--muted)", fontFamily: "var(--font-mono)", fontSize: 12 }}>
            events {entity.event_ids.join(", ") || "none"}
          </div>
          {entity.risk_components.map((item) => (
            <div key={`${item.source}:${item.kind}`} style={{ color: "var(--muted)", fontSize: 12 }}>
              {item.explanation}
            </div>
          ))}
        </Panel>
      ))}
      {rels.length > 0 ? (
        <Panel title="OBSERVED RELATIONSHIPS">
          {rels.map((rel) => (
            <div key={rel.id} style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
              {rel.src_id} —{rel.relation}→ {rel.dst_id} ({rel.event_ids.length} events)
            </div>
          ))}
        </Panel>
      ) : null}
    </AppShell>
  );
}
