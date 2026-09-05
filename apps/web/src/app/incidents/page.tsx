"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { api } from "@/lib/api";

type Incident = {
  id: string;
  title: string;
  status: string;
  storyline_ids: string[];
  event_ids: string[];
  mitre_techniques: string[];
  created_at: string;
};

export default function IncidentsPage() {
  const [items, setItems] = useState<Incident[] | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api<{ items: Incident[]; note?: string }>("/api/v1/incidents")
      .then((body) => {
        setItems(body.items);
        setNote(body.note ?? "");
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <AppShell
      title="Incidents"
      description="Phase 7 grouping only. Assignment, containment, and lessons are Phase 10 and are not claimed here."
    >
      {note ? <p style={{ color: "var(--muted)" }}>{note}</p> : null}
      {error ? <StateBox kind="error" text={error} /> : null}
      {!items ? <StateBox kind="loading" text="Loading grouped incidents…" /> : null}
      {items && items.length === 0 ? (
        <StateBox kind="empty" text="No correlated storylines have been grouped yet." />
      ) : null}
      {items?.map((item) => (
        <Panel key={item.id} title={`${item.id} · ${item.status}`}>
          <div>{item.title}</div>
          <div style={{ fontFamily: "var(--font-mono)", color: "var(--muted)" }}>
            {item.storyline_ids.length} storylines · {item.event_ids.length} events ·{" "}
            {item.mitre_techniques.join(", ") || "no ATT&CK map"}
          </div>
        </Panel>
      ))}
    </AppShell>
  );
}
