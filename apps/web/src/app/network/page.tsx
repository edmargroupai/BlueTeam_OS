"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { api } from "@/lib/api";

type Session = {
  session_id: string;
  src: string;
  dst: string;
  protocol: string;
  start: string;
  end: string;
  packets: number;
  zeek_refs: string[];
  suricata_refs: string[];
  risk: number;
};

export default function NetworkPage() {
  const [items, setItems] = useState<Session[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<{ items: Session[] }>("/api/v1/investigate/sessions")
      .then((body) => setItems(body.items))
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <AppShell
      title="Network Investigation"
      description="Sessions are derived from stored telemetry. The UI does not invent flows that are not in the event store."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!items ? <StateBox kind="loading" text="Loading sessions…" /> : null}
      {items && items.length === 0 ? (
        <StateBox kind="empty" text="No network sessions. Ingest Zeek or Suricata JSON to populate this view." />
      ) : null}
      {items?.map((item) => (
        <Panel key={item.session_id} title={`${item.src} → ${item.dst}`}>
          <div>
            {item.protocol} · packets {item.packets} · risk {item.risk}
          </div>
          <div style={{ color: "var(--muted)", fontFamily: "var(--font-mono)", fontSize: 12 }}>
            zeek {item.zeek_refs.join(", ") || "none"} · suricata {item.suricata_refs.join(", ") || "none"}
          </div>
        </Panel>
      ))}
    </AppShell>
  );
}
