"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { api } from "@/lib/api";

type Finding = {
  id: string;
  rule_id: string;
  title: string;
  explanation: string;
  mitre_techniques: string[];
  evidence_ids: string[];
};

export default function IdentityPage() {
  const [items, setItems] = useState<Finding[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<{ items: Finding[] }>("/api/v1/detections/findings")
      .then((body) => setItems(body.items.filter((item) => item.rule_id.startsWith("identity."))))
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <AppShell
      title="Identity Investigation"
      description="Identity findings produced by deterministic rules. Each finding cites evidence IDs from primary telemetry."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!items ? <StateBox kind="loading" text="Loading identity findings…" /> : null}
      {items && items.length === 0 ? (
        <StateBox kind="empty" text="No identity findings. Run Blue Range or ingest authentication telemetry." />
      ) : null}
      {items?.map((item) => (
        <Panel key={item.id} title={item.rule_id}>
          <div>{item.title}</div>
          <p style={{ color: "var(--muted)" }}>{item.explanation}</p>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
            ATT&CK {item.mitre_techniques.join(", ")} · evidence {item.evidence_ids.join(", ") || "none"}
          </div>
        </Panel>
      ))}
    </AppShell>
  );
}
