"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, Severity, StateBox } from "@/components/AppShell";
import { api } from "@/lib/api";

type Alert = { id: string; title: string; severity: string; status: string; created_at: string };

export default function AlertsPage() {
  const [items, setItems] = useState<Alert[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<{ items: Alert[] }>("/api/v1/alerts")
      .then((body) => setItems(body.items))
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <AppShell title="Live Alerts" description="Alerts created by the detection engine when a finding is persisted.">
      {error ? <StateBox kind="error" text={error} /> : null}
      {!items ? <StateBox kind="loading" text="Loading alerts…" /> : null}
      {items && items.length === 0 ? <StateBox kind="empty" text="No alerts for this tenant." /> : null}
      {items && items.length > 0 ? (
        <Panel title="OPEN AND RECENT">
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ textAlign: "left", color: "var(--muted)" }}>
                <th>Severity</th>
                <th>Status</th>
                <th>Title</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} style={{ borderTop: "1px solid var(--border)" }}>
                  <td>
                    <Severity value={item.severity} />
                  </td>
                  <td>{item.status}</td>
                  <td>{item.title}</td>
                  <td style={{ fontFamily: "var(--font-mono)" }}>{item.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      ) : null}
    </AppShell>
  );
}
