"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { api } from "@/lib/api";

type AuditItem = {
  id: string;
  sequence: number;
  action: string;
  actor_id: string;
  result: string;
  timestamp: string;
  record_hash: string;
};

export default function AuditPage() {
  const [items, setItems] = useState<AuditItem[] | null>(null);
  const [intact, setIntact] = useState<boolean | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      api<{ items: AuditItem[] }>("/api/v1/audit"),
      api<{ intact: boolean }>("/api/v1/audit/integrity"),
    ])
      .then(([list, chain]) => {
        setItems(list.items);
        setIntact(chain.intact);
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <AppShell
      title="Audit"
      description="Append-only hash-chained audit log. Integrity is verified from the stored chain, not assumed."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {intact === null && !error ? <StateBox kind="loading" text="Loading audit chain…" /> : null}
      {intact !== null ? (
        <Panel title="CHAIN">
          Hash chain {intact ? "intact" : "BROKEN"}
        </Panel>
      ) : null}
      {items && items.length === 0 ? <StateBox kind="empty" text="No audit records." /> : null}
      {items && items.length > 0 ? (
        <Panel title="RECORDS">
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ textAlign: "left", color: "var(--muted)" }}>
                <th>#</th>
                <th>Action</th>
                <th>Actor</th>
                <th>Result</th>
                <th>Hash</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} style={{ borderTop: "1px solid var(--border)" }}>
                  <td>{item.sequence}</td>
                  <td>{item.action}</td>
                  <td style={{ fontFamily: "var(--font-mono)" }}>{item.actor_id}</td>
                  <td>{item.result}</td>
                  <td style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>{item.record_hash.slice(0, 16)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      ) : null}
    </AppShell>
  );
}
