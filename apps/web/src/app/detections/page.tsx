"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { api } from "@/lib/api";

type Rule = {
  rule_id: string;
  name: string;
  version: string;
  severity: string;
  mitre_techniques: string[];
  status: string;
  execution?: string;
  description: string;
};

type HistoryItem = {
  id: string;
  version: string;
  status: string;
  created_at: string;
  created_by: string;
};

export default function DetectionsPage() {
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api<{ items: Rule[] }>("/api/v1/detections")
      .then((body) => {
        setRules(body.items);
        const first = body.items[0];
        if (first) {
          setSelected(first.rule_id);
          return api<{ items: HistoryItem[] }>(`/api/v1/detections/rules/${first.rule_id}/history`);
        }
        return { items: [] };
      })
      .then((body) => setHistory(body.items ?? []))
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <AppShell
      title="Detection Engineering"
      description="Versioned Python detections. A row here is a rule object with tests, not a dashboard widget."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!rules ? <StateBox kind="loading" text="Loading catalogue…" /> : null}
      {rules && rules.length === 0 ? <StateBox kind="empty" text="No detections registered." /> : null}
      {rules?.map((rule) => (
        <Panel key={rule.rule_id} title={`${rule.rule_id} · v${rule.version}`}>
          <div style={{ fontSize: 16 }}>{rule.name}</div>
          <p style={{ color: "var(--muted)" }}>{rule.description}</p>
          <div style={{ fontFamily: "var(--font-mono)", color: "var(--muted)" }}>
            {rule.severity} · {rule.status} · {rule.execution ?? "realtime"} ·{" "}
            {rule.mitre_techniques.join(", ") || "no ATT&CK map"}
          </div>
        </Panel>
      ))}
      {selected && history.length > 0 ? (
        <Panel title={`VERSION HISTORY · ${selected}`}>
          {history.map((item) => (
            <div key={item.id} style={{ fontFamily: "var(--font-mono)", color: "var(--muted)" }}>
              {item.version} · {item.status} · {item.created_by} · {item.created_at}
            </div>
          ))}
        </Panel>
      ) : null}
    </AppShell>
  );
}
