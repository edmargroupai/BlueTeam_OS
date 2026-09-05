"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { api } from "@/lib/api";

type Catalogue = {
  python_orchestrates: boolean;
  ai_executes_os_commands: boolean;
  generic_shell: boolean;
  actions: { action_type: string; language: string; tier: number; read_only: boolean; description: string }[];
  sql_hunts: { id: string; name: string }[];
  runtimes?: { yara: string; rego: string; clickhouse_configured: boolean; redpanda_configured: boolean };
};

export default function LanguagesPage() {
  const [data, setData] = useState<Catalogue | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Catalogue>("/api/v1/languages")
      .then(setData)
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <AppShell
      title="Polyglot Security Layer"
      description="Languages are isolated. Python reasons. TypeScript only presents. AI cannot execute OS commands."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!data ? <StateBox kind="loading" text="Loading catalogue…" /> : null}
      {data ? (
        <>
          <Panel title="BOUNDARIES">
            <div>Python orchestrates: {String(data.python_orchestrates)}</div>
            <div>Generic shell: {String(data.generic_shell)}</div>
            <div>AI executes OS commands: {String(data.ai_executes_os_commands)}</div>
            {data.runtimes ? (
              <div style={{ marginTop: 8, color: "var(--muted)" }}>
                YARA engine: {data.runtimes.yara} · Rego engine: {data.runtimes.rego} · ClickHouse configured:{" "}
                {String(data.runtimes.clickhouse_configured)} · Redpanda configured:{" "}
                {String(data.runtimes.redpanda_configured)}
              </div>
            ) : null}
          </Panel>
          <Panel title="REGISTERED ACTIONS">
            {data.actions.map((action) => (
              <div key={action.action_type} style={{ borderTop: "1px solid var(--border)", padding: "6px 0" }}>
                <strong>{action.action_type}</strong> · {action.language} · T{action.tier} · {action.read_only ? "read-only" : "state-changing"}
                <div style={{ color: "var(--muted)" }}>{action.description}</div>
              </div>
            ))}
          </Panel>
        </>
      ) : null}
    </AppShell>
  );
}
