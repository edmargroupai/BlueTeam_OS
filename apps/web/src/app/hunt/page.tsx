"use client";

import { FormEvent, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { api } from "@/lib/api";

type HuntResult = {
  dry_run: boolean;
  explain?: { form: string; sql_concatenation: boolean; cost: string };
  matches?: string[];
  count?: number;
};

export default function HuntPage() {
  const [query, setQuery] = useState('process.name = "powershell.exe" AND parent.name IN ("winword.exe", "excel.exe")');
  const [result, setResult] = useState<HuntResult | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function run(event: FormEvent, dryRun: boolean) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      setResult(await api<HuntResult>("/api/v1/hunts/blueql", { method: "POST", body: JSON.stringify({ query, dry_run: dryRun }) }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Hunt failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AppShell
      title="Threat Hunting"
      description="BlueQL compiles to an AST in Python. The UI never executes SQL or OS commands. Injection tokens are rejected by the parser."
    >
      <Panel title="BLUEQL">
        <form>
          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            rows={6}
            style={{
              width: "100%",
              background: "var(--bg)",
              color: "var(--text)",
              border: "1px solid var(--border)",
              fontFamily: "var(--font-mono)",
              padding: 8,
            }}
          />
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            <button type="button" onClick={(e) => run(e, true)} disabled={loading} style={btn()}>
              Validate / explain
            </button>
            <button type="button" onClick={(e) => run(e, false)} disabled={loading} style={btn()}>
              Execute against tenant events
            </button>
          </div>
        </form>
      </Panel>
      {error ? <StateBox kind="error" text={error} /> : null}
      {result ? (
        <Panel title="RESULT">
          <div>dry_run: {String(result.dry_run)}</div>
          {result.explain ? (
            <div style={{ color: "var(--muted)", fontFamily: "var(--font-mono)" }}>
              form={result.explain.form} cost={result.explain.cost} sql_concat={String(result.explain.sql_concatenation)}
            </div>
          ) : null}
          <div>matches: {result.count ?? result.matches?.length ?? 0}</div>
        </Panel>
      ) : (
        <StateBox kind="empty" text="No hunt executed. Validate first. Empty tenant event stores return zero matches." />
      )}
    </AppShell>
  );
}

function btn() {
  return {
    background: "var(--accent-dim)",
    color: "var(--text)",
    border: "1px solid var(--border)",
    padding: "8px 12px",
    cursor: "pointer",
  } as const;
}
