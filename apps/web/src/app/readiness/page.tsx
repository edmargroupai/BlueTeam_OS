"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

export default function ReadinessPage() {
  const [gate, setGate] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Record<string, unknown>>("/api/v1/readiness/gate")
      .then(setGate)
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed"));
  }, []);

  return (
    <AppShell
      title="Production Readiness Gate"
      description="Evidence checklist for CI, replay, AI failover, DFIR export, and architecture. Necessary but not sufficient for GSE-calibre."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!gate ? <StateBox kind="loading" text="Evaluating gate…" /> : null}
      {gate ? (
        <Panel title={String(gate.gate)}>
          <pre style={{ fontFamily: "var(--font-mono)", fontSize: 12, whiteSpace: "pre-wrap" }}>
            {JSON.stringify(gate, null, 2)}
          </pre>
        </Panel>
      ) : null}
    </AppShell>
  );
}
