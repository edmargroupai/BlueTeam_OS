"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

export default function ImprovePage() {
  const [analytics, setAnalytics] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Record<string, unknown>>("/api/v1/improve/analytics")
      .then(setAnalytics)
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed"));
  }, []);

  return (
    <AppShell
      title="Self-Improvement"
      description="Noisy/duplicate rule analytics, ATT&CK and telemetry gaps, and improvement candidates. AI may suggest — it cannot promote."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!analytics ? <StateBox kind="loading" text="Loading analytics…" /> : null}
      {analytics ? (
        <Panel title="ANALYTICS">
          <pre style={{ whiteSpace: "pre-wrap", fontFamily: "var(--font-mono)", fontSize: 12 }}>
            {JSON.stringify(analytics, null, 2)}
          </pre>
        </Panel>
      ) : null}
    </AppShell>
  );
}
