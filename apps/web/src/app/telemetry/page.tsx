"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

type Health = {
  status: string;
  warnings: { kind: string; source?: string; reason?: string; count?: number }[];
  counts: Record<string, unknown>;
  note: string;
};

export default function TelemetryPage() {
  const [data, setData] = useState<Health | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Health>("/api/v1/telemetry/health")
      .then(setData)
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed to load health"));
  }, []);

  return (
    <AppShell
      title="Telemetry Health"
      description="Silent sensors, parser failures, lag, volume anomalies, schema drift, and missing expected sources — warnings only from observed state."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!data ? <StateBox kind="loading" text="Evaluating telemetry…" /> : null}
      {data ? (
        <Panel title={`STATUS · ${data.status}`}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>{JSON.stringify(data.counts)}</div>
          <div style={{ color: "var(--muted)", marginTop: 8 }}>{data.note}</div>
        </Panel>
      ) : null}
      {data?.warnings.map((warning, idx) => (
        <Panel key={`${warning.kind}-${idx}`} title={warning.kind}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{JSON.stringify(warning)}</div>
        </Panel>
      ))}
    </AppShell>
  );
}
