"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { api } from "@/lib/api";

type Quality = {
  total: number;
  band: string;
  model_version: string;
  domains: Record<string, number>;
  checks: { check_id: string; title: string; awarded_points: number; max_points: number; reason: string; evidence_ids: string[] }[];
};

export default function QualityPage() {
  const [data, setData] = useState<Quality | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Quality>("/api/v1/quality/index")
      .then(setData)
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <AppShell
      title="Quality Index"
      description="1,000-point defensive quality model. Missing evidence reduces the score. The UI cannot edit these numbers."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!data ? <StateBox kind="loading" text="Calculating from stored evidence…" /> : null}
      {data ? (
        <>
          <Panel title="TOTAL">
            <div style={{ fontSize: 40, fontFamily: "var(--font-mono)" }}>{data.total} / 1000</div>
            <div>
              {data.band} · {data.model_version}
            </div>
          </Panel>
          <Panel title="DOMAINS">
            {Object.entries(data.domains).map(([domain, score]) => (
              <div key={domain} style={{ display: "flex", justifyContent: "space-between", borderTop: "1px solid var(--border)", padding: "6px 0" }}>
                <span>{domain.replaceAll("_", " ")}</span>
                <span style={{ fontFamily: "var(--font-mono)" }}>{score}</span>
              </div>
            ))}
          </Panel>
          <Panel title="CHECKS">
            {data.checks.map((check) => (
              <div key={check.check_id} style={{ marginBottom: 12 }}>
                <div>
                  {check.title} · {check.awarded_points}/{check.max_points}
                </div>
                <div style={{ color: "var(--muted)" }}>{check.reason}</div>
              </div>
            ))}
          </Panel>
        </>
      ) : null}
    </AppShell>
  );
}
