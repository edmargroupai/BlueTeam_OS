"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { AttackHeatmap } from "@/components/charts/AttackHeatmap";
import { Grid, MetricTile } from "@/components/ui/Primitives";
import { ApiError, api } from "@/lib/api";

type Technique = {
  technique_id: string;
  name: string;
  tactic: string;
  detections: string[];
  telemetry_sources: string[];
  finding_count: number;
  validated: boolean;
  coverage_score: number;
  gap_severity: string;
  gaps: string[];
};

type Coverage = {
  tenant_id: string;
  techniques: Technique[];
  summary: { technique_count: number; covered: number; gaps: number; mean_coverage: number };
};

export default function AttackPage() {
  const [data, setData] = useState<Coverage | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Coverage>("/api/v1/attack/coverage")
      .then(setData)
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed to load coverage"));
  }, []);

  return (
    <AppShell
      title="ATT&CK Coverage"
      description="Heatmap and table from registered detections, telemetry, validation, and findings. Gaps are scored — not invented."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!data ? <StateBox kind="loading" text="Computing coverage…" /> : null}
      {data ? (
        <>
          <Grid cols={4}>
            <MetricTile label="Techniques" value={data.summary.technique_count} />
            <MetricTile label="Covered" value={data.summary.covered} />
            <MetricTile label="Gaps" value={data.summary.gaps} />
            <MetricTile label="Mean coverage" value={data.summary.mean_coverage} />
          </Grid>
          <Panel title="COVERAGE HEATMAP">
            <AttackHeatmap techniques={data.techniques} />
          </Panel>
        </>
      ) : null}
    </AppShell>
  );
}
