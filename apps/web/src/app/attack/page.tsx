"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, Severity, StateBox } from "@/components/AppShell";
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
      description="Technique coverage from registered detections, observed telemetry, validation state, and findings. Gaps are scored — not invented."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!data ? <StateBox kind="loading" text="Computing coverage…" /> : null}
      {data ? (
        <Panel title="SUMMARY">
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
            techniques={data.summary.technique_count} covered={data.summary.covered} gaps={data.summary.gaps}{" "}
            mean={data.summary.mean_coverage}
          </div>
        </Panel>
      ) : null}
      {data?.techniques.map((tech) => (
        <Panel key={tech.technique_id} title={`${tech.technique_id} · ${tech.name}`}>
          <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 8 }}>
            <Severity value={tech.gap_severity} />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
              score {tech.coverage_score} · validated {String(tech.validated)} · findings {tech.finding_count}
            </span>
          </div>
          <div style={{ color: "var(--muted)", fontSize: 13 }}>{tech.tactic}</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, marginTop: 6 }}>
            detections: {tech.detections.join(", ") || "none"}
          </div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
            telemetry: {tech.telemetry_sources.join(", ") || "none"}
          </div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--muted)" }}>
            gaps: {tech.gaps.join(", ") || "none"}
          </div>
        </Panel>
      ))}
    </AppShell>
  );
}
