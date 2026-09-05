"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, Severity, StateBox } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

type Overview = {
  tenant_id: string;
  open_alerts: number;
  findings: number;
  events: number;
  dead_letter: number;
  incidents?: number;
  detections: number;
  severity: Record<string, number>;
  quality: { total: number; band: string; model_version: string };
  ai_required: boolean;
  top_alerts: { id: string; title: string; severity: string; created_at: string }[];
  top_risk_entities?: { id: string; entity_type: string; display_name: string; risk_score: number }[];
};

export default function CommandPage() {
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api<Overview>("/api/v1/command/overview")
      .then(setData)
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed to load overview"))
      .finally(() => setLoading(false));
  }, []);

  return (
    <AppShell
      title="Security Command Center"
      description="Live control-plane posture from the API. Empty counters mean no tenant telemetry yet — they are not placeholders."
    >
      {loading ? <StateBox kind="loading" text="Loading tenant posture…" /> : null}
      {error ? <StateBox kind="error" text={error} /> : null}
      {data ? (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 12 }}>
            <Metric label="Open alerts" value={data.open_alerts} />
            <Metric label="Findings" value={data.findings} />
            <Metric label="Events stored" value={data.events} />
            <Metric label="Dead letter" value={data.dead_letter} />
            <Metric label="Grouped incidents" value={data.incidents ?? 0} />
          </div>
          <Panel title="QUALITY INDEX">
            <div style={{ display: "flex", gap: 24, alignItems: "baseline" }}>
              <div style={{ fontSize: 36, fontFamily: "var(--font-mono)" }}>{data.quality.total}</div>
              <div>
                <div>Band: {data.quality.band}</div>
                <div style={{ color: "var(--muted)" }}>
                  Model {data.quality.model_version}. Score is evidence-backed and not editable.
                </div>
                <div style={{ color: "var(--muted)" }}>
                  AI required for operations: {data.ai_required ? "yes" : "no"}
                </div>
              </div>
            </div>
          </Panel>
          <Panel title="TOP-RISK ENTITIES">
            {!data.top_risk_entities || data.top_risk_entities.length === 0 ? (
              <StateBox kind="empty" text="No scored entities. Ingest detections so risk can be computed from findings." />
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ color: "var(--muted)", textAlign: "left" }}>
                    <th>Type</th>
                    <th>Entity</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_risk_entities.map((entity) => (
                    <tr key={entity.id} style={{ borderTop: "1px solid var(--border)" }}>
                      <td>{entity.entity_type}</td>
                      <td>{entity.display_name}</td>
                      <td style={{ fontFamily: "var(--font-mono)" }}>{entity.risk_score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
          <Panel title="TOP ALERTS">
            {data.top_alerts.length === 0 ? (
              <StateBox kind="empty" text="No alerts. Ingest Blue Range or live telemetry to populate this panel." />
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ color: "var(--muted)", textAlign: "left" }}>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_alerts.map((alert) => (
                    <tr key={alert.id} style={{ borderTop: "1px solid var(--border)" }}>
                      <td>
                        <Severity value={alert.severity} />
                      </td>
                      <td>{alert.title}</td>
                      <td style={{ fontFamily: "var(--font-mono)" }}>{alert.created_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </>
      ) : null}
    </AppShell>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <Panel>
      <div style={{ color: "var(--muted)", fontSize: 12 }}>{label}</div>
      <div style={{ fontSize: 28, fontFamily: "var(--font-mono)" }}>{value}</div>
    </Panel>
  );
}
