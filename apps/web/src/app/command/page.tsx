"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, Severity, StateBox } from "@/components/AppShell";
import { RiskBars, SeverityDonut } from "@/components/charts/SeverityCharts";
import { Grid, MetricTile } from "@/components/ui/Primitives";
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
  telemetry_health?: {
    events: number;
    dead_letter: number;
    dead_letter_ratio: number;
    all_configured_connected: boolean;
  };
  detection_health?: {
    catalogue_rules: number;
    revisions: number;
    by_status: Record<string, number>;
    findings: number;
    open_alerts: number;
  };
  attack_overview?: {
    techniques_observed: number;
    top_techniques: { technique: string; count: number }[];
  };
  automation_queue?: { id: string; title: string; status: string; queue: string; updated_at: string }[];
  top_alerts: { id: string; title: string; severity: string; created_at: string }[];
  top_incidents?: { id: string; title: string; status: string; severity: string; updated_at: string }[];
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
      description="Live Operations from the control plane. Charts encode tenant telemetry only — empty means no data yet."
    >
      {loading ? <StateBox kind="loading" text="Loading tenant posture…" /> : null}
      {error ? <StateBox kind="error" text={error} /> : null}
      {data ? (
        <>
          <Grid cols={4}>
            <MetricTile label="Open alerts" value={data.open_alerts} />
            <MetricTile label="Findings" value={data.findings} />
            <MetricTile label="Events stored" value={data.events} />
            <MetricTile label="Dead letter" value={data.dead_letter} />
            <MetricTile label="Incidents" value={data.incidents ?? 0} />
            <MetricTile label="Catalogue rules" value={data.detections} />
            <MetricTile label="Quality index" value={data.quality.total} />
            <MetricTile label="Quality band" value={data.quality.band} />
          </Grid>

          <Grid cols={2}>
            <Panel title="SEVERITY DISTRIBUTION">
              <SeverityDonut severity={data.severity} />
            </Panel>
            <Panel title="TOP-RISK ENTITIES">
              <RiskBars
                items={(data.top_risk_entities ?? []).slice(0, 8).map((entity) => ({
                  name: entity.display_name,
                  value: entity.risk_score,
                }))}
              />
            </Panel>
          </Grid>

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

          <Grid cols={2}>
            <Panel title="TELEMETRY HEALTH">
              {!data.telemetry_health ? (
                <StateBox kind="empty" text="Telemetry health not reported by API." />
              ) : (
                <div className="mono">
                  <div>events={data.telemetry_health.events}</div>
                  <div>dead_letter={data.telemetry_health.dead_letter}</div>
                  <div>dlq_ratio={data.telemetry_health.dead_letter_ratio.toFixed(4)}</div>
                  <div>
                    configured_plane=
                    {data.telemetry_health.all_configured_connected ? "connected" : "degraded"}
                  </div>
                </div>
              )}
            </Panel>
            <Panel title="DETECTION HEALTH">
              {!data.detection_health ? (
                <StateBox kind="empty" text="Detection health not reported by API." />
              ) : (
                <div className="mono">
                  <div>catalogue={data.detection_health.catalogue_rules}</div>
                  <div>revisions={data.detection_health.revisions}</div>
                  <div>findings={data.detection_health.findings}</div>
                  <div>open_alerts={data.detection_health.open_alerts}</div>
                </div>
              )}
            </Panel>
          </Grid>

          <Panel title="ATT&CK OVERVIEW">
            {!data.attack_overview || data.attack_overview.techniques_observed === 0 ? (
              <StateBox kind="empty" text="No ATT&CK techniques observed on findings or incidents yet." />
            ) : (
              <table className="btos-table">
                <thead>
                  <tr>
                    <th>Technique</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {data.attack_overview.top_techniques.map((row) => (
                    <tr key={row.technique}>
                      <td className="mono">{row.technique}</td>
                      <td>{row.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>

          <Panel title="TOP INCIDENTS">
            {!data.top_incidents || data.top_incidents.length === 0 ? (
              <StateBox kind="empty" text="No open incidents." />
            ) : (
              <table className="btos-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Title</th>
                    <th>Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_incidents.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <Severity value={item.severity} />
                      </td>
                      <td>{item.status}</td>
                      <td>{item.title}</td>
                      <td className="mono">{item.updated_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>

          <Panel title="TOP ALERTS">
            {data.top_alerts.length === 0 ? (
              <StateBox kind="empty" text="No alerts." />
            ) : (
              <table className="btos-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_alerts.map((alert) => (
                    <tr key={alert.id}>
                      <td>
                        <Severity value={alert.severity} />
                      </td>
                      <td>{alert.title}</td>
                      <td className="mono">{alert.created_at}</td>
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
