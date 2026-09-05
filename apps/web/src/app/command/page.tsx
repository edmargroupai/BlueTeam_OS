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
      description="Live Operations from the control plane. Empty panels mean no tenant telemetry yet — not placeholders."
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
            <Metric label="Incidents" value={data.incidents ?? 0} />
            <Metric label="Catalogue rules" value={data.detections} />
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
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Panel title="TELEMETRY HEALTH">
              {!data.telemetry_health ? (
                <StateBox kind="empty" text="Telemetry health not reported by API." />
              ) : (
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
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
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
                  <div>catalogue={data.detection_health.catalogue_rules}</div>
                  <div>revisions={data.detection_health.revisions}</div>
                  <div>findings={data.detection_health.findings}</div>
                  <div>open_alerts={data.detection_health.open_alerts}</div>
                  <div>
                    statuses=
                    {Object.entries(data.detection_health.by_status)
                      .map(([k, v]) => `${k}:${v}`)
                      .join(" ") || "none"}
                  </div>
                </div>
              )}
            </Panel>
          </div>
          <Panel title="ATT&CK OVERVIEW">
            {!data.attack_overview || data.attack_overview.techniques_observed === 0 ? (
              <StateBox kind="empty" text="No ATT&CK techniques observed on findings or incidents yet." />
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ color: "var(--muted)", textAlign: "left" }}>
                    <th>Technique</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {data.attack_overview.top_techniques.map((row) => (
                    <tr key={row.technique} style={{ borderTop: "1px solid var(--border)" }}>
                      <td style={{ fontFamily: "var(--font-mono)" }}>{row.technique}</td>
                      <td>{row.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
          <Panel title="AUTOMATION QUEUE">
            {!data.automation_queue || data.automation_queue.length === 0 ? (
              <StateBox kind="empty" text="No open IR work items in the response queue." />
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ color: "var(--muted)", textAlign: "left" }}>
                    <th>Queue</th>
                    <th>Status</th>
                    <th>Title</th>
                  </tr>
                </thead>
                <tbody>
                  {data.automation_queue.map((item) => (
                    <tr key={item.id} style={{ borderTop: "1px solid var(--border)" }}>
                      <td>{item.queue}</td>
                      <td>{item.status}</td>
                      <td>{item.title}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
          <Panel title="TOP INCIDENTS">
            {!data.top_incidents || data.top_incidents.length === 0 ? (
              <StateBox kind="empty" text="No open incidents. Convert an alert or rebuild correlation groups." />
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ color: "var(--muted)", textAlign: "left" }}>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Title</th>
                    <th>Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_incidents.map((item) => (
                    <tr key={item.id} style={{ borderTop: "1px solid var(--border)" }}>
                      <td>
                        <Severity value={item.severity} />
                      </td>
                      <td>{item.status}</td>
                      <td>{item.title}</td>
                      <td style={{ fontFamily: "var(--font-mono)" }}>{item.updated_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
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
