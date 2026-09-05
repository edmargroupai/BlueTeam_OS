"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

type Connector = { connector_id: string; name: string; kind: string };
type Health = {
  connector_id: string;
  name: string;
  status: string;
  agents_total: number;
  agents_active: number;
  last_event_at: string | null;
  details: Record<string, unknown>;
};
type Sessions = {
  items: { session_id: string; src: string; dst: string; protocol: string; packets: number; risk: number }[];
  count: number;
  dns: number;
  http: number;
  tls: number;
  ids_alerts: number;
};
type Correlate = { count: number; ip_joins: unknown[]; cross_source: unknown[]; note: string };

export default function ConnectorsPage() {
  const [connectors, setConnectors] = useState<Connector[] | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [sessions, setSessions] = useState<Sessions | null>(null);
  const [correlate, setCorrelate] = useState<Correlate | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      api<{ items: Connector[] }>("/api/v1/connectors"),
      api<Health>("/api/v1/connectors/wazuh/health"),
      api<Sessions>("/api/v1/connectors/network/sessions"),
      api<Correlate>("/api/v1/connectors/network/correlate"),
    ])
      .then(([list, wazuh, net, corr]) => {
        setConnectors(list.items);
        setHealth(wazuh);
        setSessions(net);
        setCorrelate(corr);
      })
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed to load connectors"));
  }, []);

  return (
    <AppShell
      title="Connectors"
      description="Wazuh endpoint adapter and Zeek/Suricata network parsers. High-impact endpoint actions stay denied until the policy engine approves them."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!connectors ? <StateBox kind="loading" text="Loading connectors…" /> : null}
      {connectors ? (
        <Panel title="REGISTERED">
          {connectors.map((item) => (
            <div key={item.connector_id} style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
              {item.connector_id} · {item.name} · {item.kind}
            </div>
          ))}
        </Panel>
      ) : null}
      {health ? (
        <Panel title="WAZUH HEALTH">
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
            status={health.status} agents={health.agents_active}/{health.agents_total} last=
            {health.last_event_at ?? "never"}
          </div>
        </Panel>
      ) : null}
      {sessions ? (
        <Panel title="NETWORK SESSIONS">
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
            sessions={sessions.count} dns={sessions.dns} http={sessions.http} tls={sessions.tls} ids=
            {sessions.ids_alerts}
          </div>
          {sessions.items.slice(0, 8).map((item) => (
            <div key={item.session_id} style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--muted)" }}>
              {item.src} → {item.dst} · {item.protocol} · pkts {item.packets} · risk {item.risk}
            </div>
          ))}
        </Panel>
      ) : null}
      {correlate ? (
        <Panel title="ENDPOINT ↔ NETWORK">
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>joins={correlate.count}</div>
          <div style={{ color: "var(--muted)", fontSize: 13 }}>{correlate.note}</div>
        </Panel>
      ) : null}
    </AppShell>
  );
}
