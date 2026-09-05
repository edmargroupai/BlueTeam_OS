"use client";

import { FormEvent, useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

type Ioc = {
  id: string;
  indicator_type: string;
  value: string;
  source: string;
  confidence: number;
  expires_at: string;
  expired: boolean;
  active: boolean;
  sightings: number;
  malware?: string | null;
  actor?: string | null;
  campaign?: string | null;
  provenance: Record<string, unknown>;
};

export default function IntelPage() {
  const [items, setItems] = useState<Ioc[] | null>(null);
  const [error, setError] = useState("");
  const [value, setValue] = useState("198.51.100.10");
  const [source, setSource] = useState("manual-lab");
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const body = await api<{ items: Ioc[] }>("/api/v1/intel/iocs?include_expired=true");
    setItems(body.items);
  }

  useEffect(() => {
    refresh().catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed to load IOCs"));
  }, []);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("/api/v1/intel/iocs", {
        method: "POST",
        body: JSON.stringify({
          indicator_type: "ip",
          value,
          source,
          confidence: 0.9,
          ttl_hours: 72,
          mitre_techniques: ["T1071"],
          provenance: { entered_via: "command_center" },
        }),
      });
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Create failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell
      title="Threat Intelligence"
      description="IOC store with source, confidence, TTL, dedup, sightings, and provenance. Expired indicators deactivate and stop enriching ingest."
    >
      <Panel title="ADD IOC">
        <form onSubmit={onSubmit} style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="indicator value" style={input()} />
          <input value={source} onChange={(e) => setSource(e.target.value)} placeholder="source" style={input()} />
          <button type="submit" disabled={busy} style={btn()}>
            Upsert
          </button>
        </form>
      </Panel>
      {error ? <StateBox kind="error" text={error} /> : null}
      {!items ? <StateBox kind="loading" text="Loading indicators…" /> : null}
      {items && items.length === 0 ? <StateBox kind="empty" text="No IOCs for this tenant." /> : null}
      {items?.map((item) => (
        <Panel key={item.id} title={`${item.indicator_type} · ${item.value}`}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
            source={item.source} confidence={item.confidence} sightings={item.sightings} active={String(item.active)}{" "}
            expired={String(item.expired)}
          </div>
          <div style={{ color: "var(--muted)" }}>
            expires {item.expires_at}
            {item.actor ? ` · actor ${item.actor}` : ""}
            {item.malware ? ` · malware ${item.malware}` : ""}
            {item.campaign ? ` · campaign ${item.campaign}` : ""}
          </div>
        </Panel>
      ))}
    </AppShell>
  );
}

function btn() {
  return {
    background: "var(--accent-dim)",
    color: "var(--text)",
    border: "1px solid var(--border)",
    padding: "8px 12px",
    cursor: "pointer",
  } as const;
}

function input() {
  return {
    background: "var(--bg)",
    color: "var(--text)",
    border: "1px solid var(--border)",
    padding: 8,
    fontFamily: "var(--font-mono)",
  } as const;
}
