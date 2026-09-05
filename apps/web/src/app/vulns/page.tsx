"use client";

import { FormEvent, useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

type Vuln = {
  id: string;
  cve_id: string;
  title: string;
  cvss: number;
  priority: number;
  band: string;
  sla_days: number;
  asset_id: string;
  status: string;
  formula: string;
};

export default function VulnsPage() {
  const [items, setItems] = useState<Vuln[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const body = await api<{ items: Vuln[] }>("/api/v1/vulns");
    setItems(body.items);
  }

  useEffect(() => {
    refresh().catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed to load vulns"));
  }, []);

  async function onImport(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("/api/v1/vulns/import", {
        method: "POST",
        body: JSON.stringify({
          findings: [
            {
              cve_id: "CVE-2024-0001",
              title: "Lab critical RCE",
              cvss: 9.8,
              exploitability: 85,
              asset_id: "dc-01",
              asset_criticality: 95,
              threat_activity: 60,
              scanner: "lab-import",
            },
          ],
        }),
      });
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Import failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell
      title="Vulnerability Exposure"
      description="Scanner import with deterministic remediation priority from CVSS, exploitability, asset criticality, and threat activity."
    >
      <Panel title="IMPORT SAMPLE">
        <form onSubmit={onImport}>
          <button type="submit" disabled={busy} style={{ padding: "8px 12px" }}>
            Import lab finding
          </button>
        </form>
      </Panel>
      {error ? <StateBox kind="error" text={error} /> : null}
      {!items ? <StateBox kind="loading" text="Loading vulnerabilities…" /> : null}
      {items && items.length === 0 ? <StateBox kind="empty" text="No vulnerabilities imported." /> : null}
      {items?.map((item) => (
        <Panel key={item.id} title={`${item.cve_id} · ${item.title}`}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
            priority={item.priority} band={item.band} sla={item.sla_days}d cvss={item.cvss} asset={item.asset_id}
          </div>
          <div style={{ color: "var(--muted)", fontSize: 12 }}>{item.formula}</div>
        </Panel>
      ))}
    </AppShell>
  );
}
