"use client";

import { FormEvent, useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

type HuntResult = {
  dry_run?: boolean;
  explain?: { form: string; sql_concatenation: boolean; cost: string };
  matches?: string[];
  count?: number;
  items?: Record<string, unknown>[];
};

type SavedHunt = { id: string; name: string; hunt_type: string; query: Record<string, unknown> };

export default function HuntPage() {
  const [query, setQuery] = useState('process.name = "powershell.exe" AND parent.name IN ("winword.exe", "excel.exe")');
  const [srcIp, setSrcIp] = useState("");
  const [ioc, setIoc] = useState("");
  const [result, setResult] = useState<HuntResult | null>(null);
  const [saved, setSaved] = useState<SavedHunt[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api<{ items: SavedHunt[] }>("/api/v1/hunts/saved")
      .then((body) => setSaved(body.items))
      .catch(() => undefined);
  }, []);

  async function runBlueql(event: FormEvent, dryRun: boolean) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      setResult(
        await api<HuntResult>("/api/v1/hunts/blueql", {
          method: "POST",
          body: JSON.stringify({ query, dry_run: dryRun }),
        }),
      );
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Hunt failed");
    } finally {
      setLoading(false);
    }
  }

  async function runStructured(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      setResult(
        await api<HuntResult>("/api/v1/hunts/structured", {
          method: "POST",
          body: JSON.stringify({ src_ip: srcIp || undefined, ioc: ioc || undefined, limit: 100 }),
        }),
      );
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Structured hunt failed");
    } finally {
      setLoading(false);
    }
  }

  async function lookupIoc() {
    if (!ioc.trim()) return;
    setLoading(true);
    setError("");
    try {
      setResult(await api<HuntResult>(`/api/v1/hunts/ioc?value=${encodeURIComponent(ioc)}`));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "IOC lookup failed");
    } finally {
      setLoading(false);
    }
  }

  async function saveCurrent() {
    setLoading(true);
    try {
      await api("/api/v1/hunts/saved", {
        method: "POST",
        body: JSON.stringify({
          name: `Structured ${srcIp || ioc || "filter"}`,
          hunt_type: "structured",
          query: { src_ip: srcIp || undefined, ioc: ioc || undefined },
        }),
      });
      const body = await api<{ items: SavedHunt[] }>("/api/v1/hunts/saved");
      setSaved(body.items);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Save failed");
    } finally {
      setLoading(false);
    }
  }

  async function exportJson() {
    if (!result?.items?.length) return;
    setLoading(true);
    try {
      const exported = await api<{ count: number; format: string }>("/api/v1/hunts/export", {
        method: "POST",
        body: JSON.stringify({ format: "json", items: result.items }),
      });
      setError("");
      setResult({ ...result, count: exported.count });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Export failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AppShell
      title="Threat Hunting"
      description="BlueQL, structured filters, IOC/entity lookup, and exports. Every execute path is audited. UI never runs SQL or shell."
    >
      <Panel title="BLUEQL">
        <form>
          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            rows={5}
            style={{
              width: "100%",
              background: "var(--bg)",
              color: "var(--text)",
              border: "1px solid var(--border)",
              fontFamily: "var(--font-mono)",
              padding: 8,
            }}
          />
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            <button type="button" onClick={(e) => runBlueql(e, true)} disabled={loading} style={btn()}>
              Validate
            </button>
            <button type="button" onClick={(e) => runBlueql(e, false)} disabled={loading} style={btn()}>
              Execute
            </button>
          </div>
        </form>
      </Panel>

      <Panel title="STRUCTURED SEARCH">
        <form onSubmit={runStructured} style={{ display: "grid", gap: 8 }}>
          <input placeholder="src_ip" value={srcIp} onChange={(e) => setSrcIp(e.target.value)} style={input()} />
          <input placeholder="ioc / indicator" value={ioc} onChange={(e) => setIoc(e.target.value)} style={input()} />
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button type="submit" disabled={loading} style={btn()}>
              Search telemetry
            </button>
            <button type="button" disabled={loading} onClick={lookupIoc} style={btn()}>
              IOC lookup
            </button>
            <button type="button" disabled={loading} onClick={saveCurrent} style={btn()}>
              Save hunt
            </button>
            <button type="button" disabled={loading || !result?.items?.length} onClick={exportJson} style={btn()}>
              Export JSON
            </button>
          </div>
        </form>
      </Panel>

      <Panel title="SAVED HUNTS">
        {saved.length === 0 ? (
          <StateBox kind="empty" text="No saved hunts for this tenant." />
        ) : (
          saved.map((item) => (
            <div key={item.id} style={{ borderTop: "1px solid var(--border)", padding: "8px 0" }}>
              <strong>{item.name}</strong> · {item.hunt_type}
              <div style={{ fontFamily: "var(--font-mono)", color: "var(--muted)", fontSize: 12 }}>
                {JSON.stringify(item.query)}
              </div>
            </div>
          ))
        )}
      </Panel>

      {error ? <StateBox kind="error" text={error} /> : null}
      {result ? (
        <Panel title="RESULT">
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
            count={result.count ?? result.matches?.length ?? result.items?.length ?? 0}
            {result.dry_run !== undefined ? ` dry_run=${String(result.dry_run)}` : ""}
          </div>
          {result.explain ? (
            <div style={{ color: "var(--muted)", fontFamily: "var(--font-mono)" }}>
              form={result.explain.form} cost={result.explain.cost}
            </div>
          ) : null}
          {result.items?.slice(0, 20).map((item) => (
            <div key={String(item.id)} style={{ borderTop: "1px solid var(--border)", padding: "6px 0", fontSize: 13 }}>
              {String(item.timestamp ?? "")} · {String(item.event_type ?? item.source ?? "")} ·{" "}
              {String(item.src_ip ?? item.user ?? "")}
            </div>
          ))}
        </Panel>
      ) : (
        <StateBox kind="empty" text="No hunt executed yet." />
      )}
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
