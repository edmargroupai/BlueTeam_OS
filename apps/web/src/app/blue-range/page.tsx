"use client";

import { useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { api } from "@/lib/api";

type RangeItem = {
  scenario_id: string;
  passed: boolean;
  latency_seconds: number;
  errors: string[];
  assertions: { rule_id: string; expected_min: number; observed: number; passed: boolean }[];
};

export default function BlueRangePage() {
  const [items, setItems] = useState<RangeItem[] | null>(null);
  const [error, setError] = useState("");
  const [running, setRunning] = useState(false);

  async function run() {
    setRunning(true);
    setError("");
    try {
      const body = await api<{ items: RangeItem[] }>("/api/v1/blue-range/run", { method: "POST" });
      setItems(body.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Run failed");
    } finally {
      setRunning(false);
    }
  }

  return (
    <AppShell
      title="Blue Range"
      description="Isolated defensive validation. Scenarios replay synthetic telemetry and assert detections. No external targets."
    >
      <button
        type="button"
        onClick={run}
        disabled={running}
        style={{
          background: "var(--accent-dim)",
          color: "var(--text)",
          border: "1px solid var(--border)",
          padding: "8px 14px",
          cursor: "pointer",
          marginBottom: 16,
        }}
      >
        {running ? "Executing scenarios…" : "Run Blue Range"}
      </button>
      {error ? <StateBox kind="error" text={error} /> : null}
      {!items && !running ? <StateBox kind="empty" text="No run yet. Execute the harness to produce evidence." /> : null}
      {items?.map((item) => (
        <Panel key={item.scenario_id} title={item.scenario_id}>
          <div>{item.passed ? "PASS" : "FAIL"} · {item.latency_seconds.toFixed(3)}s</div>
          {item.errors.map((err) => (
            <div key={err} style={{ color: "var(--critical)" }}>
              {err}
            </div>
          ))}
          {item.assertions.map((assertion) => (
            <div key={assertion.rule_id} style={{ fontFamily: "var(--font-mono)", color: "var(--muted)" }}>
              {assertion.rule_id}: {assertion.observed}/{assertion.expected_min} {assertion.passed ? "ok" : "miss"}
            </div>
          ))}
        </Panel>
      ))}
    </AppShell>
  );
}
