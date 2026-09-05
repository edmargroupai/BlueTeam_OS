"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { PlaybookFlow } from "@/components/charts/PlaybookFlow";
import { ApiError, api } from "@/lib/api";

type Playbook = {
  playbook_id: string;
  name: string;
  description: string;
  steps: { id: string; action_type: string; tier: number; depends_on: string[]; rollback_action?: string | null }[];
};

type Run = {
  run_id: string;
  playbook_id: string;
  status: string;
  dry_run: boolean;
  approval_required: string[];
  steps: { step_id: string; action_type: string; status: string; rollback_hook?: string | null }[];
};

export default function PlaybooksPage() {
  const [items, setItems] = useState<Playbook[] | null>(null);
  const [lastRun, setLastRun] = useState<Run | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ items: Playbook[] }>("/api/v1/playbooks")
      .then((body) => setItems(body.items))
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed to load playbooks"));
  }, []);

  async function run(playbookId: string, dryRun: boolean) {
    setBusy(true);
    setError("");
    try {
      const runBody = await api<Run>("/api/v1/playbooks/run", {
        method: "POST",
        body: JSON.stringify({ playbook_id: playbookId, dry_run: dryRun }),
      });
      setLastRun(runBody);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Run failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell
      title="Playbooks"
      description="Python playbook DAG with retries, idempotency, action tiers, approval gates, execution logs, and rollback hooks."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!items ? <StateBox kind="loading" text="Loading playbooks…" /> : null}
      {items?.map((item) => (
        <Panel key={item.playbook_id} title={item.name}>
          <p style={{ color: "var(--muted)" }}>{item.description}</p>
          <PlaybookFlow steps={item.steps} />
          <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
            <button type="button" disabled={busy} onClick={() => run(item.playbook_id, true)}>
              Dry-run
            </button>
            <button type="button" disabled={busy} onClick={() => run(item.playbook_id, false)}>
              Live (policy gated)
            </button>
          </div>
        </Panel>
      ))}
      {lastRun ? (
        <Panel title={`LAST RUN · ${lastRun.status}`}>
          <div className="mono">
            {lastRun.run_id} · {lastRun.playbook_id} · dry_run={String(lastRun.dry_run)}
          </div>
          {lastRun.steps.map((step) => (
            <div key={step.step_id} className="mono">
              {step.step_id} → {step.status}
              {step.rollback_hook ? ` · rollback {${step.rollback_hook}}` : ""}
            </div>
          ))}
        </Panel>
      ) : null}
    </AppShell>
  );
}
