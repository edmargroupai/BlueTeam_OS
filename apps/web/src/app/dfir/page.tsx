"use client";

import { useEffect, useState } from "react";
import { AppShell, Panel, StateBox } from "@/components/AppShell";
import { ApiError, api } from "@/lib/api";

export default function DfirPage() {
  const [host, setHost] = useState<{ items: unknown[] } | null>(null);
  const [files, setFiles] = useState<{ items: unknown[] } | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      api<{ items: unknown[] }>("/api/v1/dfir/timeline/host"),
      api<{ items: unknown[] }>("/api/v1/dfir/artefacts/files"),
    ])
      .then(([a, b]) => {
        setHost(a);
        setFiles(b);
      })
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed"));
  }, []);

  return (
    <AppShell
      title="DFIR Workbench"
      description="Host/network timelines, file artefacts, and evidence export. Browser/memory collectors remain adapter contracts only."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      <Panel title="HOST TIMELINE">{host ? `${host.items.length} events` : "loading…"}</Panel>
      <Panel title="FILE ARTEFACTS">{files ? `${files.items.length} artefacts` : "loading…"}</Panel>
    </AppShell>
  );
}
