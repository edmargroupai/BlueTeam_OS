"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { AppShell, Panel, Severity, StateBox } from "@/components/AppShell";
import { ApiError, api, getSession } from "@/lib/api";

type Incident = {
  id: string;
  title: string;
  status: string;
  severity: string;
  assignee_email?: string | null;
  storyline_ids: string[];
  event_ids: string[];
  evidence_ids: string[];
  mitre_techniques: string[];
  notes: { id: string; at: string; author_id: string; body: string }[];
  tasks: { id: string; title: string; status: string }[];
  timeline: { id: string; at: string; kind: string; summary: string }[];
  root_cause?: string | null;
  lessons_learned?: string | null;
  created_at: string;
  updated_at: string;
};

type AlertRow = { id: string; title: string; severity: string; status: string };

export default function IncidentsPage() {
  const [items, setItems] = useState<Incident[] | null>(null);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [taskTitle, setTaskTitle] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const body = await api<{ items: Incident[] }>("/api/v1/incidents");
    setItems(body.items);
    if (selected) {
      const next = body.items.find((item) => item.id === selected.id) ?? null;
      setSelected(next);
    }
  }, [selected]);

  useEffect(() => {
    Promise.all([
      api<{ items: Incident[] }>("/api/v1/incidents"),
      api<{ items: AlertRow[] }>("/api/v1/alerts").catch(() => ({ items: [] as AlertRow[] })),
    ])
      .then(([inc, al]) => {
        setItems(inc.items);
        setAlerts(al.items.filter((a) => a.status === "open").slice(0, 12));
      })
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Failed to load incidents"));
  }, []);

  async function convertAlert(alertId: string) {
    setBusy(true);
    setError("");
    try {
      const created = await api<Incident>("/api/v1/incidents/from-alert", {
        method: "POST",
        body: JSON.stringify({ alert_id: alertId }),
      });
      setSelected(created);
      await refresh();
      setAlerts((prev) => prev.filter((a) => a.id !== alertId));
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Convert failed");
    } finally {
      setBusy(false);
    }
  }

  async function setStatus(status: string) {
    if (!selected) return;
    setBusy(true);
    try {
      const updated = await api<Incident>(`/api/v1/incidents/${selected.id}/status`, {
        method: "POST",
        body: JSON.stringify({ status }),
      });
      setSelected(updated);
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Status update failed");
    } finally {
      setBusy(false);
    }
  }

  async function assignSelf(e: FormEvent) {
    e.preventDefault();
    if (!selected) return;
    const session = getSession();
    if (!session) return;
    setBusy(true);
    try {
      const me = await api<{ id: string; email: string }>("/api/v1/auth/me").catch(() => null);
      const updated = await api<Incident>(`/api/v1/incidents/${selected.id}/assign`, {
        method: "POST",
        body: JSON.stringify({
          assignee_user_id: me?.id ?? "self",
          assignee_email: me?.email ?? "analyst@demo.blueteam.local",
        }),
      });
      setSelected(updated);
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Assign failed");
    } finally {
      setBusy(false);
    }
  }

  async function submitNote(e: FormEvent) {
    e.preventDefault();
    if (!selected || !note.trim()) return;
    setBusy(true);
    try {
      const updated = await api<Incident>(`/api/v1/incidents/${selected.id}/notes`, {
        method: "POST",
        body: JSON.stringify({ body: note }),
      });
      setSelected(updated);
      setNote("");
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Note failed");
    } finally {
      setBusy(false);
    }
  }

  async function submitTask(e: FormEvent) {
    e.preventDefault();
    if (!selected || !taskTitle.trim()) return;
    setBusy(true);
    try {
      const updated = await api<Incident>(`/api/v1/incidents/${selected.id}/tasks`, {
        method: "POST",
        body: JSON.stringify({ title: taskTitle }),
      });
      setSelected(updated);
      setTaskTitle("");
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Task failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell
      title="Incident Response"
      description="Convert alerts, assign work, record notes/tasks, and reconstruct timeline. Evidence links require sealed artefacts."
    >
      {error ? <StateBox kind="error" text={error} /> : null}
      {!items ? <StateBox kind="loading" text="Loading incidents…" /> : null}

      {alerts.length > 0 ? (
        <Panel title="CONVERT OPEN ALERTS">
          {alerts.map((alert) => (
            <div
              key={alert.id}
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: 12,
                borderTop: "1px solid var(--border)",
                padding: "8px 0",
              }}
            >
              <div>
                <Severity value={alert.severity} /> {alert.title}
              </div>
              <button disabled={busy} onClick={() => convertAlert(alert.id)} type="button">
                Open incident
              </button>
            </div>
          ))}
        </Panel>
      ) : null}

      {items && items.length === 0 ? (
        <StateBox kind="empty" text="No incidents yet. Convert an alert or rebuild correlation groups." />
      ) : null}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.2fr", gap: 12 }}>
        <div>
          {items?.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setSelected(item)}
              style={{
                display: "block",
                width: "100%",
                textAlign: "left",
                marginBottom: 8,
                background: selected?.id === item.id ? "var(--panel)" : "transparent",
                border: "1px solid var(--border)",
                padding: 12,
                cursor: "pointer",
                color: "inherit",
              }}
            >
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <Severity value={item.severity} />
                <strong>{item.status}</strong>
              </div>
              <div>{item.title}</div>
              <div style={{ fontFamily: "var(--font-mono)", color: "var(--muted)", fontSize: 12 }}>{item.id}</div>
            </button>
          ))}
        </div>

        <div>
          {!selected ? (
            <StateBox kind="empty" text="Select an incident to investigate." />
          ) : (
            <>
              <Panel title={`${selected.id} · ${selected.status}`}>
                <div>{selected.title}</div>
                <div style={{ color: "var(--muted)", marginTop: 8 }}>
                  Assignee: {selected.assignee_email || "unassigned"} · Evidence: {selected.evidence_ids.length} ·
                  Techniques: {selected.mitre_techniques.join(", ") || "none"}
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 12 }}>
                  {["triaging", "investigating", "contained", "closed"].map((status) => (
                    <button key={status} type="button" disabled={busy} onClick={() => setStatus(status)}>
                      {status}
                    </button>
                  ))}
                  <button type="button" disabled={busy} onClick={assignSelf}>
                    Assign me
                  </button>
                </div>
              </Panel>
              <Panel title="NOTES">
                <form onSubmit={submitNote} style={{ display: "flex", gap: 8, marginBottom: 12 }}>
                  <input
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    placeholder="Analyst note"
                    style={{ flex: 1 }}
                  />
                  <button type="submit" disabled={busy}>
                    Add
                  </button>
                </form>
                {(selected.notes || []).length === 0 ? (
                  <StateBox kind="empty" text="No notes yet." />
                ) : (
                  selected.notes.map((n) => (
                    <div key={n.id} style={{ borderTop: "1px solid var(--border)", padding: "8px 0" }}>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--muted)" }}>
                        {n.at} · {n.author_id}
                      </div>
                      <div>{n.body}</div>
                    </div>
                  ))
                )}
              </Panel>
              <Panel title="ANALYST TASKS">
                <form onSubmit={submitTask} style={{ display: "flex", gap: 8, marginBottom: 12 }}>
                  <input
                    value={taskTitle}
                    onChange={(e) => setTaskTitle(e.target.value)}
                    placeholder="Task title"
                    style={{ flex: 1 }}
                  />
                  <button type="submit" disabled={busy}>
                    Add
                  </button>
                </form>
                {(selected.tasks || []).length === 0 ? (
                  <StateBox kind="empty" text="No tasks yet." />
                ) : (
                  selected.tasks.map((t) => (
                    <div key={t.id} style={{ borderTop: "1px solid var(--border)", padding: "8px 0" }}>
                      [{t.status}] {t.title}
                    </div>
                  ))
                )}
              </Panel>
              <Panel title="TIMELINE">
                {(selected.timeline || []).length === 0 ? (
                  <StateBox kind="empty" text="Timeline empty." />
                ) : (
                  selected.timeline.map((event) => (
                    <div key={event.id} style={{ borderTop: "1px solid var(--border)", padding: "8px 0" }}>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--muted)" }}>
                        {event.at} · {event.kind}
                      </div>
                      <div>{event.summary}</div>
                    </div>
                  ))
                )}
              </Panel>
            </>
          )}
        </div>
      </div>
    </AppShell>
  );
}
