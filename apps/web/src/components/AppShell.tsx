"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, type CSSProperties, type ReactNode } from "react";
import { clearSession, getSession } from "@/lib/api";

const NAV = [
  {
    label: "Command",
    items: [
      { href: "/command", label: "Security Command Center" },
      { href: "/alerts", label: "Live Alerts" },
    ],
  },
  {
    label: "Detect",
    items: [
      { href: "/detections", label: "Detection Engineering" },
      { href: "/attack", label: "ATT&CK Coverage" },
      { href: "/identity", label: "Identity Defence" },
      { href: "/network", label: "Network Investigation" },
      { href: "/endpoint", label: "Endpoint Investigation" },
      { href: "/connectors", label: "Connectors" },
      { href: "/vulns", label: "Vulnerabilities" },
      { href: "/telemetry", label: "Telemetry Health" },
    ],
  },
  {
    label: "Investigate",
    items: [
      { href: "/incidents", label: "Incidents" },
      { href: "/graph", label: "Entity Graph" },
      { href: "/hunt", label: "Threat Hunt" },
      { href: "/intel", label: "Threat Intel" },
      { href: "/dfir", label: "DFIR Workbench" },
      { href: "/architecture", label: "Architecture" },
      { href: "/audit", label: "Audit" },
    ],
  },
  {
    label: "Engineering",
    items: [
      { href: "/blue-range", label: "Blue Range" },
      { href: "/improve", label: "Self-Improvement" },
      { href: "/playbooks", label: "Playbooks" },
      { href: "/quality", label: "Quality Index" },
      { href: "/readiness", label: "Readiness Gate" },
      { href: "/languages", label: "Language Layer" },
    ],
  },
];

export function AppShell({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (!getSession()) router.replace("/login");
  }, [router]);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "240px 1fr", minHeight: "100vh" }}>
      <aside
        style={{
          borderRight: "1px solid var(--border)",
          background: varSurface(),
          padding: "20px 16px",
        }}
      >
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, letterSpacing: "0.08em" }}>
          BLUE TEAM OS
        </div>
        <div style={{ color: "var(--muted)", fontSize: 12, marginBottom: 24 }}>Center · Control plane</div>
        {NAV.map((group) => (
          <div key={group.label} style={{ marginBottom: 18 }}>
            <div style={{ color: "var(--muted)", fontSize: 11, letterSpacing: "0.12em" }}>{group.label}</div>
            {group.items.map((item) => {
              const active = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  style={{
                    display: "block",
                    padding: "6px 8px",
                    marginTop: 4,
                    borderLeft: active ? "2px solid var(--accent)" : "2px solid transparent",
                    background: active ? "var(--accent-dim)" : "transparent",
                  }}
                >
                  {item.label}
                </Link>
              );
            })}
          </div>
        ))}
        <button
          type="button"
          onClick={() => {
            clearSession();
            router.replace("/login");
          }}
          style={ghostButton()}
        >
          Sign out
        </button>
      </aside>
      <main style={{ padding: "24px 28px" }}>
        <header style={{ marginBottom: 20 }}>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 560 }}>{title}</h1>
          <p style={{ margin: "6px 0 0", color: "var(--muted)", maxWidth: 720 }}>{description}</p>
        </header>
        {children}
      </main>
    </div>
  );
}

function varSurface() {
  return "var(--surface)";
}

export function ghostButton(): CSSProperties {
  return {
    marginTop: 12,
    background: "transparent",
    color: "var(--muted)",
    border: "1px solid var(--border)",
    padding: "6px 10px",
    cursor: "pointer",
  };
}

export function Panel({
  title,
  children,
}: {
  title?: string;
  children: ReactNode;
}) {
  return (
    <section
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        padding: 16,
        marginBottom: 16,
      }}
    >
      {title ? (
        <h2 style={{ margin: "0 0 12px", fontSize: 13, color: "var(--muted)", letterSpacing: "0.08em" }}>
          {title}
        </h2>
      ) : null}
      {children}
    </section>
  );
}

export function StateBox({ kind, text }: { kind: "loading" | "empty" | "error"; text: string }) {
  const color = kind === "error" ? "var(--critical)" : "var(--muted)";
  return (
    <div style={{ padding: 24, border: "1px dashed var(--border)", color, textAlign: "center" }}>{text}</div>
  );
}

export function Severity({ value }: { value: string }) {
  const map: Record<string, string> = {
    critical: "var(--critical)",
    high: "var(--high)",
    medium: "var(--medium)",
    low: "var(--low)",
  };
  return <span style={{ color: map[value] ?? "var(--info)", fontFamily: "var(--font-mono)" }}>{value}</span>;
}
