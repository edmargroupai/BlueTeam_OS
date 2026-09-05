"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, type CSSProperties, type ReactNode } from "react";
import { clearSession, getSession } from "@/lib/api";
import { severityColor } from "@/lib/tokens.generated";

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
    <div className="btos-shell" data-density="comfortable">
      <aside className="btos-shell__aside">
        <div className="btos-shell__brand">BLUE TEAM OS</div>
        <div style={{ color: "var(--muted)", fontSize: 12, marginBottom: 24 }}>Center · Control plane</div>
        {NAV.map((group) => (
          <div key={group.label} className="btos-nav-group">
            <div className="btos-nav-group__label">{group.label}</div>
            {group.items.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className="btos-nav-link"
                data-active={pathname === item.href}
              >
                {item.label}
              </Link>
            ))}
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
      <main className="btos-shell__main">
        <header style={{ marginBottom: 20 }}>
          <h1 style={{ margin: 0, fontSize: "var(--btos-type-title-size)", fontWeight: 560 }}>{title}</h1>
          <p style={{ margin: "6px 0 0", color: "var(--muted)", maxWidth: 720 }}>{description}</p>
        </header>
        {children}
      </main>
    </div>
  );
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

export function Panel({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="btos-panel">
      {title ? <h2 className="btos-panel__title">{title}</h2> : null}
      {children}
    </section>
  );
}

export function StateBox({ kind, text }: { kind: "loading" | "empty" | "error" | "disabled"; text: string }) {
  const color = kind === "error" ? "var(--critical)" : "var(--muted)";
  return (
    <div className="btos-state" style={{ color }} role="status">
      {text}
    </div>
  );
}

export function Severity({ value }: { value: string }) {
  return (
    <span className="mono" style={{ color: severityColor(value) }}>
      {value}
    </span>
  );
}
