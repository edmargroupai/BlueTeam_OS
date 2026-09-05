"use client";

import { FormEvent, useState, type CSSProperties } from "react";
import { useRouter } from "next/navigation";
import { api, getApiUrl, setSession } from "@/lib/api";

type LoginResponse = {
  access_token: string;
  user: { email: string };
};

type TenantList = { items: { id: string; name: string }[] };

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("edmargroupai@gmail.com");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const login = await api<LoginResponse>(
        "/api/v1/auth/login",
        { method: "POST", body: JSON.stringify({ email, password }) },
        false,
      );
      localStorage.setItem("btos.token", login.access_token);
      const tenants = await fetch(`${getApiUrl()}/api/v1/tenants`, {
        headers: { Authorization: `Bearer ${login.access_token}` },
      }).then((r) => r.json() as Promise<TenantList>);
      const tenantId = tenants.items[0]?.id;
      if (!tenantId) throw new Error("No tenant membership");
      setSession(login.access_token, tenantId);
      router.replace("/command");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={{ display: "grid", placeItems: "center", minHeight: "100vh" }}>
      <form
        onSubmit={onSubmit}
        style={{
          width: 380,
          background: "var(--surface)",
          border: "1px solid var(--border)",
          padding: 28,
        }}
      >
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, letterSpacing: "0.1em" }}>
          BLUE TEAM OS CENTER
        </div>
        <h1 style={{ fontSize: 22, margin: "8px 0 6px" }}>Operator sign-in</h1>
        <p style={{ color: "var(--muted)", marginTop: 0 }}>
          Local password auth for development. Production uses the OIDC abstraction.
        </p>
        <label style={{ display: "block", marginBottom: 12 }}>
          Email
          <input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={inputStyle()}
            autoComplete="username"
          />
        </label>
        <label style={{ display: "block", marginBottom: 16 }}>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={inputStyle()}
            autoComplete="current-password"
          />
        </label>
        {error ? <div style={{ color: "var(--critical)", marginBottom: 12 }}>{error}</div> : null}
        <button type="submit" disabled={loading} style={{ ...inputStyle(), cursor: "pointer", background: "var(--accent-dim)", color: "var(--text)" }}>
          {loading ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}

function inputStyle(): CSSProperties {
  return {
    display: "block",
    width: "100%",
    marginTop: 6,
    padding: "8px 10px",
    background: "var(--bg)",
    color: "var(--text)",
    border: "1px solid var(--border)",
  };
}
