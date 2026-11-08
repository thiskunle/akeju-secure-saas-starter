"use client";
// Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
// Akeju Secure SaaS Starter, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later

import { FormEvent, useCallback, useEffect, useState } from "react";

type Me = { email: string; role: string; mfa_enabled: boolean };
type Project = { id: string; name: string };
type Audit = { action: string; at: string };
type Stage = "loading" | "signin" | "signup" | "mfa" | "app";

async function api<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const csrf = document.cookie.split("; ").find((c) => c.startsWith("csrf="))?.split("=")[1];
  const response = await fetch(`/api${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...(csrf ? { "X-CSRF-Token": csrf } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(typeof data.detail === "string" ? data.detail : "Check the form and try again.");
  }
  return response.status === 204 ? (undefined as T) : response.json();
}

function fields(event: FormEvent<HTMLFormElement>) {
  event.preventDefault();
  return Object.fromEntries(new FormData(event.currentTarget)) as Record<string, string>;
}

export default function Page() {
  const [stage, setStage] = useState<Stage>("loading");
  const [error, setError] = useState("");
  const [ticket, setTicket] = useState("");
  const [me, setMe] = useState<Me | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [audit, setAudit] = useState<Audit[] | null>(null);
  const [mfaSecret, setMfaSecret] = useState("");

  const load = useCallback(async () => {
    const user = await api<Me>("/me");
    setMe(user);
    setProjects(await api<Project[]>("/projects"));
    setAudit(["owner", "admin"].includes(user.role) ? await api<Audit[]>("/audit") : null);
    setStage("app");
  }, []);

  useEffect(() => { load().catch(() => setStage("signin")); }, [load]);

  const attempt = (work: () => Promise<void>) => {
    setError("");
    work().catch((e: Error) => setError(e.message));
  };

  const signIn = (e: FormEvent<HTMLFormElement>) => {
    const data = fields(e);
    attempt(async () => {
      const result = await api<{ mfa_required: boolean; ticket?: string }>("/auth/login", "POST", data);
      if (result.mfa_required) { setTicket(result.ticket!); setStage("mfa"); } else await load();
    });
  };
  const signUp = (e: FormEvent<HTMLFormElement>) => {
    const data = fields(e);
    attempt(async () => { await api("/auth/signup", "POST", data); await load(); });
  };
  const verify = (e: FormEvent<HTMLFormElement>) => {
    const data = fields(e);
    attempt(async () => { await api("/auth/mfa/login", "POST", { ticket, code: data.code }); await load(); });
  };
  const addProject = (e: FormEvent<HTMLFormElement>) => {
    const form = e.currentTarget;
    const data = fields(e);
    attempt(async () => { await api("/projects", "POST", data); form.reset(); await load(); });
  };
  const setupMfa = () => attempt(async () => setMfaSecret((await api<{ secret: string }>("/auth/mfa/setup", "POST")).secret));
  const enableMfa = (e: FormEvent<HTMLFormElement>) => {
    const data = fields(e);
    attempt(async () => { await api("/auth/mfa/enable", "POST", data); setMfaSecret(""); await load(); });
  };
  const signOut = () => attempt(async () => { await api("/auth/logout", "POST"); setMe(null); setStage("signin"); });

  return (
    <main>
      <h1>Secure SaaS Starter</h1>
      <p className="muted">Sign-in, two-step codes, roles, audit logs and separated customer data.</p>
      {error && <p className="error" role="alert">{error}</p>}

      {stage === "signin" && (
        <section>
          <h2>Sign in</h2>
          <form onSubmit={signIn}>
            <label>Email<input name="email" type="email" required autoComplete="username" /></label>
            <label>Password<input name="password" type="password" required autoComplete="current-password" /></label>
            <button>Sign in</button>
          </form>
          <p /><button className="quiet" onClick={() => { setError(""); setStage("signup"); }}>Create a company account</button>
        </section>
      )}

      {stage === "signup" && (
        <section>
          <h2>Create a company account</h2>
          <form onSubmit={signUp}>
            <label>Company name<input name="company" required /></label>
            <label>Email<input name="email" type="email" required autoComplete="username" /></label>
            <label>Password (at least 12 characters)<input name="password" type="password" minLength={12} required autoComplete="new-password" /></label>
            <button>Create account</button>
          </form>
          <p /><button className="quiet" onClick={() => { setError(""); setStage("signin"); }}>Back to sign in</button>
        </section>
      )}

      {stage === "mfa" && (
        <section>
          <h2>Enter your 6-digit code</h2>
          <form onSubmit={verify}>
            <label>Code from your authenticator app<input name="code" inputMode="numeric" pattern="[0-9]{6}" required autoComplete="one-time-code" /></label>
            <button>Verify code</button>
          </form>
        </section>
      )}

      {stage === "app" && me && (
        <>
          <section>
            <div className="row">
              <span>Signed in as <strong>{me.email}</strong> ({me.role})</span>
              <button className="quiet" onClick={signOut}>Sign out</button>
            </div>
          </section>

          <section>
            <h2>Two-step sign-in</h2>
            {me.mfa_enabled ? <p>Two-step sign-in is on.</p> : mfaSecret ? (
              <form onSubmit={enableMfa}>
                <p>Add this key to your authenticator app: <code data-testid="mfa-secret">{mfaSecret}</code></p>
                <label>Code from your app<input name="code" inputMode="numeric" pattern="[0-9]{6}" required /></label>
                <button>Turn on two-step sign-in</button>
              </form>
            ) : <button onClick={setupMfa}>Set up two-step sign-in</button>}
          </section>

          <section>
            <h2>Projects</h2>
            {me.role !== "viewer" && (
              <form onSubmit={addProject}>
                <label>Project name<input name="name" required maxLength={120} /></label>
                <button>Add project</button>
              </form>
            )}
            {projects.length === 0 ? <p className="muted">No projects yet.</p> : <ul>{projects.map((p) => <li key={p.id}>{p.name}</li>)}</ul>}
          </section>

          {audit && (
            <section>
              <h2>Audit log</h2>
              <ul data-testid="audit">{audit.map((a, i) => <li key={i}>{a.action} <span className="muted">{new Date(a.at + "Z").toLocaleString()}</span></li>)}</ul>
            </section>
          )}
        </>
      )}

      <footer>Built on akeju-secure-saas-starter, created by Adekunle Akeju.</footer>
    </main>
  );
}
