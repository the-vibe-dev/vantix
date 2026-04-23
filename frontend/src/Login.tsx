import { useState } from "react";

import { api, ApiError, type AuthUser } from "./api";

type LoginProps = {
  onSuccess: (user: AuthUser) => void;
};

export default function Login({ onSuccess }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setError("");
    try {
      const res = await api.login(username, password);
      onSuccess(res.user);
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError("Too many login attempts. Wait a minute and try again.");
      } else if (err instanceof ApiError && err.status === 401) {
        setError("Invalid credentials.");
      } else {
        setError(err instanceof Error ? err.message : "Login failed.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-shell">
      <section className="login-copy" aria-label="Vantix positioning">
        <p className="login-eyebrow">Vantix</p>
        <h1>Autonomous security testing for logic flaws and trust-boundary bugs</h1>
        <p>
          Flow-aware analysis for authentication paths, protocol state machines, systemic authorization
          failures, and high-signal triage. Findings are grouped by root cause and backed by evidence.
        </p>
        <div className="case-grid">
          <article>
            <strong>Authentication trust boundaries</strong>
            <span>Trace frontend state and backend assertions to catch identity trust failures.</span>
          </article>
          <article>
            <strong>Protocol correctness</strong>
            <span>Detect liveness and state-machine bugs that do not look like simple input flaws.</span>
          </article>
          <article>
            <strong>Systemic exposure</strong>
            <span>Group repeated secret or control-plane leaks by root cause, not by endpoint count.</span>
          </article>
        </div>
      </section>
      <form className="login-card" onSubmit={submit}>
        <h1>Vantix SecOps</h1>
        <p className="muted">Sign in to continue to the operator control plane.</p>
        <label>
          <span>Username</span>
          <input
            type="text"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </label>
        <label>
          <span>Password</span>
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        {error ? <div className="login-error">{error}</div> : null}
        <button type="submit" disabled={submitting || !username || !password}>
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
