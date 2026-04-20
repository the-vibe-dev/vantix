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
      <form className="login-card" onSubmit={submit}>
        <h1>Vantix SecOps</h1>
        <p className="muted">Sign in to continue</p>
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
