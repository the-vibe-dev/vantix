import { useEffect, useState } from "react";
import { RuntimeHealth, api } from "../../api";

// P3-2 — lightweight ops panel that polls /runtime/health.
export function RuntimeHealthPanel({ pollSeconds = 15 }: { pollSeconds?: number }) {
  const [data, setData] = useState<RuntimeHealth | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      try {
        const health = await api.getRuntimeHealth();
        if (!cancelled) {
          setData(health);
          setError("");
        }
      } catch (exc) {
        if (!cancelled) setError(String((exc as Error)?.message || exc));
      }
    }
    tick();
    const timer = window.setInterval(tick, Math.max(5, pollSeconds) * 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [pollSeconds]);

  if (!data) {
    return (
      <article className="panel">
        <header>
          <h3>Runtime Health</h3>
          <span>polling…</span>
        </header>
        {error ? <p style={{ color: "var(--error)" }}>{error}</p> : <p className="empty">Loading.</p>}
      </article>
    );
  }

  const { leases, workers, thresholds } = data;
  const staleLeaseCount = leases.stale.length;
  const staleWorkerCount = workers.stale.length;

  return (
    <article className="panel">
      <header>
        <h3>Runtime Health</h3>
        <span>
          {workers.total} workers · {leases.total} leases
        </span>
      </header>

      <section>
        <h4>Leases</h4>
        <ul style={{ fontSize: ".78rem" }}>
          {Object.entries(leases.by_state).map(([state, count]) => (
            <li key={state}>
              {state}: {count}
            </li>
          ))}
        </ul>
        {staleLeaseCount ? (
          <div className="alert" style={{ color: "var(--warn)" }}>
            {staleLeaseCount} stale lease{staleLeaseCount === 1 ? "" : "s"} (threshold{" "}
            {thresholds.stale_lease_seconds}s)
          </div>
        ) : null}
      </section>

      <section>
        <h4>Workers</h4>
        <ul style={{ fontSize: ".78rem" }}>
          {workers.rows.map((row) => (
            <li key={row.worker_id}>
              <strong>{row.worker_id}</strong> · {row.status} ·{" "}
              {row.heartbeat_age_seconds != null
                ? `${row.heartbeat_age_seconds.toFixed(0)}s ago`
                : "no heartbeat"}
              {row.current_phase ? ` · phase ${row.current_phase}` : ""}
            </li>
          ))}
        </ul>
        {staleWorkerCount ? (
          <div className="alert" style={{ color: "var(--warn)" }}>
            {staleWorkerCount} stale worker{staleWorkerCount === 1 ? "" : "s"} (threshold{" "}
            {thresholds.stale_heartbeat_seconds}s)
          </div>
        ) : null}
      </section>

      <footer style={{ fontSize: ".7rem", color: "var(--ink-dim)" }}>
        Updated {data.generated_at}
      </footer>
    </article>
  );
}
