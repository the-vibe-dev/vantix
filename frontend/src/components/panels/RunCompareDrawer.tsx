import { useEffect, useState } from "react";
import { RunCompare, api } from "../../api";

type Props = {
  runA: string;
  runB: string;
  onClose: () => void;
};

// P3-6 — structured diff view between two runs.
export function RunCompareDrawer({ runA, runB, onClose }: Props) {
  const [data, setData] = useState<RunCompare | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const diff = await api.compareRuns(runA, runB);
        if (!cancelled) setData(diff);
      } catch (exc) {
        if (!cancelled) setError(String((exc as Error)?.message || exc));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [runA, runB]);

  return (
    <aside
      className="panel"
      role="dialog"
      aria-label="Run comparison"
      style={{
        position: "fixed",
        top: 0,
        right: 0,
        bottom: 0,
        width: "min(640px, 100%)",
        overflowY: "auto",
        zIndex: 40,
        borderLeft: "1px solid var(--line)",
        background: "var(--surface-1)",
      }}
    >
      <header style={{ display: "flex", justifyContent: "space-between" }}>
        <div>
          <h3 style={{ margin: 0 }}>Run Comparison</h3>
          <span style={{ fontSize: ".75rem", color: "var(--ink-dim)" }}>
            {runA} ↔ {runB}
          </span>
        </div>
        <button onClick={onClose}>Close</button>
      </header>

      {error ? <p style={{ color: "var(--error)" }}>{error}</p> : null}
      {!data ? (
        <p className="empty">Loading diff…</p>
      ) : (
        <>
          <section>
            <h4>Findings — only in A ({data.findings.only_in_a.length})</h4>
            <ul style={{ fontSize: ".78rem" }}>
              {data.findings.only_in_a.map((f) => (
                <li key={f.id}>
                  [{f.severity}] {f.title}
                </li>
              ))}
            </ul>
          </section>
          <section>
            <h4>Findings — only in B ({data.findings.only_in_b.length})</h4>
            <ul style={{ fontSize: ".78rem" }}>
              {data.findings.only_in_b.map((f) => (
                <li key={f.id}>
                  [{f.severity}] {f.title}
                </li>
              ))}
            </ul>
          </section>
          <section>
            <h4>Findings — changed ({data.findings.changed.length})</h4>
            <ul style={{ fontSize: ".78rem" }}>
              {data.findings.changed.map((row) => (
                <li key={row.fingerprint}>
                  <strong>{row.title || row.fingerprint}</strong>
                  <ul>
                    {Object.entries(row.changes).map(([field, delta]) => (
                      <li key={field}>
                        {field}: {String(delta.a)} → {String(delta.b)}
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          </section>
          <section>
            <h4>Phase durations</h4>
            <table style={{ width: "100%", fontSize: ".78rem" }}>
              <thead>
                <tr>
                  <th align="left">Phase</th>
                  <th align="right">A (s)</th>
                  <th align="right">B (s)</th>
                  <th align="right">Δ</th>
                </tr>
              </thead>
              <tbody>
                {data.phases.map((phase) => (
                  <tr key={phase.phase_name}>
                    <td>{phase.phase_name}</td>
                    <td align="right">{phase.duration_a_seconds ?? "—"}</td>
                    <td align="right">{phase.duration_b_seconds ?? "—"}</td>
                    <td
                      align="right"
                      style={{
                        color: phase.delta_seconds > 0 ? "var(--warn)" : phase.delta_seconds < 0 ? "var(--ok)" : undefined,
                      }}
                    >
                      {phase.delta_seconds}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          <section>
            <h4>Vectors</h4>
            <p style={{ fontSize: ".78rem" }}>
              A: {data.vectors.count_a} · B: {data.vectors.count_b}
            </p>
          </section>
        </>
      )}
    </aside>
  );
}
