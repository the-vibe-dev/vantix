import { useEffect, useState } from "react";
import { BusEvent, api } from "../../api";

type Props = {
  runId: string;
  onClose: () => void;
};

// V2-10 — Drawer listing policy_decision bus events for a run.
export function PolicyDecisionDrawer({ runId, onClose }: Props) {
  const [events, setEvents] = useState<BusEvent[]>([]);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const rows = await api.listRunBusEvents(runId, { type: "policy_decision", limit: 500 });
        if (!cancelled) setEvents(rows);
      } catch (exc) {
        if (!cancelled) setError(String((exc as Error)?.message || exc));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [runId]);

  const verdictColor = (v: unknown) => {
    switch (v) {
      case "allow": return "var(--success, #4ade80)";
      case "blocked": return "var(--error, #f87171)";
      case "approval_required": return "var(--warning, #fbbf24)";
      default: return "var(--ink-dim)";
    }
  };

  return (
    <aside
      className="panel"
      role="dialog"
      aria-label="Policy decisions"
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
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h3 style={{ margin: 0 }}>Policy Decisions</h3>
          <span style={{ fontSize: ".75rem", color: "var(--ink-dim)" }}>run {runId}</span>
        </div>
        <button onClick={onClose}>Close</button>
      </header>

      {error ? <p style={{ color: "var(--error)" }}>{error}</p> : null}
      {!error && events.length === 0 ? (
        <p className="empty">No policy decisions recorded.</p>
      ) : null}

      <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
        {events.map((ev) => {
          const verdict = (ev.payload as Record<string, unknown>)?.verdict;
          const phase = (ev.payload as Record<string, unknown>)?.phase;
          const isOpen = !!expanded[ev.id];
          return (
            <li key={ev.id} style={{ borderTop: "1px solid var(--line)", padding: ".5rem 0" }}>
              <button
                onClick={() => setExpanded((s) => ({ ...s, [ev.id]: !isOpen }))}
                style={{
                  display: "flex", width: "100%", justifyContent: "space-between",
                  background: "transparent", border: 0, color: "inherit", cursor: "pointer",
                }}
              >
                <span>
                  <strong style={{ color: verdictColor(verdict) }}>{String(verdict ?? "—")}</strong>
                  <span style={{ marginLeft: ".5rem", color: "var(--ink-dim)" }}>
                    turn {ev.turn_id} · {String(phase ?? ev.agent)}
                  </span>
                </span>
                <span style={{ fontSize: ".75rem", color: "var(--ink-dim)" }}>
                  #{ev.seq} · {new Date(ev.created_at).toLocaleTimeString()}
                </span>
              </button>
              {isOpen ? (
                <pre style={{ fontSize: ".75rem", overflowX: "auto", background: "var(--surface-2)", padding: ".5rem" }}>
                  {JSON.stringify(ev.payload, null, 2)}
                </pre>
              ) : null}
            </li>
          );
        })}
      </ul>
    </aside>
  );
}
