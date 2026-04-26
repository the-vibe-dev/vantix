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
      case "blocked":
      case "block": return "var(--error, #f87171)";
      case "approval_required": return "var(--warning, #fbbf24)";
      case "rewrite_plan":
      case "downgrade_action": return "var(--accent, #60a5fa)";
      case "route_to_verifier": return "var(--accent-2, #a78bfa)";
      case "sandbox_only": return "var(--warning, #fbbf24)";
      default: return "var(--ink-dim)";
    }
  };

  const verdictLabel = (v: unknown): string => {
    switch (v) {
      case "rewrite_plan": return "rewrite plan";
      case "downgrade_action": return "downgrade action";
      case "route_to_verifier": return "route to verifier";
      case "sandbox_only": return "sandbox only";
      default: return String(v ?? "—");
    }
  };

  const renderExtension = (payload: Record<string, unknown> | undefined) => {
    if (!payload) return null;
    const verdict = payload.verdict;
    const lines: { label: string; value: string }[] = [];
    if (verdict === "rewrite_plan" && payload.rewrite) {
      const rewrite = payload.rewrite as { actions?: { action_type?: string; objective?: string }[] };
      const actions = (rewrite.actions ?? []).map((a) => `${a.action_type ?? "?"}: ${a.objective ?? ""}`);
      lines.push({ label: "rewrite", value: actions.join(" · ") || "(empty plan)" });
    }
    if (verdict === "downgrade_action" && payload.downgrade) {
      const dg = payload.downgrade as Record<string, { action_type?: string; objective?: string }>;
      lines.push({
        label: "downgrade",
        value: Object.entries(dg)
          .map(([idx, a]) => `#${idx} → ${a.action_type ?? "?"} (${a.objective ?? ""})`)
          .join(" · "),
      });
    }
    if (verdict === "route_to_verifier" && payload.verifier_id) {
      lines.push({ label: "verifier", value: String(payload.verifier_id) });
    }
    if (verdict === "sandbox_only" && payload.sandbox) {
      const sb = payload.sandbox as { network?: boolean; max_runtime_seconds?: number };
      const parts = [
        `network=${sb.network ? "on" : "off"}`,
        sb.max_runtime_seconds != null ? `max=${sb.max_runtime_seconds}s` : "",
      ].filter(Boolean);
      lines.push({ label: "sandbox", value: parts.join(" · ") });
    }
    if (typeof payload.reason === "string" && payload.reason) {
      lines.push({ label: "reason", value: payload.reason });
    }
    if (lines.length === 0) return null;
    return (
      <div style={{ marginTop: ".25rem", fontSize: ".75rem", color: "var(--ink-dim)" }}>
        {lines.map((l) => (
          <div key={l.label}>
            <strong>{l.label}:</strong> {l.value}
          </div>
        ))}
      </div>
    );
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
                <span style={{ textAlign: "left" }}>
                  <strong style={{ color: verdictColor(verdict) }}>{verdictLabel(verdict)}</strong>
                  <span style={{ marginLeft: ".5rem", color: "var(--ink-dim)" }}>
                    turn {ev.turn_id} · {String(phase ?? ev.agent)}
                  </span>
                  {renderExtension(ev.payload as Record<string, unknown>)}
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
