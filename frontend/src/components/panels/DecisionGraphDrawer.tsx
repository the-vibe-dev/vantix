import { useEffect, useMemo, useState } from "react";
import { DecisionGraphResponse, api } from "../../api";

type Props = {
  runId: string;
  factIds?: string[];
  onClose: () => void;
};

// V2-20 — Decision-graph viewer. Renders the DAG as a per-turn list
// with intra-turn ordering and causal arrows to the next turn so the
// operator can trace "why this action → which fact → which evidence".
export function DecisionGraphDrawer({ runId, factIds, onClose }: Props) {
  const [data, setData] = useState<DecisionGraphResponse | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const g = await api.getDecisionGraph(runId, { factIds });
        if (!cancelled) setData(g);
      } catch (exc) {
        if (!cancelled) setError(String((exc as Error)?.message || exc));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [runId, (factIds || []).join(",")]);

  const groupedByTurn = useMemo(() => {
    const map = new Map<number, DecisionGraphResponse["nodes"]>();
    if (data) {
      for (const n of data.nodes) {
        const arr = map.get(n.turn_id) || [];
        arr.push(n);
        map.set(n.turn_id, arr);
      }
    }
    return [...map.entries()].sort(([a], [b]) => a - b);
  }, [data]);

  const causalByTo = useMemo(() => {
    const m = new Map<string, string>();
    if (data) for (const e of data.edges) if (e.kind === "causal_fact") m.set(e.to_id, e.from_id);
    return m;
  }, [data]);

  return (
    <aside
      className="panel"
      role="dialog"
      aria-label="Decision graph"
      style={{
        position: "fixed",
        top: 0,
        right: 0,
        bottom: 0,
        width: "min(720px, 100%)",
        overflowY: "auto",
        zIndex: 40,
        borderLeft: "1px solid var(--line)",
        background: "var(--surface-1)",
      }}
    >
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h3 style={{ margin: 0 }}>Decision Graph</h3>
          <span style={{ fontSize: ".75rem", color: "var(--ink-dim)" }}>
            run {runId}
            {factIds && factIds.length > 0 ? ` · filtered by ${factIds.length} fact(s)` : null}
          </span>
        </div>
        <button onClick={onClose}>Close</button>
      </header>

      {error ? <p style={{ color: "var(--error)" }}>{error}</p> : null}
      {!error && data && data.nodes.length === 0 ? (
        <p className="empty">No bus events recorded.</p>
      ) : null}

      {data ? (
        <div style={{ fontSize: ".8rem" }}>
          <p style={{ color: "var(--ink-dim)" }}>
            {data.node_count} nodes · {data.edge_count} edges
          </p>
          {groupedByTurn.map(([turn, nodes]) => (
            <section key={turn} style={{ marginBottom: "1rem", borderTop: "1px solid var(--line)", paddingTop: ".5rem" }}>
              <h4 style={{ margin: ".25rem 0" }}>Turn {turn}</h4>
              <ol style={{ listStyle: "decimal", paddingLeft: "1.5rem", margin: 0 }}>
                {nodes.map((n) => {
                  const parent = causalByTo.get(n.id);
                  return (
                    <li key={n.id} title={n.content_hash}>
                      <code>{n.agent}.{n.type}</code>{" "}
                      <span style={{ color: "var(--ink-dim)" }}>#{n.seq} {n.payload_summary}</span>
                      {parent ? (
                        <span style={{ marginLeft: ".5rem", color: "var(--accent, #38bdf8)" }}>
                          ← caused by {parent.slice(0, 8)}
                        </span>
                      ) : null}
                    </li>
                  );
                })}
              </ol>
            </section>
          ))}
        </div>
      ) : null}
    </aside>
  );
}
