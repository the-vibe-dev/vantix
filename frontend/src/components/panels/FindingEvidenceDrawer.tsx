import { useState } from "react";
import { Finding, api } from "../../api";

type Props = {
  runId: string;
  finding: Finding;
  onClose: () => void;
  onUpdated?: (finding: Finding) => void;
};

// P3-1 — surfaces evidence_ids, reproduction_script, and the custody trio
// on a single finding, with a Replay action that copies the repro script to
// the clipboard and a terminal disposition review button.
export function FindingEvidenceDrawer({ runId, finding, onClose, onUpdated }: Props) {
  const [current, setCurrent] = useState<Finding>(finding);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function review(disposition: "confirmed" | "dismissed" | "reviewed") {
    setBusy(true);
    setError("");
    try {
      const updated = await api.reviewFinding(runId, current.id, { disposition });
      setCurrent(updated);
      onUpdated?.(updated);
    } catch (exc) {
      setError(String((exc as Error)?.message || exc));
    } finally {
      setBusy(false);
    }
  }

  async function replay() {
    if (!current.reproduction_script) return;
    try {
      await navigator.clipboard.writeText(current.reproduction_script);
    } catch {
      // Clipboard not available (non-secure context); fall through silently.
    }
  }

  const evidenceIds = current.evidence_ids || [];
  return (
    <aside
      className="panel"
      role="dialog"
      aria-label="Finding evidence"
      style={{
        position: "fixed",
        top: 0,
        right: 0,
        bottom: 0,
        width: "min(520px, 100%)",
        overflowY: "auto",
        zIndex: 40,
        borderLeft: "1px solid var(--line)",
        background: "var(--surface-1)",
      }}
    >
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h3 style={{ margin: 0 }}>{current.title}</h3>
          <span style={{ fontSize: ".75rem", color: "var(--ink-dim)" }}>
            {current.severity} · {current.status} · {current.disposition || "draft"}
          </span>
        </div>
        <button onClick={onClose}>Close</button>
      </header>

      <section>
        <h4>Custody</h4>
        <ul style={{ listStyle: "none", padding: 0, margin: 0, fontSize: ".78rem" }}>
          <li>Promoted: {current.promoted_at || "—"}</li>
          <li>Reviewed: {current.reviewed_at || "—"}</li>
          <li>Reviewer: {current.reviewer_user_id || "—"}</li>
          <li>Fingerprint: {current.fingerprint || "—"}</li>
        </ul>
      </section>

      <section>
        <h4>Summary</h4>
        <p style={{ fontSize: ".8rem", lineHeight: 1.45 }}>{current.summary}</p>
        {current.evidence ? (
          <>
            <h4>Evidence</h4>
            <pre
              style={{
                fontSize: ".72rem",
                background: "var(--surface-2)",
                padding: 8,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {current.evidence}
            </pre>
          </>
        ) : null}
      </section>

      <section>
        <h4>Linked Evidence ({evidenceIds.length})</h4>
        {evidenceIds.length ? (
          <ul style={{ fontSize: ".78rem" }}>
            {evidenceIds.map((id) => (
              <li key={id}>
                <a href={`/api/v1/runs/${runId}/artifacts/${id}`}>{id}</a>
              </li>
            ))}
          </ul>
        ) : (
          <p className="empty">No linked artifacts.</p>
        )}
      </section>

      <section>
        <h4>Reproduction</h4>
        {current.reproduction_script ? (
          <>
            <pre
              style={{
                fontSize: ".72rem",
                background: "var(--surface-2)",
                padding: 8,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {current.reproduction_script}
            </pre>
            <button onClick={replay}>Replay (copy to clipboard)</button>
          </>
        ) : (
          <p className="empty">No reproduction script recorded.</p>
        )}
      </section>

      <section>
        <h4>Review</h4>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <button disabled={busy} onClick={() => review("reviewed")}>Mark Reviewed</button>
          <button disabled={busy} onClick={() => review("confirmed")}>Confirm</button>
          <button disabled={busy} onClick={() => review("dismissed")}>Dismiss</button>
        </div>
        {error ? <p style={{ color: "var(--error)", fontSize: ".75rem" }}>{error}</p> : null}
      </section>
    </aside>
  );
}
