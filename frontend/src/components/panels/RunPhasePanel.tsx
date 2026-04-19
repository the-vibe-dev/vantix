import { RunPhase } from "../../api";

export function RunPhasePanel({ phase }: { phase: RunPhase | null }) {
  const attemptCount = phase?.history?.length || 0;
  const reason = (phase?.reason || "").toLowerCase();
  const badge = reason.includes("retry")
    ? "retrying"
    : reason.includes("blocked")
      ? "blocked"
      : reason.includes("resume")
        ? "resumed"
        : "active";
  return (
    <article className="panel">
      <header><h3>Phase State</h3><span>{phase?.current || "unknown"}</span></header>
      {phase ? (
        <>
          <p>Attempt history: {attemptCount}</p>
          <p>Status: <strong>{badge}</strong></p>
          <p>Reason: {phase.reason || "n/a"}</p>
          <p>Completed: {phase.completed.join(", ") || "none"}</p>
          <p>Pending: {phase.pending.slice(0, 4).join(", ") || "none"}</p>
        </>
      ) : <p className="empty">No phase state loaded.</p>}
    </article>
  );
}
