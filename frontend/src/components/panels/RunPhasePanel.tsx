import { RunPhase, WorkflowState } from "../../api";

export function RunPhasePanel({ phase, workflowState }: { phase: RunPhase | null; workflowState: WorkflowState | null }) {
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
          <p>Workflow: <strong>{workflowState?.workflow?.status || "n/a"}</strong></p>
          <p>Retries: {Number(workflowState?.metrics?.retry_count || 0)}</p>
          <p>Blocked attempts: {Number(workflowState?.metrics?.blocked_count || 0)}</p>
          <p>Active leases: {Number(workflowState?.metrics?.active_lease_count || 0)}</p>
          <p>Workers: {workflowState?.workers?.map((row) => `${row.worker_id}:${row.status}`).join(", ") || "none"}</p>
          <p>Blocked reason: {workflowState?.blocked_reasons?.[0] || "none"}</p>
          <p>Completed: {phase.completed.join(", ") || "none"}</p>
          <p>Pending: {phase.pending.slice(0, 4).join(", ") || "none"}</p>
        </>
      ) : <p className="empty">No phase state loaded.</p>}
    </article>
  );
}
