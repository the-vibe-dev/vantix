import { Run, RunPhase, SystemStatus } from "../../api";

export function TopBar(props: { selectedRun: Run | null; phase: RunPhase | null; systemStatus: SystemStatus | null; statusMessage: string; onRefresh: () => void; onPause: () => void; onRetry: () => void; onReplan: () => void; onCancel: () => void }) {
  return (
    <section className="topbar card">
      <div>
        <span className="eyebrow">Vantix Orchestrator</span>
        <h2>{props.selectedRun ? props.selectedRun.workspace_id : "No active run"}</h2>
        <p>{props.selectedRun ? `${props.selectedRun.mode} / ${props.selectedRun.status} / ${props.selectedRun.target}` : "Type a target and objective in chat to start."}</p>
        {props.phase ? <p>Phase: {props.phase.current}</p> : null}
        {props.statusMessage ? <p className="status-line">{props.statusMessage}</p> : null}
      </div>
      <div className="status-stack">
        <span className={props.systemStatus?.codex?.available ? "pill ok" : "pill warn"}>Codex {props.systemStatus?.codex?.available ? "ready" : "unavailable"}</span>
        {props.selectedRun ? <div className="controls"><button onClick={props.onRefresh}>Refresh</button><button onClick={props.onPause}>Pause</button><button onClick={props.onRetry}>Retry</button><button onClick={props.onReplan}>Replan</button><button onClick={props.onCancel}>Cancel</button></div> : null}
      </div>
    </section>
  );
}
