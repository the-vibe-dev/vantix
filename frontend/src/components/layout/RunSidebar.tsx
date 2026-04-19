import { Run } from "../../api";

export function RunSidebar(props: { runs: Run[]; selectedRun: Run | null; mode: string; setMode: (mode: string) => void; target: string; setTarget: (target: string) => void; modes: string[]; onSelect: (run: Run) => void }) {
  return (
    <aside className="sidebar">
      <div className="brand-block">
        <span className="eyebrow">Autonomous Offensive Security Suite</span>
        <h1>VANTIX</h1>
        <p>Recon. Exploit. Forge. Report.</p>
      </div>
      <div className="launch card">
        <label>
          Module
          <select value={props.mode} onChange={(event) => props.setMode(event.target.value)}>
            {props.modes.map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
        </label>
        <label>
          Target override
          <input value={props.target} onChange={(event) => props.setTarget(event.target.value)} placeholder="10.10.10.10 or https://target" />
        </label>
        <p className="hint">Use the orchestrator chat to launch or continue a run.</p>
      </div>
      <div className="card run-list">
        <h2>Recent Runs</h2>
        {props.runs.map((run) => (
          <button key={run.id} className={`run-card ${props.selectedRun?.id === run.id ? "active" : ""}`} onClick={() => props.onSelect(run)}>
            <strong>{run.workspace_id}</strong>
            <span>{run.mode} / {run.status}</span>
            <small>{run.target}</small>
          </button>
        ))}
      </div>
    </aside>
  );
}
