import { SystemStatus, ToolStatus } from "../../api";

export function InstallerPanel(props: {
  systemStatus: SystemStatus | null;
  installStatus: { ready: boolean; updated_at: string; state: Record<string, unknown> } | null;
  tools: Array<Pick<ToolStatus, "id" | "name" | "installed" | "installable" | "suites" | "version" | "path">>;
  suites: Record<string, unknown>;
  selectedSuite: string;
  setSelectedSuite: (value: string) => void;
  onRefresh: () => void;
  onInstallSuite: (suite: string) => Promise<void>;
}) {
  const suiteNames = Object.keys(props.suites);
  const selectedSuiteRecord = (props.suites[props.selectedSuite] as { tools?: string[]; title?: string } | undefined) || undefined;
  const suiteTools = selectedSuiteRecord?.tools || [];
  const suiteStatus = props.tools.filter((tool) => suiteTools.includes(tool.id));
  const installedCount = suiteStatus.filter((tool) => tool.installed).length;
  const missingCount = suiteStatus.length - installedCount;
  const installerState = props.installStatus?.state || {};
  const cveState = (installerState.cve as Record<string, unknown> | undefined) || {};
  const runtimeState = (installerState.runtime as Record<string, unknown> | undefined) || {};

  return (
    <article className="panel settings-panel">
      <header><h3>Installer And Tools</h3><span>Bootstrap state</span></header>
      <div className="installer-grid">
        <div className="installer-summary">
          <span className={props.installStatus?.ready ? "pill ok" : "pill warn"}>{props.installStatus?.ready ? "Installer ready" : "Installer incomplete"}</span>
          <span className={(props.systemStatus?.codex?.available as boolean) ? "pill ok" : "pill warn"}>{(props.systemStatus?.codex?.available as boolean) ? "Codex ready" : "Codex missing"}</span>
          <span className={(props.systemStatus?.cve_mcp?.enabled as boolean) ? "pill ok" : "pill warn"}>{(props.systemStatus?.cve_mcp?.enabled as boolean) ? "CVE MCP on" : "CVE MCP off"}</span>
          <p>Runtime: {String(runtimeState.runtime_type || "codex")}</p>
          <p>Suite: {String((installerState.tools as Record<string, unknown> | undefined)?.suite || props.systemStatus?.installer?.selected_suite || "unset")}</p>
          <p>CVE refresh: {String(cveState.refresh_cadence || props.systemStatus?.installer?.cve_refresh || "unset")}</p>
          <p>Updated: {props.installStatus?.updated_at || "never"}</p>
        </div>
        <div className="installer-actions">
          <label>
            Tool suite
            <select value={props.selectedSuite} onChange={(event) => props.setSelectedSuite(event.target.value)}>
              {suiteNames.map((suite) => <option key={suite} value={suite}>{suite}</option>)}
            </select>
          </label>
          <p>{selectedSuiteRecord?.title || "Choose a suite to review the expected tool inventory."}</p>
          <p>{installedCount}/{suiteStatus.length} installed{missingCount ? `, ${missingCount} missing` : ""}</p>
          <div className="approval-actions">
            <button type="button" onClick={() => void props.onRefresh()}>Refresh State</button>
            {props.selectedSuite ? <button type="button" onClick={() => void props.onInstallSuite(props.selectedSuite)}>Install Suite</button> : null}
          </div>
        </div>
      </div>
      <ul>
        {suiteStatus.slice(0, 8).map((tool) => (
          <li key={tool.id}>
            <strong>{tool.name}</strong>
            <span>{tool.installed ? "installed" : tool.installable ? "missing/installable" : "missing/blocked"}</span>
            <p>{tool.version || tool.path || tool.id}</p>
          </li>
        ))}
      </ul>
      {!suiteStatus.length ? <p className="empty">No suite inventory loaded.</p> : null}
    </article>
  );
}
