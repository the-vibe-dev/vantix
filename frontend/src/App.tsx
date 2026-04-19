import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  AgentSession,
  AttackChain,
  ApiError,
  Approval,
  EventRecord,
  Fact,
  Handoff,
  ProviderConfig,
  Run,
  RunMessage,
  RunResults,
  RunSkillApplication,
  SystemStatus,
  Task,
  Vector,
  api,
  getApiToken,
  setApiToken,
} from "./api";
import { AttackChainPanel } from "./components/panels/AttackChainPanel";
import { HandoffPanel } from "./components/panels/HandoffPanel";
import { SkillPanel } from "./components/panels/SkillPanel";

const modes = ["pentest", "ctf", "koth", "bugbounty", "windows-ctf", "windows-koth"];
const roles = ["orchestrator", "recon", "knowledge_base", "vector_store", "researcher", "developer", "executor", "reporter"];

export default function App() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [selectedRun, setSelectedRun] = useState<Run | null>(null);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [agents, setAgents] = useState<AgentSession[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [facts, setFacts] = useState<Fact[]>([]);
  const [learning, setLearning] = useState<Array<Record<string, unknown>>>([]);
  const [messages, setMessages] = useState<RunMessage[]>([]);
  const [vectors, setVectors] = useState<Vector[]>([]);
  const [results, setResults] = useState<RunResults | null>(null);
  const [skillApps, setSkillApps] = useState<RunSkillApplication[]>([]);
  const [handoff, setHandoff] = useState<Handoff | null>(null);
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [providers, setProviders] = useState<ProviderConfig[]>([]);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [installStatus, setInstallStatus] = useState<{ ready: boolean; updated_at: string; state: Record<string, unknown> } | null>(null);
  const [tools, setTools] = useState<Array<{ id: string; name: string; installed: boolean; installable: boolean; suites: string[]; version: string; path: string }>>([]);
  const [toolSuites, setToolSuites] = useState<Record<string, unknown>>({});
  const [selectedToolSuite, setSelectedToolSuite] = useState("common");
  const [chatText, setChatText] = useState("Full test of 10.10.10.10");
  const [note, setNote] = useState("");
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("pentest");
  const [apiToken, setApiTokenState] = useState(getApiToken());
  const [providerForm, setProviderForm] = useState({ name: "OpenAI", provider_type: "openai", default_model: "", base_url: "", secret: "" });
  const [statusMessage, setStatusMessage] = useState("");
  const streamRef = useRef<EventSource | null>(null);

  async function refreshRuns() {
    setRuns(await api.listRuns());
  }

  async function refreshSystem() {
    try {
      const [status, providerRows, install, toolRows, suites] = await Promise.all([
        api.systemStatus(),
        api.listProviders(),
        api.installStatus(),
        api.listTools(),
        api.listToolSuites(),
      ]);
      setSystemStatus(status);
      setProviders(providerRows);
      setInstallStatus(install);
      setTools(toolRows.map((tool) => ({
        id: tool.id,
        name: tool.name,
        installed: tool.installed,
        installable: tool.installable,
        suites: tool.suites,
        version: tool.version,
        path: tool.path,
      })));
      setToolSuites(suites);
      if (!selectedToolSuite && Object.keys(suites).length) {
        setSelectedToolSuite(Object.keys(suites)[0]);
      }
    } catch (error) {
      console.error(error);
    }
  }

  async function refreshRun(runId: string) {
    try {
      const [run, graph, runFacts, learningHits, runMessages, runVectors, runResults, runSkills, runHandoff, chains] = await Promise.all([
        api.getRun(runId),
        api.getGraph(runId),
        api.getFacts(runId),
        api.getLearning(runId),
        api.getMessages(runId),
        api.getVectors(runId),
        api.getResults(runId),
        api.getSkills(runId),
        api.getHandoff(runId),
        api.getAttackChains(runId),
      ]);
      setSelectedRun(run);
      setTasks(graph.tasks);
      setAgents(graph.agents);
      setApprovals(graph.approvals);
      setFacts(runFacts);
      setLearning(learningHits.results);
      setMessages(runMessages);
      setVectors(runVectors);
      setResults(runResults);
      setSkillApps(runSkills);
      setHandoff(runHandoff);
      setAttackChains(chains);
      setStatusMessage("");
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        streamRef.current?.close();
        clearRunState("The selected run no longer exists. Pick a fresh run.");
        await refreshRuns();
        return;
      }
      throw error;
    }
  }

  function clearRunState(message = "") {
    setSelectedRun(null);
    setTasks([]);
    setAgents([]);
    setApprovals([]);
    setFacts([]);
    setLearning([]);
    setMessages([]);
    setVectors([]);
    setResults(null);
    setSkillApps([]);
    setHandoff(null);
    setAttackChains([]);
    setEvents([]);
    setStatusMessage(message);
  }

  useEffect(() => {
    refreshRuns().catch(console.error);
    refreshSystem().catch(console.error);
  }, []);

  useEffect(() => {
    if (!selectedRun) {
      streamRef.current?.close();
      return;
    }
    refreshRun(selectedRun.id).catch(console.error);
    streamRef.current?.close();
    if (apiToken) {
      const interval = window.setInterval(() => refreshRun(selectedRun.id).catch(console.error), 2000);
      return () => window.clearInterval(interval);
    }
    const source = new EventSource(`/api/v1/runs/${selectedRun.id}/stream`);
    source.onmessage = (event) => {
      const data = JSON.parse(event.data) as EventRecord;
      setEvents((current) => [...current.slice(-199), data]);
      if (data.event_type !== "terminal") refreshRun(selectedRun.id).catch(console.error);
    };
    source.onerror = () => {
      source.close();
      refreshRun(selectedRun.id).catch(console.error);
    };
    streamRef.current = source;
    return () => source.close();
  }, [selectedRun?.id, apiToken]);

  async function sendChat(event: FormEvent) {
    event.preventDefault();
    if (!chatText.trim()) return;
    try {
      const response = await api.submitChat({ message: chatText, run_id: selectedRun?.id, mode, target: selectedRun ? undefined : target || undefined });
      setChatText("");
      setEvents([]);
      setSelectedRun(response.run);
      setStatusMessage(response.scheduler_status);
      await refreshRuns();
      await refreshRun(response.run.id);
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : String(error));
    }
  }

  async function saveProvider(event: FormEvent) {
    event.preventDefault();
    try {
      await api.saveProvider(providerForm);
      setProviderForm({ ...providerForm, secret: "" });
      await refreshSystem();
      setStatusMessage("Provider saved. Codex remains the default runtime until a run explicitly selects a provider.");
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : String(error));
    }
  }

  const terminalText = useMemo(() => {
    const streamed = events.filter((entry) => entry.event_type === "terminal").map((entry) => entry.message);
    if (streamed.length) return streamed.join("\n");
    return results?.terminal_summary || "No live terminal output yet.";
  }, [events, results]);

  const cveFacts = facts.filter((fact) => fact.kind === "cve");

  return (
    <div className="vantix-shell">
      <RunSidebar
        runs={runs}
        selectedRun={selectedRun}
        mode={mode}
        setMode={setMode}
        target={target}
        setTarget={setTarget}
        onSelect={(run) => {
          setEvents([]);
          setSelectedRun(run);
        }}
      />
      <main className="workspace">
        <TopBar
          selectedRun={selectedRun}
          systemStatus={systemStatus}
          statusMessage={statusMessage}
          onRefresh={() => selectedRun && refreshRun(selectedRun.id)}
          onPause={() => selectedRun && api.pauseRun(selectedRun.id).then(() => refreshRun(selectedRun.id))}
          onRetry={() => selectedRun && api.retryRun(selectedRun.id).then(() => refreshRun(selectedRun.id))}
          onReplan={() => selectedRun && api.replanRun(selectedRun.id).then(() => refreshRun(selectedRun.id))}
          onCancel={() => selectedRun && api.cancelRun(selectedRun.id).then(() => refreshRun(selectedRun.id))}
        />
        <section className="command-grid">
          <OrchestratorChat messages={messages} chatText={chatText} setChatText={setChatText} onSend={sendChat} />
          <AgentTimeline agents={agents} tasks={tasks} />
          <TerminalPanel terminalText={terminalText} />
          <SkillPanel applications={skillApps} selectedRun={selectedRun} onApply={() => selectedRun && api.applySkills(selectedRun.id).then(() => refreshRun(selectedRun.id))} />
          <HandoffPanel handoff={handoff} />
          <AttackChainPanel chains={attackChains} />
          <TargetPanel selectedRun={selectedRun} facts={facts} />
          <VectorPanel vectors={vectors} selectedRun={selectedRun} onSelect={(vector) => selectedRun && api.selectVector(selectedRun.id, vector.id).then(() => refreshRun(selectedRun.id))} />
          <MemoryPanel learning={learning} />
          <CveIntelPanel cveFacts={cveFacts} />
          <ResultsPanel results={results} />
          <ApprovalPanel approvals={approvals} onApprove={(approval) => selectedRun && api.approve(approval.id).then(() => refreshRun(selectedRun.id))} onReject={(approval) => selectedRun && api.reject(approval.id).then(() => refreshRun(selectedRun.id))} />
          <NotesPanel note={note} setNote={setNote} selectedRun={selectedRun} onSaved={() => selectedRun && refreshRun(selectedRun.id)} />
          <InstallerPanel
            systemStatus={systemStatus}
            installStatus={installStatus}
            tools={tools}
            suites={toolSuites}
            selectedSuite={selectedToolSuite}
            setSelectedSuite={setSelectedToolSuite}
            onRefresh={() => refreshSystem().catch(console.error)}
            onInstallSuite={async (suite) => {
              await api.installTools({ suite, apply: true });
              await refreshSystem();
              setStatusMessage(`Tool suite install triggered: ${suite}`);
            }}
          />
          <ProviderSettings
            apiToken={apiToken}
            setApiToken={(token) => {
              setApiTokenState(token);
              setApiToken(token);
              refreshSystem().catch(console.error);
            }}
            providers={providers}
            providerForm={providerForm}
            setProviderForm={setProviderForm}
            onSave={saveProvider}
          />
        </section>
      </main>
    </div>
  );
}

function RunSidebar(props: { runs: Run[]; selectedRun: Run | null; mode: string; setMode: (mode: string) => void; target: string; setTarget: (target: string) => void; onSelect: (run: Run) => void }) {
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
            {modes.map((value) => <option key={value} value={value}>{value}</option>)}
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

function TopBar(props: { selectedRun: Run | null; systemStatus: SystemStatus | null; statusMessage: string; onRefresh: () => void; onPause: () => void; onRetry: () => void; onReplan: () => void; onCancel: () => void }) {
  return (
    <section className="topbar card">
      <div>
        <span className="eyebrow">Vantix Orchestrator</span>
        <h2>{props.selectedRun ? props.selectedRun.workspace_id : "No active run"}</h2>
        <p>{props.selectedRun ? `${props.selectedRun.mode} / ${props.selectedRun.status} / ${props.selectedRun.target}` : "Type a target and objective in chat to start."}</p>
        {props.statusMessage ? <p className="status-line">{props.statusMessage}</p> : null}
      </div>
      <div className="status-stack">
        <span className={props.systemStatus?.codex?.available ? "pill ok" : "pill warn"}>Codex {props.systemStatus?.codex?.available ? "ready" : "unavailable"}</span>
        {props.selectedRun ? <div className="controls"><button onClick={props.onRefresh}>Refresh</button><button onClick={props.onPause}>Pause</button><button onClick={props.onRetry}>Retry</button><button onClick={props.onReplan}>Replan</button><button onClick={props.onCancel}>Cancel</button></div> : null}
      </div>
    </section>
  );
}

function OrchestratorChat(props: { messages: RunMessage[]; chatText: string; setChatText: (value: string) => void; onSend: (event: FormEvent) => void }) {
  return (
    <article className="panel chat-panel">
      <header><h3>Orchestrator Chat</h3><span>Chat creates or replans runs</span></header>
      <div className="messages">
        {props.messages.length ? props.messages.map((message) => (
          <div key={message.id} className={`message ${message.role}`}>
            <strong>{message.author || message.role}</strong>
            <p>{message.content}</p>
          </div>
        )) : <p className="empty">Ask for a full test of a target to initialize Vantix.</p>}
      </div>
      <form className="chat-input" onSubmit={props.onSend}>
        <textarea value={props.chatText} onChange={(event) => props.setChatText(event.target.value)} placeholder="Full test of 10.10.10.10" />
        <button type="submit">Send to Vantix</button>
      </form>
    </article>
  );
}

function AgentTimeline(props: { agents: AgentSession[]; tasks: Task[] }) {
  return (
    <article className="panel">
      <header><h3>Specialists</h3><span>Scheduler roles</span></header>
      <div className="agent-grid">
        {roles.map((role) => {
          const agent = props.agents.find((item) => item.role === role);
          const task = props.tasks.find((item) => item.kind.includes(role.replace("_", "-")) || item.kind.includes(role));
          return <div key={role} className={`agent ${agent?.status || "pending"}`}><strong>{role.replace("_", " ")}</strong><span>{agent?.status || task?.status || "pending"}</span></div>;
        })}
      </div>
    </article>
  );
}

function TerminalPanel({ terminalText }: { terminalText: string }) {
  return <article className="panel terminal"><header><h3>Live Terminal</h3><span>Runtime stream</span></header><pre>{terminalText}</pre></article>;
}

function TargetPanel({ selectedRun, facts }: { selectedRun: Run | null; facts: Fact[] }) {
  return <article className="panel"><header><h3>Target</h3><span>Profile</span></header>{selectedRun ? <><p><strong>{selectedRun.target}</strong></p><p>{selectedRun.objective}</p></> : <p className="empty">No target selected.</p>}<List items={facts.slice(0, 6).map((fact) => `${fact.kind}: ${fact.value}`)} /></article>;
}

function VectorPanel({ vectors, selectedRun, onSelect }: { vectors: Vector[]; selectedRun: Run | null; onSelect: (vector: Vector) => void }) {
  return <article className="panel"><header><h3>Vectors</h3><span>{vectors.length} candidates</span></header><ul>{vectors.map((vector) => <li key={vector.id}><strong>{vector.title}</strong><span>{vector.source} / {vector.status} / confidence {vector.confidence.toFixed(2)}</span><p>{vector.summary}</p><p>{vector.next_action}</p>{selectedRun ? <button onClick={() => onSelect(vector)}>Select Vector</button> : null}</li>)}</ul>{!vectors.length ? <p className="empty">No candidate vectors yet.</p> : null}</article>;
}

function MemoryPanel({ learning }: { learning: Array<Record<string, unknown>> }) {
  return <article className="panel"><header><h3>Memory</h3><span>Similar experience</span></header><ul>{learning.slice(0, 5).map((item, index) => <li key={index}><strong>{String(item.title ?? "Memory hit")}</strong><span>rank {String(item.rank ?? "")}</span><p>{String(item.summary_short ?? item.summary ?? "")}</p></li>)}</ul>{!learning.length ? <p className="empty">No memory hits loaded.</p> : null}</article>;
}

function CveIntelPanel({ cveFacts }: { cveFacts: Fact[] }) {
  return <article className="panel"><header><h3>CVE Intel</h3><span>{cveFacts.length} facts</span></header><List items={cveFacts.map((fact) => `${fact.value} (${fact.confidence})`)} empty="No CVE facts yet." /></article>;
}

function ResultsPanel({ results }: { results: RunResults | null }) {
  return <article className="panel"><header><h3>Results</h3><span>Evidence and artifacts</span></header>{results ? <><p>Status: {results.status}</p><p>Report: {results.report_path || "not generated"}</p><List items={results.artifacts.slice(0, 6).map((artifact) => `${artifact.kind}: ${artifact.path}`)} empty="No artifacts yet." /></> : <p className="empty">No results yet.</p>}</article>;
}

function ApprovalPanel({ approvals, onApprove, onReject }: { approvals: Approval[]; onApprove: (approval: Approval) => void; onReject: (approval: Approval) => void }) {
  return <article className="panel"><header><h3>Approvals</h3><span>{approvals.length} queued</span></header><ul>{approvals.map((approval) => <li key={approval.id}><strong>{approval.title}</strong><span>{approval.status} / {approval.reason}</span><p>{approval.detail}</p><div className="approval-actions"><button onClick={() => onApprove(approval)}>Approve</button><button onClick={() => onReject(approval)}>Reject</button></div></li>)}</ul>{!approvals.length ? <p className="empty">No approvals pending.</p> : null}</article>;
}

function NotesPanel(props: { note: string; setNote: (value: string) => void; selectedRun: Run | null; onSaved: () => void }) {
  return <article className="panel"><header><h3>Operator Notes</h3><span>Human guidance</span></header><textarea value={props.note} onChange={(event) => props.setNote(event.target.value)} placeholder="Add guidance when the run gets stuck." /><button onClick={() => { if (!props.selectedRun || !props.note.trim()) return; api.addNote(props.selectedRun.id, props.note).then(() => { props.setNote(""); props.onSaved(); }); }}>Send Note</button></article>;
}

function ProviderSettings(props: { apiToken: string; setApiToken: (token: string) => void; providers: ProviderConfig[]; providerForm: { name: string; provider_type: string; default_model: string; base_url: string; secret: string }; setProviderForm: (value: { name: string; provider_type: string; default_model: string; base_url: string; secret: string }) => void; onSave: (event: FormEvent) => void }) {
  return <article className="panel settings-panel"><header><h3>Runtime Settings</h3><span>Codex first, APIs optional</span></header><label>UI API token<input value={props.apiToken} onChange={(event) => props.setApiToken(event.target.value)} placeholder="Bearer token for protected APIs" /></label><form className="provider-form" onSubmit={props.onSave}><label>Name<input value={props.providerForm.name} onChange={(event) => props.setProviderForm({ ...props.providerForm, name: event.target.value })} /></label><label>Type<select value={props.providerForm.provider_type} onChange={(event) => props.setProviderForm({ ...props.providerForm, provider_type: event.target.value })}>{["openai", "anthropic", "gemini", "ollama", "bedrock", "deepseek", "glm", "kimi", "qwen", "openrouter", "custom"].map((item) => <option key={item} value={item}>{item}</option>)}</select></label><label>Model<input value={props.providerForm.default_model} onChange={(event) => props.setProviderForm({ ...props.providerForm, default_model: event.target.value })} /></label><label>Base URL<input value={props.providerForm.base_url} onChange={(event) => props.setProviderForm({ ...props.providerForm, base_url: event.target.value })} /></label><label>Secret<input type="password" value={props.providerForm.secret} onChange={(event) => props.setProviderForm({ ...props.providerForm, secret: event.target.value })} placeholder="requires VANTIX_SECRET_KEY" /></label><button type="submit">Save Provider</button></form><List items={props.providers.map((provider) => `${provider.name}: ${provider.provider_type} / ${provider.enabled ? "enabled" : "disabled"} / key=${provider.has_key ? "yes" : "no"}`)} empty="No optional providers configured." /></article>;
}

function InstallerPanel(props: {
  systemStatus: SystemStatus | null;
  installStatus: { ready: boolean; updated_at: string; state: Record<string, unknown> } | null;
  tools: Array<{ id: string; name: string; installed: boolean; installable: boolean; suites: string[]; version: string; path: string }>;
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

function List({ items, empty = "No records." }: { items: string[]; empty?: string }) {
  if (!items.length) return <p className="empty">{empty}</p>;
  return <ul>{items.map((item, index) => <li key={`${item}-${index}`}><span>{item}</span></li>)}</ul>;
}
