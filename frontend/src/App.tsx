import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  AgentSession,
  ApiError,
  Approval,
  AttackChain,
  EventRecord,
  Fact,
  Handoff,
  ProviderConfig,
  Run,
  RunMessage,
  RunPhase,
  RunResults,
  RunSkillApplication,
  SystemStatus,
  Task,
  Vector,
  api,
  getApiToken,
  setApiToken,
} from "./api";
import { RunSidebar } from "./components/layout/RunSidebar";
import { TopBar } from "./components/layout/TopBar";
import { AgentTimeline } from "./components/panels/AgentTimeline";
import { ApprovalPanel } from "./components/panels/ApprovalPanel";
import { AttackChainPanel } from "./components/panels/AttackChainPanel";
import { CveIntelPanel } from "./components/panels/CveIntelPanel";
import { HandoffPanel } from "./components/panels/HandoffPanel";
import { InstallerPanel } from "./components/panels/InstallerPanel";
import { MemoryPanel } from "./components/panels/MemoryPanel";
import { NotesPanel } from "./components/panels/NotesPanel";
import { OrchestratorChat } from "./components/panels/OrchestratorChat";
import { ProviderSettings } from "./components/panels/ProviderSettings";
import { ResultsPanel } from "./components/panels/ResultsPanel";
import { RunPhasePanel } from "./components/panels/RunPhasePanel";
import { SkillPanel } from "./components/panels/SkillPanel";
import { TargetPanel } from "./components/panels/TargetPanel";
import { TerminalPanel } from "./components/panels/TerminalPanel";
import { VectorPanel } from "./components/panels/VectorPanel";

const modes = ["pentest", "ctf", "koth", "bugbounty", "windows-ctf", "windows-koth"];
const roles = ["orchestrator", "recon", "knowledge_base", "vector_store", "researcher", "developer", "executor", "reporter"];

type InstallStatus = { ready: boolean; updated_at: string; state: Record<string, unknown> };
type ToolRow = { id: string; name: string; installed: boolean; installable: boolean; suites: string[]; version: string; path: string };

export default function App() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [selectedRun, setSelectedRun] = useState<Run | null>(null);
  const [phase, setPhase] = useState<RunPhase | null>(null);
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
  const [installStatus, setInstallStatus] = useState<InstallStatus | null>(null);
  const [tools, setTools] = useState<ToolRow[]>([]);
  const [toolSuites, setToolSuites] = useState<Record<string, unknown>>({});
  const [selectedToolSuite, setSelectedToolSuite] = useState("common");
  const [chatText, setChatText] = useState("Full test of 10.10.10.10");
  const [note, setNote] = useState("");
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("pentest");
  const [apiToken, setApiTokenState] = useState(getApiToken());
  const [routedProviderId, setRoutedProviderId] = useState("");
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
      setTools(toolRows.map((tool) => ({ id: tool.id, name: tool.name, installed: tool.installed, installable: tool.installable, suites: tool.suites, version: tool.version, path: tool.path })));
      setToolSuites(suites);
      if (!selectedToolSuite && Object.keys(suites).length) setSelectedToolSuite(Object.keys(suites)[0]);
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
      setRoutedProviderId(String((run.config?.provider_id as string | undefined) || ""));
      setPhase(graph.phase);
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
    setRoutedProviderId("");
    setPhase(null);
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

  async function promoteVector(vector: Vector) {
    if (!selectedRun) return;
    try {
      await api.promoteFinding(selectedRun.id, { source_kind: "vector", source_id: vector.id, title: vector.title, severity: vector.severity, summary: vector.summary, evidence: vector.evidence });
      await refreshRun(selectedRun.id);
      setStatusMessage(`Promoted vector to finding draft: ${vector.title}`);
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : String(error));
    }
  }

  async function promoteAttackChain(chain: AttackChain) {
    if (!selectedRun) return;
    try {
      await api.promoteFinding(selectedRun.id, { source_kind: "attack_chain", source_id: chain.id, title: chain.name, evidence: chain.notes });
      await refreshRun(selectedRun.id);
      setStatusMessage(`Promoted attack chain to finding draft: ${chain.name}`);
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : String(error));
    }
  }

  async function saveNote() {
    if (!selectedRun || !note.trim()) return;
    try {
      await api.addNote(selectedRun.id, note);
      setNote("");
      await refreshRun(selectedRun.id);
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
        modes={modes}
        onSelect={(run) => {
          setEvents([]);
          setSelectedRun(run);
        }}
      />
      <main className="workspace">
        <TopBar
          selectedRun={selectedRun}
          phase={phase}
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
          <RunPhasePanel phase={phase} />
          <AgentTimeline agents={agents} tasks={tasks} roles={roles} />
          <TerminalPanel terminalText={terminalText} />
          <SkillPanel applications={skillApps} selectedRun={selectedRun} onApply={() => selectedRun && api.applySkills(selectedRun.id).then(() => refreshRun(selectedRun.id))} />
          <HandoffPanel handoff={handoff} />
          <AttackChainPanel chains={attackChains} onPromote={promoteAttackChain} />
          <TargetPanel selectedRun={selectedRun} facts={facts} />
          <VectorPanel vectors={vectors} selectedRun={selectedRun} onSelect={(vector) => selectedRun && api.selectVector(selectedRun.id, vector.id).then(() => refreshRun(selectedRun.id))} onPromote={promoteVector} />
          <MemoryPanel learning={learning} />
          <CveIntelPanel cveFacts={cveFacts} />
          <ResultsPanel results={results} />
          <ApprovalPanel approvals={approvals} onApprove={(approval) => selectedRun && api.approve(approval.id).then(() => refreshRun(selectedRun.id))} onReject={(approval) => selectedRun && api.reject(approval.id).then(() => refreshRun(selectedRun.id))} />
          <NotesPanel note={note} setNote={setNote} canSave={Boolean(selectedRun && note.trim())} onSave={saveNote} />
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
            selectedRun={selectedRun}
            routedProviderId={routedProviderId}
            setRoutedProviderId={setRoutedProviderId}
            onRoute={() => {
              if (!selectedRun) return;
              api.routeRunProvider(selectedRun.id, routedProviderId).then((run) => {
                setSelectedRun(run);
                setStatusMessage(routedProviderId ? "Run routed to provider." : "Run routed back to Codex.");
                return refreshRun(run.id);
              }).catch((error) => setStatusMessage(error instanceof Error ? error.message : String(error)));
            }}
            providerForm={providerForm}
            setProviderForm={setProviderForm}
            onSave={saveProvider}
          />
        </section>
      </main>
    </div>
  );
}
