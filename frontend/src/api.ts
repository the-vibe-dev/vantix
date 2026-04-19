export type Engagement = {
  id: string;
  name: string;
  mode: string;
  target: string;
  status: string;
};

export type Run = {
  id: string;
  engagement_id: string;
  mode: string;
  workspace_id: string;
  status: string;
  objective: string;
  target: string;
  config: Record<string, unknown>;
};

export type Task = {
  id: string;
  name: string;
  kind: string;
  status: string;
  sequence: number;
  result: Record<string, unknown>;
};

export type Approval = {
  id: string;
  title: string;
  detail: string;
  status: string;
  reason: string;
};

export type AgentSession = {
  id: string;
  role: string;
  name: string;
  status: string;
  workspace_path: string;
  log_path: string;
  metadata?: Record<string, unknown>;
};

export type Fact = {
  id: string;
  source: string;
  kind: string;
  value: string;
  confidence: number;
  tags: string[];
  metadata: Record<string, unknown>;
};

export type Artifact = {
  id: string;
  kind: string;
  path: string;
  metadata: Record<string, unknown>;
};

export type Finding = {
  id: string;
  title: string;
  severity: string;
  status: string;
  summary: string;
  evidence: string;
  confidence: number;
};

export type EventRecord = {
  id: string;
  sequence: number;
  event_type: string;
  level: string;
  message: string;
  payload: Record<string, unknown>;
  created_at: string;
};

export type RunMessage = {
  id: string;
  run_id: string;
  role: "user" | "orchestrator" | "agent" | "system" | string;
  author: string;
  content: string;
  metadata: Record<string, unknown>;
  created_at: string;
};

export type Vector = {
  id: string;
  title: string;
  summary: string;
  source: string;
  confidence: number;
  severity: string;
  status: string;
  evidence: string;
  next_action: string;
  metadata: Record<string, unknown>;
  created_at: string;
};

export type RunResults = {
  run_id: string;
  status: string;
  findings: Finding[];
  artifacts: Artifact[];
  vectors: Vector[];
  terminal_summary: string;
  report_path: string | null;
};

export type SkillPack = {
  id: string;
  name: string;
  version: number;
  summary: string;
  roles: string[];
  modes: string[];
  execution_level: string;
  safety_level: string;
  tags: string[];
  requires_scope: boolean;
  forbidden: string[];
  reason: string;
};

export type RunSkillApplication = {
  agent_role: string;
  skills: SkillPack[];
  prompt_path: string;
};

export type AttackChain = {
  id: string;
  name: string;
  score: number;
  status: string;
  steps: Array<Record<string, unknown>>;
  mitre_ids: string[];
  notes: string;
  created_at: string;
};

export type Handoff = {
  run_id: string;
  workspace_id: string;
  mode: string;
  status: string;
  target: string;
  objective: string;
  scope: string;
  phase: string;
  services: Array<Record<string, unknown>>;
  vectors: Array<Record<string, unknown>>;
  validated_findings: Array<Record<string, unknown>>;
  blocked_items: string[];
  attack_chains: AttackChain[];
  next_actions: string[];
};

export type SystemStatus = {
  product: string;
  version: string;
  default_runtime: string;
  codex: Record<string, unknown>;
  execution: Record<string, unknown>;
  runtime: Record<string, unknown>;
  artifacts: Record<string, unknown>;
  memory: Record<string, unknown>;
  cve_mcp: Record<string, unknown>;
  providers: Record<string, unknown>;
  installer: Record<string, unknown>;
  tooling: Record<string, unknown>;
  warnings: string[];
};

export type ToolStatus = {
  id: string;
  name: string;
  binaries: string[];
  suites: string[];
  method: string;
  installed: boolean;
  binary: string;
  path: string;
  version: string;
  installable: boolean;
  allow_auto_install: boolean;
  last_result: Record<string, unknown>;
};

export type ProviderConfig = {
  id: string;
  name: string;
  provider_type: string;
  base_url: string;
  default_model: string;
  enabled: boolean;
  has_key: boolean;
  metadata: Record<string, unknown>;
};

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, statusText: string, detail = "") {
    super(`${status} ${statusText}${detail ? `: ${detail}` : ""}`);
    this.status = status;
    this.detail = detail;
  }
}

export function getApiToken(): string {
  return localStorage.getItem("vantix_api_token") || "";
}

export function setApiToken(token: string): void {
  if (token.trim()) localStorage.setItem("vantix_api_token", token.trim());
  else localStorage.removeItem("vantix_api_token");
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getApiToken();
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers || {}),
    },
    ...init,
  });
  if (!response.ok) {
    let detail = "";
    try {
      const payload = await response.json();
      detail = String(payload?.detail ?? "");
    } catch {
      detail = "";
    }
    throw new ApiError(response.status, response.statusText, detail);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  listModes: () => request<Array<Record<string, unknown>>>("/api/v1/modes"),
  systemStatus: () => request<SystemStatus>("/api/v1/system/status"),
  installStatus: () => request<{ ready: boolean; updated_at: string; state: Record<string, unknown> }>("/api/v1/system/install-status"),
  listTools: (suite = "") => request<ToolStatus[]>(`/api/v1/tools${suite ? `?suite=${encodeURIComponent(suite)}` : ""}`),
  listToolSuites: () => request<Record<string, unknown>>("/api/v1/tools/suites"),
  installTools: (payload: { tool_ids?: string[]; suite?: string; apply?: boolean }) =>
    request<Array<Record<string, unknown>>>("/api/v1/tools/install", { method: "POST", body: JSON.stringify(payload) }),
  toolInstallHistory: () => request<Array<Record<string, unknown>>>("/api/v1/tools/install/history"),
  listEngagements: () => request<Engagement[]>("/api/v1/engagements"),
  listRuns: () => request<Run[]>("/api/v1/runs"),
  createEngagement: (payload: Record<string, unknown>) =>
    request<Engagement>("/api/v1/engagements", { method: "POST", body: JSON.stringify(payload) }),
  createRun: (payload: Record<string, unknown>) =>
    request<Run>("/api/v1/runs", { method: "POST", body: JSON.stringify(payload) }),
  submitChat: (payload: { message: string; run_id?: string; mode?: string; target?: string; metadata?: Record<string, unknown> }) =>
    request<{ run: Run; message: RunMessage; started: boolean; scheduler_status: string }>("/api/v1/chat", { method: "POST", body: JSON.stringify(payload) }),
  getRun: (runId: string) => request<Run>(`/api/v1/runs/${runId}`),
  getGraph: (runId: string) => request<{ run_id: string; status: string; tasks: Task[]; agents: AgentSession[]; approvals: Approval[] }>(`/api/v1/runs/${runId}/graph`),
  getMessages: (runId: string) => request<RunMessage[]>(`/api/v1/runs/${runId}/messages`),
  getLearning: (runId: string) => request<{ run_id: string; mode: string; results: Array<Record<string, unknown>> }>(`/api/v1/runs/${runId}/learning`),
  getFacts: (runId: string) => request<Fact[]>(`/api/v1/runs/${runId}/facts`),
  getVectors: (runId: string) => request<Vector[]>(`/api/v1/runs/${runId}/vectors`),
  createVector: (runId: string, payload: Partial<Vector>) =>
    request<Vector>(`/api/v1/runs/${runId}/vectors`, { method: "POST", body: JSON.stringify(payload) }),
  selectVector: (runId: string, vectorId: string) =>
    request<Vector>(`/api/v1/runs/${runId}/vectors/${vectorId}/select`, { method: "POST" }),
  getResults: (runId: string) => request<RunResults>(`/api/v1/runs/${runId}/results`),
  listSkills: () => request<SkillPack[]>("/api/v1/skills"),
  getSkills: (runId: string) => request<RunSkillApplication[]>(`/api/v1/runs/${runId}/skills`),
  applySkills: (runId: string) => request<RunSkillApplication[]>(`/api/v1/runs/${runId}/skills/apply`, { method: "POST" }),
  getHandoff: (runId: string) => request<Handoff>(`/api/v1/runs/${runId}/handoff`),
  getAttackChains: (runId: string) => request<AttackChain[]>(`/api/v1/runs/${runId}/attack-chains`),
  createAttackChain: (runId: string, payload: Partial<AttackChain>) =>
    request<AttackChain>(`/api/v1/runs/${runId}/attack-chains`, { method: "POST", body: JSON.stringify(payload) }),
  getTerminal: (runId: string) => request<{ run_id: string; content: string }>(`/api/v1/runs/${runId}/terminal`),
  startRun: (runId: string) => request<{ message: string }>(`/api/v1/runs/${runId}/start`, { method: "POST" }),
  pauseRun: (runId: string) => request<{ message: string }>(`/api/v1/runs/${runId}/pause`, { method: "POST" }),
  retryRun: (runId: string) => request<{ message: string }>(`/api/v1/runs/${runId}/retry`, { method: "POST" }),
  replanRun: (runId: string) => request<{ message: string }>(`/api/v1/runs/${runId}/replan`, { method: "POST" }),
  cancelRun: (runId: string) => request<{ message: string }>(`/api/v1/runs/${runId}/cancel`, { method: "POST" }),
  addNote: (runId: string, content: string) =>
    request(`/api/v1/runs/${runId}/operator-notes`, { method: "POST", body: JSON.stringify({ content }) }),
  approve: (approvalId: string, note = "") =>
    request(`/api/v1/approvals/${approvalId}/approve`, { method: "POST", body: JSON.stringify({ note }) }),
  reject: (approvalId: string, note = "") =>
    request(`/api/v1/approvals/${approvalId}/reject`, { method: "POST", body: JSON.stringify({ note }) }),
  listProviders: () => request<ProviderConfig[]>("/api/v1/providers"),
  saveProvider: (payload: Record<string, unknown>) =>
    request<ProviderConfig>("/api/v1/providers", { method: "POST", body: JSON.stringify(payload) }),
  testProvider: (providerId: string) => request<Record<string, unknown>>(`/api/v1/providers/${providerId}/test`, { method: "POST" }),
};
