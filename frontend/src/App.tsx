import {
  CSSProperties,
  FormEvent,
  ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  AgentSession,
  ApiError,
  Approval,
  AttackChain,
  AuthUser,
  BrowserState,
  EventRecord,
  Fact,
  Finding,
  ReplayState,
  Run,
  RunMessage,
  RunPhase,
  RunResults,
  RunSkillApplication,
  SourceStatus,
  SourceInput,
  Task,
  Vector,
  WorkflowState,
  api,
  hydrateCsrfFromCookie,
} from "./api";
import Login from "./Login";

// ─── Primitives ──────────────────────────────────────────────────────────────
type Variant =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "ok"
  | "warn"
  | "danger"
  | "amber"
  | "blue"
  | "default";

const SEV: Record<Variant, { bg: string; color: string; border: string }> = {
  critical: { bg: "rgba(239,68,68,.14)", color: "#ff6b6b", border: "rgba(239,68,68,.35)" },
  high: { bg: "rgba(249,115,22,.14)", color: "#f97316", border: "rgba(249,115,22,.35)" },
  medium: { bg: "rgba(244,184,96,.14)", color: "#f4b860", border: "rgba(244,184,96,.35)" },
  low: { bg: "rgba(25,195,125,.12)", color: "#19c37d", border: "rgba(25,195,125,.3)" },
  ok: { bg: "rgba(25,195,125,.12)", color: "#19c37d", border: "rgba(25,195,125,.3)" },
  warn: { bg: "rgba(249,115,22,.12)", color: "#f97316", border: "rgba(249,115,22,.3)" },
  danger: { bg: "rgba(239,68,68,.12)", color: "#ef4444", border: "rgba(239,68,68,.3)" },
  amber: { bg: "rgba(244,184,96,.12)", color: "#f4b860", border: "rgba(244,184,96,.3)" },
  blue: { bg: "rgba(99,179,237,.12)", color: "#63b3ed", border: "rgba(99,179,237,.3)" },
  default: { bg: "rgba(255,255,255,.05)", color: "#a69599", border: "rgba(217,58,73,.25)" },
};

function Badge({
  children,
  variant = "default",
  style,
}: {
  children: ReactNode;
  variant?: Variant;
  style?: CSSProperties;
}) {
  const c = SEV[variant] || SEV.default;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "2px 8px",
        borderRadius: 99,
        fontSize: ".68rem",
        fontWeight: 700,
        letterSpacing: ".07em",
        textTransform: "uppercase",
        background: c.bg,
        color: c.color,
        border: `1px solid ${c.border}`,
        whiteSpace: "nowrap",
        ...style,
      }}
    >
      {children}
    </span>
  );
}

function SevBadge({ severity }: { severity?: string }) {
  const key = (severity || "").toLowerCase();
  const v: Variant = (["critical", "high", "medium", "low"] as Variant[]).includes(key as Variant)
    ? (key as Variant)
    : "default";
  return <Badge variant={v}>{severity || "unknown"}</Badge>;
}

function StatusDot({ status, size = 8 }: { status?: string; size?: number }) {
  const cols: Record<string, string> = {
    running: "#f4b860",
    completed: "#19c37d",
    failed: "#ef4444",
    blocked: "#ef4444",
    pending: "rgba(140,185,165,.3)",
    idle: "rgba(140,185,165,.3)",
  };
  const color = cols[status || ""] || cols.idle;
  const pulse = status === "running";
  return (
    <span
      style={{
        position: "relative",
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        width: size,
        height: size,
        flexShrink: 0,
      }}
    >
      {pulse && (
        <span
          style={{
            position: "absolute",
            inset: -3,
            borderRadius: "50%",
            background: color,
            opacity: 0.35,
            animation: "vx-pulse 1.8s ease-in-out infinite",
          }}
        />
      )}
      <span
        style={{ width: size, height: size, borderRadius: "50%", background: color, display: "block" }}
      />
    </span>
  );
}

function ConfBar({ value, max = 1 }: { value: number; max?: number }) {
  const pct = Math.round(Math.min(value / max, 1) * 100);
  const color = pct >= 80 ? "#19c37d" : pct >= 50 ? "#f4b860" : "#ef4444";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div
        style={{
          flex: 1,
          height: 3,
          background: "rgba(255,255,255,.07)",
          borderRadius: 99,
          overflow: "hidden",
        }}
      >
        <div
          style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 99, transition: "width .5s ease" }}
        />
      </div>
      <span
        style={{
          fontSize: ".7rem",
          color: "#7a9e92",
          minWidth: 28,
          textAlign: "right",
          fontFamily: "var(--mono)",
        }}
      >
        {pct}%
      </span>
    </div>
  );
}

function EmptyState({ icon = "◌", text }: { icon?: string; text: string }) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 8,
        padding: "28px 0",
        color: "#7a9e92",
      }}
    >
      <span style={{ fontSize: "1.4rem", opacity: 0.3 }}>{icon}</span>
      <span style={{ fontSize: ".78rem" }}>{text}</span>
    </div>
  );
}

function Spinner() {
  return (
    <div
      style={{
        width: 16,
        height: 16,
        border: "2px solid rgba(25,195,125,.2)",
        borderTopColor: "#19c37d",
        borderRadius: "50%",
        animation: "vx-spin .7s linear infinite",
      }}
    />
  );
}

type BtnVariant = "primary" | "ghost" | "danger" | "amber" | "green" | "blue";
type BtnSize = "xs" | "sm" | "md" | "lg";

function Btn({
  children,
  onClick,
  variant = "primary",
  size = "md",
  disabled = false,
  type = "button",
  style,
}: {
  children: ReactNode;
  onClick?: (e: React.MouseEvent<HTMLButtonElement>) => void;
  variant?: BtnVariant;
  size?: BtnSize;
  disabled?: boolean;
  type?: "button" | "submit";
  style?: CSSProperties;
}) {
  const vs: Record<BtnVariant, CSSProperties> = {
    primary: { background: "linear-gradient(135deg,#d93a49,#ef5c67)", color: "#140507", border: "none" },
    ghost: { background: "rgba(255,255,255,.04)", color: "#e8f4ee", border: "1px solid rgba(217,58,73,.25)" },
    danger: { background: "rgba(239,68,68,.1)", color: "#ef4444", border: "1px solid rgba(239,68,68,.3)" },
    amber: { background: "rgba(244,184,96,.1)", color: "#f4b860", border: "1px solid rgba(244,184,96,.3)" },
    green: { background: "rgba(25,195,125,.1)", color: "#19c37d", border: "1px solid rgba(25,195,125,.3)" },
    blue: { background: "rgba(96,165,250,.1)", color: "#60a5fa", border: "1px solid rgba(96,165,250,.3)" },
  };
  const ss: Record<BtnSize, CSSProperties> = {
    xs: { padding: "3px 8px", fontSize: ".68rem", borderRadius: 6 },
    sm: { padding: "5px 10px", fontSize: ".72rem", borderRadius: 7 },
    md: { padding: "8px 14px", fontSize: ".78rem", borderRadius: 8 },
    lg: { padding: "11px 20px", fontSize: ".84rem", borderRadius: 8 },
  };
  const [hov, setHov] = useState(false);
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        ...vs[variant],
        ...ss[size],
        fontWeight: 600,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
        transition: "filter .15s",
        letterSpacing: ".02em",
        filter: hov && !disabled ? "brightness(1.12)" : "none",
        ...style,
      }}
    >
      {children}
    </button>
  );
}

function Label({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        fontSize: ".67rem",
        fontWeight: 700,
        letterSpacing: ".1em",
        textTransform: "uppercase",
        color: "#7a9e92",
        marginBottom: 6,
      }}
    >
      {children}
    </div>
  );
}

function Panel({
  title,
  meta,
  action,
  children,
  style,
  loading = false,
}: {
  title: string;
  meta?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  style?: CSSProperties;
  loading?: boolean;
}) {
  return (
    <article className="vx-panel" style={style}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          marginBottom: 14,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span
            style={{
              fontSize: ".72rem",
              fontWeight: 700,
              letterSpacing: ".09em",
              textTransform: "uppercase",
              color: "#e8f4ee",
            }}
          >
            {title}
          </span>
          {meta && <span style={{ fontSize: ".72rem", color: "#7a9e92" }}>{meta}</span>}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {loading && <Spinner />}
          {action}
        </div>
      </div>
      {children}
    </article>
  );
}

// ─── Static lists ───────────────────────────────────────────────────────────
const ROLES = ["orchestrator", "recon", "browser", "knowledge_base", "vector_store", "researcher", "developer", "executor", "reporter"];
const MODES = ["pentest", "ctf", "koth", "bugbounty", "windows-ctf", "windows-koth"];
const DISPLAY_PHASES = ["init", "recon", "exploit", "validate", "post-exploit", "report"] as const;
type DisplayPhase = (typeof DISPLAY_PHASES)[number];

const PHASE_ALIAS: Record<string, DisplayPhase | "completed"> = {
  "flow-initialization": "init",
  "context-bootstrap": "init",
  "source-intake": "init",
  "source-analysis": "init",
  "learning-recall": "recon",
  recon: "recon",
  "recon-sidecar": "recon",
  "browser-assessment": "recon",
  "knowledge-load": "recon",
  "vector-store": "exploit",
  research: "exploit",
  "cve-analysis": "exploit",
  planning: "validate",
  development: "validate",
  orchestrate: "validate",
  execution: "post-exploit",
  "learn-ingest": "post-exploit",
  "post-exploit": "post-exploit",
  report: "report",
  reporting: "report",
  completed: "completed",
};

function toDisplayPhase(value: string | undefined): DisplayPhase | "completed" {
  return PHASE_ALIAS[String(value || "").toLowerCase()] || "init";
}

function normalizeCompletedPhases(values: string[] | undefined): DisplayPhase[] {
  const out = new Set<DisplayPhase>();
  for (const raw of values || []) {
    const mapped = toDisplayPhase(raw);
    if (mapped !== "completed") out.add(mapped);
  }
  return DISPLAY_PHASES.filter((name) => out.has(name));
}

function eventToChatMessage(event: EventRecord): RunMessage | null {
  if (
    ![
      "phase_transition",
      "approval_requested",
      "approval_resolved",
      "run_status",
      "policy_decision",
      "agent_status",
      "scheduler",
      "vector_generated",
      "attack_chain_generated",
      "finding_promoted",
      "report_generated",
      "browser_observation",
    ].includes(event.event_type)
  )
    return null;
  return {
    id: `e-${event.id}`,
    run_id: "",
    role: "system",
    author: "System",
    content: event.message,
    metadata: { event_type: event.event_type, level: event.level, ...(event.payload || {}) },
    created_at: event.created_at,
  };
}

function mergeTimeline(messages: RunMessage[], events: EventRecord[]): RunMessage[] {
  const merged = [...messages];
  const seen = new Set(messages.map((item) => item.id));
  for (const event of events) {
    const mapped = eventToChatMessage(event);
    if (!mapped) continue;
    if (seen.has(mapped.id)) continue;
    seen.add(mapped.id);
    merged.push(mapped);
  }
  return merged.sort((a, b) => {
    const left = new Date(a.created_at || 0).getTime();
    const right = new Date(b.created_at || 0).getTime();
    return left - right;
  });
}

const EVENT_LABELS: Record<string, string> = {
  phase_transition: "Phase",
  approval_requested: "Approval",
  approval_resolved: "Approval",
  policy_decision: "Policy",
  agent_status: "Agent",
  scheduler: "Scheduler",
  vector_generated: "Vector",
  attack_chain_generated: "Chain",
  finding_promoted: "Finding",
  report_generated: "Report",
  browser_observation: "Browser",
  run_status: "Run",
};

function eventBadgeVariant(eventType: string): Variant {
  if (eventType.startsWith("approval")) return "warn";
  if (eventType === "policy_decision") return "amber";
  if (eventType === "finding_promoted") return "danger";
  if (eventType === "report_generated") return "ok";
  if (eventType === "vector_generated" || eventType === "attack_chain_generated") return "blue";
  if (eventType === "browser_observation") return "amber";
  return "default";
}

function metricNumber(workflowState: WorkflowState | null, key: string): number {
  const value = workflowState?.metrics?.[key];
  return typeof value === "number" ? value : Number(value || 0);
}

// ─── Risk calculation ───────────────────────────────────────────────────────
function calcRisk(findings: Finding[]): { score: string; level: string; variant: Variant } | null {
  if (!findings.length) return null;
  const weights: Record<string, number> = { critical: 10, high: 7, medium: 4, low: 1 };
  const max = findings.length * 10;
  const score = findings.reduce((s, f) => s + (weights[(f.severity || "").toLowerCase()] || 0), 0);
  const pct = score / max;
  const level = pct >= 0.8 ? "Critical" : pct >= 0.6 ? "High" : pct >= 0.35 ? "Medium" : "Low";
  const variant: Variant = pct >= 0.8 ? "danger" : pct >= 0.6 ? "warn" : pct >= 0.35 ? "amber" : "ok";
  return { score: (pct * 10).toFixed(1), level, variant };
}

// ─── Risk bar ───────────────────────────────────────────────────────────────
function RiskBar({
  run,
  findings,
  phase,
  connected,
}: {
  run: Run | null;
  findings: Finding[];
  phase: RunPhase | null;
  connected: boolean;
}) {
  if (!run) return null;
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => {
    const k = (f.severity || "").toLowerCase();
    if (counts[k] !== undefined) counts[k]++;
  });
  const risk = calcRisk(findings);
  const completed = normalizeCompletedPhases(phase?.completed);
  const currentDisplay = toDisplayPhase(phase?.current);
  const done = completed.length + (currentDisplay === "completed" ? 1 : 0);
  const phasePct = Math.round((done / DISPLAY_PHASES.length) * 100);
  return (
    <div className="vx-riskbar">
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginRight: 8 }}>
        <StatusDot status={run.status} size={7} />
        <span
          style={{ fontFamily: "var(--mono)", fontSize: ".74rem", fontWeight: 600, color: "#e8f4ee" }}
        >
          {run.workspace_id}
        </span>
      </div>
      <div style={{ width: 1, height: 20, background: "rgba(140,185,165,.15)" }} />
      {risk && (
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span
            style={{ fontSize: ".67rem", color: "#7a9e92", textTransform: "uppercase", letterSpacing: ".08em" }}
          >
            Risk
          </span>
          <span
            style={{
              fontFamily: "var(--mono)",
              fontSize: ".9rem",
              fontWeight: 700,
              color: SEV[risk.variant].color,
            }}
          >
            {risk.score}
          </span>
          <Badge variant={risk.variant}>{risk.level}</Badge>
        </div>
      )}
      <div style={{ width: 1, height: 20, background: "rgba(140,185,165,.15)" }} />
      <div style={{ display: "flex", gap: 8 }}>
        {[
          ["critical", "#ff6b6b"],
          ["high", "#f97316"],
          ["medium", "#f4b860"],
          ["low", "#19c37d"],
        ].map(([k, c]) => (
          <div key={k} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <span
              style={{ width: 6, height: 6, borderRadius: "50%", background: c, display: "block", flexShrink: 0 }}
            />
            <span
              style={{
                fontSize: ".72rem",
                color: counts[k] > 0 ? c : "#7a9e92",
                fontWeight: counts[k] > 0 ? 700 : 400,
              }}
            >
              {counts[k]}
            </span>
            <span
              style={{ fontSize: ".67rem", color: "#7a9e92", textTransform: "capitalize" }}
            >
              {k}
            </span>
          </div>
        ))}
      </div>
      <div style={{ width: 1, height: 20, background: "rgba(140,185,165,.15)" }} />
      <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 120 }}>
        <span
          style={{
            fontSize: ".67rem",
            color: "#7a9e92",
            whiteSpace: "nowrap",
            textTransform: "uppercase",
            letterSpacing: ".08em",
          }}
        >
          Progress
        </span>
        <div
          style={{
            flex: 1,
            height: 4,
            background: "rgba(255,255,255,.07)",
            borderRadius: 99,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${phasePct}%`,
              height: "100%",
              background: "#19c37d",
              borderRadius: 99,
              transition: "width .5s",
            }}
          />
        </div>
        <span
          style={{ fontFamily: "var(--mono)", fontSize: ".7rem", color: "#7a9e92", whiteSpace: "nowrap" }}
        >
          {currentDisplay}
        </span>
      </div>
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
        {connected ? <Badge variant="ok">● Live API</Badge> : <Badge variant="danger">API Offline</Badge>}
      </div>
    </div>
  );
}

// ─── Exec summary ───────────────────────────────────────────────────────────
function ExecSummary({
  run,
  findings,
  phase,
  approvals,
}: {
  run: Run | null;
  findings: Finding[];
  phase: RunPhase | null;
  approvals: Approval[];
}) {
  if (!run) return null;
  const risk = calcRisk(findings);
  const criticals = findings.filter((f) => f.severity === "critical");
  const highs = findings.filter((f) => f.severity === "high");
  const pendingApprovals = approvals.filter((a) => a.status === "pending");
  const phaseLabels: Record<string, string> = {
    init: "Initializing",
    recon: "Discovery & Reconnaissance",
    exploit: "Active Exploitation",
    validate: "Validation",
    "post-exploit": "Post-exploitation",
    report: "Generating Report",
    completed: "Completed",
  };
  const currentDisplay = toDisplayPhase(phase?.current);
  return (
    <div
      className="vx-panel"
      style={{
        gridColumn: "span 4",
        marginBottom: 0,
        background: "linear-gradient(135deg,rgba(11,20,22,.95),rgba(14,22,18,.95))",
      }}
    >
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 20 }}>
        <div>
          <div
            style={{
              fontSize: ".67rem",
              fontWeight: 700,
              letterSpacing: ".1em",
              textTransform: "uppercase",
              color: "#7a9e92",
              marginBottom: 10,
            }}
          >
            Engagement Status
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
            {risk && (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 52,
                  height: 52,
                  borderRadius: 12,
                  background: SEV[risk.variant].bg,
                  border: `1px solid ${SEV[risk.variant].border}`,
                  flexShrink: 0,
                }}
              >
                <span
                  style={{
                    fontFamily: "var(--mono)",
                    fontSize: "1.1rem",
                    fontWeight: 700,
                    color: SEV[risk.variant].color,
                    lineHeight: 1,
                  }}
                >
                  {risk.score}
                </span>
                <span
                  style={{
                    fontSize: ".55rem",
                    color: SEV[risk.variant].color,
                    letterSpacing: ".06em",
                    textTransform: "uppercase",
                  }}
                >
                  risk
                </span>
              </div>
            )}
            <div>
              <div style={{ fontSize: ".88rem", fontWeight: 700, color: "#e8f4ee", marginBottom: 2 }}>
                {risk?.level || "Pending"} Risk
              </div>
              <div style={{ fontSize: ".74rem", color: "#7a9e92" }}>
                {phaseLabels[currentDisplay] || "Initializing"}
              </div>
              <div style={{ fontSize: ".72rem", color: "#7a9e92", marginTop: 2 }}>{run.target}</div>
            </div>
          </div>
          {pendingApprovals.length > 0 && (
            <div
              style={{
                padding: "8px 10px",
                borderRadius: 9,
                background: "rgba(249,115,22,.08)",
                border: "1px solid rgba(249,115,22,.2)",
                fontSize: ".73rem",
                color: "#f97316",
              }}
            >
              ⚠ {pendingApprovals.length} action{pendingApprovals.length > 1 ? "s" : ""} awaiting your approval
            </div>
          )}
        </div>
        <div>
          <div
            style={{
              fontSize: ".67rem",
              fontWeight: 700,
              letterSpacing: ".1em",
              textTransform: "uppercase",
              color: "#7a9e92",
              marginBottom: 10,
            }}
          >
            Confirmed Findings
          </div>
          {findings.length ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
              {findings.slice(0, 3).map((f) => (
                <div key={f.id} style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                  <SevBadge severity={f.severity} />
                  <div>
                    <div
                      style={{ fontSize: ".76rem", fontWeight: 600, color: "#e8f4ee", lineHeight: 1.3 }}
                    >
                      {f.title}
                    </div>
                    <div
                      style={{ fontSize: ".71rem", color: "#7a9e92", lineHeight: 1.4, marginTop: 2 }}
                    >
                      {(f.summary || "").slice(0, 90)}
                      {(f.summary || "").length > 90 ? "…" : ""}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ fontSize: ".78rem", color: "#7a9e92", padding: "8px 0" }}>
              No confirmed findings yet — scan in progress.
            </div>
          )}
        </div>
        <div>
          <div
            style={{
              fontSize: ".67rem",
              fontWeight: 700,
              letterSpacing: ".1em",
              textTransform: "uppercase",
              color: "#7a9e92",
              marginBottom: 10,
            }}
          >
            Recommended Next Steps
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
            {pendingApprovals.length > 0 && (
              <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                <span style={{ color: "#f97316", fontSize: ".8rem", flexShrink: 0, marginTop: 1 }}>→</span>
                <span style={{ fontSize: ".76rem", color: "#e8f4ee" }}>
                  Review and approve exploitation actions in the{" "}
                  <strong style={{ color: "#f4b860" }}>Config</strong> tab
                </span>
              </div>
            )}
            {criticals.length > 0 && (
              <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                <span style={{ color: "#ef4444", fontSize: ".8rem", flexShrink: 0, marginTop: 1 }}>→</span>
                <span style={{ fontSize: ".76rem", color: "#e8f4ee" }}>
                  Patch {criticals.length} critical vulnerability{criticals.length > 1 ? "s" : ""} immediately
                </span>
              </div>
            )}
            {highs.length > 0 && (
              <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                <span style={{ color: "#f97316", fontSize: ".8rem", flexShrink: 0, marginTop: 1 }}>→</span>
                <span style={{ fontSize: ".76rem", color: "#e8f4ee" }}>
                  Schedule remediation for {highs.length} high-severity issue{highs.length > 1 ? "s" : ""} within 14 days
                </span>
              </div>
            )}
            <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
              <span style={{ color: "#19c37d", fontSize: ".8rem", flexShrink: 0, marginTop: 1 }}>→</span>
              <span style={{ fontSize: ".76rem", color: "#e8f4ee" }}>
                Full report will be available once the engagement completes
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Chat ────────────────────────────────────────────────────────────────────
function ChatPanel({
  messages,
  chatText,
  setChatText,
  onSend,
  loading,
}: {
  messages: RunMessage[];
  chatText: string;
  setChatText: (v: string) => void;
  onSend: (e: FormEvent) => void;
  loading: boolean;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages]);
  const rStyle: Record<string, { color: string; label: string }> = {
    user: { color: "#f4b860", label: "Operator" },
    orchestrator: { color: "#19c37d", label: "Vantix" },
    agent: { color: "#63b3ed", label: "Agent" },
    system: { color: "#7a9e92", label: "System" },
  };
  return (
    <Panel
      title="Mission Chat"
      meta="Guides and replans the engagement"
      loading={loading}
      style={{ gridColumn: "span 2", gridRow: "span 2", display: "flex", flexDirection: "column" }}
    >
      <div
        ref={scrollRef}
        style={{
          flex: 1,
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          gap: 10,
          maxHeight: 300,
          paddingRight: 4,
        }}
      >
        {messages.length ? (
          messages.map((m, i) => {
            const rs = rStyle[m.role] || rStyle.system;
            const isUser = m.role === "user";
            return (
              <div
                key={m.id || i}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: isUser ? "flex-end" : "flex-start",
                  gap: 4,
                }}
              >
                <span
                  style={{ fontSize: ".67rem", color: rs.color, fontWeight: 600, letterSpacing: ".05em" }}
                >
                  {m.author || rs.label}
                </span>
                {m.role === "system" && typeof m.metadata?.event_type === "string" && (
                  <Badge variant={eventBadgeVariant(String(m.metadata.event_type))} style={{ alignSelf: isUser ? "flex-end" : "flex-start" }}>
                    {EVENT_LABELS[String(m.metadata.event_type)] || String(m.metadata.event_type).replace(/_/g, " ")}
                  </Badge>
                )}
                <div
                  style={{
                    maxWidth: "88%",
                    padding: "10px 14px",
                    borderRadius: isUser ? "16px 16px 4px 16px" : "16px 16px 16px 4px",
                    background: isUser ? "rgba(244,184,96,.08)" : "rgba(25,195,125,.07)",
                    border: `1px solid ${isUser ? "rgba(244,184,96,.2)" : "rgba(25,195,125,.18)"}`,
                    fontSize: ".82rem",
                    color: "#e8f4ee",
                    lineHeight: 1.55,
                    whiteSpace: "pre-wrap",
                  }}
                >
                  {m.content}
                </div>
              </div>
            );
          })
        ) : (
          <EmptyState icon="⬡" text="Enter a target and objective to start an engagement." />
        )}
      </div>
      <form onSubmit={onSend} style={{ display: "flex", gap: 8, marginTop: 12, alignItems: "flex-end" }}>
        <textarea
          value={chatText}
          onChange={(e) => setChatText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              onSend(e as unknown as FormEvent);
            }
          }}
          placeholder="e.g. Full pentest of 10.10.10.10 — check for web vulnerabilities and misconfigurations"
          style={{
            flex: 1,
            minHeight: 52,
            maxHeight: 120,
            resize: "vertical",
            padding: "10px 12px",
            background: "rgba(6,12,12,.9)",
            border: "1px solid rgba(140,185,165,.18)",
            borderRadius: 12,
            color: "#e8f4ee",
            fontSize: ".82rem",
            lineHeight: 1.5,
          }}
        />
        <Btn type="submit" size="md" style={{ whiteSpace: "nowrap", height: 52 }}>
          Send
        </Btn>
      </form>
    </Panel>
  );
}

// ─── Terminal ───────────────────────────────────────────────────────────────
function TerminalPanel({ lines }: { lines: string[] }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);
  const colorLine = (l: string): string => {
    if (!l) return "#7a9e92";
    if (l.startsWith("[!]") || l.includes("CRITICAL") || l.includes("←")) return "#ff6b6b";
    if (l.startsWith("[+]") || l.includes(" open")) return "#19c37d";
    if (l.startsWith("[*]")) return "#63b3ed";
    if (l.includes("CVE-")) return "#f4b860";
    if (l.startsWith("|") || l.startsWith("  ")) return "#a8d5c2";
    return "#7a9e92";
  };
  return (
    <Panel title="Live Activity" meta="Technical execution output" style={{ gridColumn: "span 2" }}>
      <div
        ref={ref}
        style={{
          fontFamily: "var(--mono)",
          fontSize: ".76rem",
          lineHeight: 1.65,
          background: "#030706",
          border: "1px solid rgba(140,185,165,.1)",
          borderRadius: 12,
          padding: "14px 16px",
          minHeight: 200,
          maxHeight: 290,
          overflowY: "auto",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
        }}
      >
        {lines.length === 0 && (
          <div style={{ color: "#7a9e92" }}>No live terminal output yet.</div>
        )}
        {lines.map((l, i) => (
          <div key={i} style={{ color: colorLine(l) }}>
            {l}
          </div>
        ))}
        <span
          style={{
            display: "inline-block",
            width: 7,
            height: "1em",
            background: "#19c37d",
            animation: "vx-blink 1s step-end infinite",
            verticalAlign: "text-bottom",
            marginLeft: 2,
          }}
        />
      </div>
    </Panel>
  );
}

// ─── Agents ─────────────────────────────────────────────────────────────────
function AgentsPanel({
  agents,
  tasks,
  roles,
  phase,
}: {
  agents: AgentSession[];
  tasks: Task[];
  roles: string[];
  phase: RunPhase | null;
}) {
  const current = String(phase?.current || "").toLowerCase();
  const activeRoles = new Set<string>(
    current === "context-bootstrap" || current === "source-intake" || current === "source-analysis"
      ? ["orchestrator", "developer"]
      : current === "learning-recall" || current === "recon-sidecar" || current === "browser-assessment"
      ? ["recon", "browser", "knowledge_base"]
      : current === "cve-analysis"
      ? ["researcher", "vector_store"]
      : current === "orchestrate"
      ? ["orchestrator"]
      : current === "learn-ingest"
      ? ["executor", "developer"]
      : current === "report"
      ? ["reporter"]
      : ["orchestrator", "recon"]
  );
  return (
    <Panel title="Agent Team" meta="Specialist agents">
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        {roles.map((role) => {
          const agent = agents.find((a) => a.role === role);
          const task = tasks.find(
            (t) => t.kind?.includes(role.replace("_", "-")) || t.kind?.includes(role),
          );
          const rawStatus = agent?.status || task?.status || "pending";
          const status =
            rawStatus === "pending" && !activeRoles.has(role) ? "standby" : rawStatus;
          const sc: Record<string, string> = {
            running: "#f4b860",
            completed: "#19c37d",
            failed: "#ef4444",
            blocked: "#ef4444",
            pending: "#7a9e92",
            standby: "#4e6b63",
          };
          return (
            <div
              key={role}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 9,
                padding: "9px 11px",
                borderRadius: 10,
                background: "rgba(255,255,255,.025)",
                border: `1px solid rgba(140,185,165,${status === "running" ? 0.22 : status === "standby" ? 0.08 : 0.1})`,
              }}
            >
              <StatusDot status={status === "standby" ? "idle" : status} size={7} />
              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    fontSize: ".73rem",
                    fontWeight: 600,
                    color: "#e8f4ee",
                    textTransform: "capitalize",
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {role.replace(/_/g, " ")}
                </div>
                <div style={{ fontSize: ".67rem", color: sc[status] || "#7a9e92", marginTop: 1 }}>
                  {status}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function ControlCenterPanel({
  workflowState,
  approvals,
}: {
  workflowState: WorkflowState | null;
  approvals: Approval[];
}) {
  const pendingApprovals = approvals.filter((row) => row.status === "pending").length;
  const blockedClasses = Array.isArray(workflowState?.metrics?.blocked_reason_classes)
    ? (workflowState?.metrics?.blocked_reason_classes as string[])
    : [];
  const phaseDurations = workflowState?.metrics?.phase_durations_seconds as Record<string, number> | undefined;
  return (
    <Panel title="Control Center" meta="Workflow health">
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 10 }}>
        <Badge variant="blue">workers {metricNumber(workflowState, "active_worker_count")}</Badge>
        <Badge variant={metricNumber(workflowState, "stale_worker_count") > 0 ? "danger" : "ok"}>
          stale {metricNumber(workflowState, "stale_worker_count")}
        </Badge>
        <Badge variant={pendingApprovals > 0 ? "warn" : "ok"}>approvals {pendingApprovals}</Badge>
        <Badge variant="default">retries {metricNumber(workflowState, "retry_count")}</Badge>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <div
          style={{
            padding: "10px 12px",
            borderRadius: 10,
            background: "rgba(255,255,255,.025)",
            border: "1px solid rgba(140,185,165,.1)",
          }}
        >
          <div style={{ fontSize: ".67rem", color: "#7a9e92", textTransform: "uppercase", letterSpacing: ".08em", marginBottom: 6 }}>
            Active Workflow
          </div>
          <div style={{ fontSize: ".8rem", color: "#e8f4ee", fontWeight: 600 }}>
            {workflowState?.workflow?.current_phase || "n/a"}
          </div>
          <div style={{ fontSize: ".72rem", color: "#7a9e92", marginTop: 4 }}>
            claim age {metricNumber(workflowState, "current_claim_age_seconds").toFixed(1)}s
          </div>
          <div style={{ fontSize: ".72rem", color: "#7a9e92" }}>
            phase age {metricNumber(workflowState, "current_phase_duration_seconds").toFixed(1)}s
          </div>
          <div style={{ fontSize: ".72rem", color: "#7a9e92" }}>
            latest heartbeat {(workflowState?.metrics?.latest_heartbeat_at as string) || "n/a"}
          </div>
        </div>
        <div
          style={{
            padding: "10px 12px",
            borderRadius: 10,
            background: "rgba(255,255,255,.025)",
            border: "1px solid rgba(140,185,165,.1)",
          }}
        >
          <div style={{ fontSize: ".67rem", color: "#7a9e92", textTransform: "uppercase", letterSpacing: ".08em", marginBottom: 6 }}>
            Governance
          </div>
          <div style={{ fontSize: ".72rem", color: "#7a9e92", marginBottom: 4 }}>
            resolved approvals {metricNumber(workflowState, "approval_resolved_count")}
          </div>
          <div style={{ fontSize: ".72rem", color: "#7a9e92", marginBottom: 4 }}>
            avg approval latency {metricNumber(workflowState, "approval_latency_seconds_avg").toFixed(1)}s
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {blockedClasses.length ? blockedClasses.map((item) => (
              <Badge key={item} variant="amber">{item}</Badge>
            )) : <span style={{ fontSize: ".72rem", color: "#7a9e92" }}>No blockers classified</span>}
          </div>
        </div>
      </div>
      {workflowState?.workers?.length ? (
        <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 6 }}>
          {workflowState.workers.map((worker) => (
            <div
              key={worker.worker_id}
              style={{
                padding: "9px 11px",
                borderRadius: 10,
                background: "rgba(255,255,255,.02)",
                border: "1px solid rgba(140,185,165,.1)",
                display: "grid",
                gridTemplateColumns: "minmax(0,1fr) auto",
                gap: 8,
              }}
            >
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: ".74rem", color: "#e8f4ee", fontWeight: 600, fontFamily: "var(--mono)" }}>
                  {worker.worker_id}
                </div>
                <div style={{ fontSize: ".7rem", color: "#7a9e92", marginTop: 2 }}>
                  {worker.current_phase || "idle"} · {worker.current_run_id || "no-run"}
                </div>
              </div>
              <Badge variant={worker.status === "error" || worker.status === "stale" ? "danger" : worker.status === "running" ? "amber" : "default"}>
                {worker.status}
              </Badge>
            </div>
          ))}
        </div>
      ) : null}
      {phaseDurations && Object.keys(phaseDurations).length > 0 && (
        <div style={{ marginTop: 10 }}>
          <Label>Phase Durations</Label>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
            {Object.entries(phaseDurations)
              .sort((left, right) => left[0].localeCompare(right[0]))
              .map(([name, seconds]) => (
                <Badge key={name} variant="default">
                  {name} {Number(seconds).toFixed(1)}s
                </Badge>
              ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

function TimelinePanel({ events }: { events: EventRecord[] }) {
  const visibleEvents = events.filter((event) => !(event.event_type === "terminal" && String(event.level || "info").toLowerCase() === "info"));
  const hiddenTerminalCount = Math.max(0, events.length - visibleEvents.length);
  return (
    <Panel
      title="Attack Timeline"
      meta={`${visibleEvents.length} events${hiddenTerminalCount ? ` · ${hiddenTerminalCount} terminal lines hidden` : ""}`}
      style={{ gridColumn: "span 2" }}
    >
      {visibleEvents.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 320, overflowY: "auto" }}>
          {visibleEvents.map((event) => (
            <div
              key={event.id}
              style={{
                padding: "10px 12px",
                borderRadius: 10,
                background: "rgba(255,255,255,.025)",
                border: "1px solid rgba(140,185,165,.1)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: "space-between", marginBottom: 4 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <Badge variant={eventBadgeVariant(event.event_type)}>
                    {EVENT_LABELS[event.event_type] || event.event_type.replace(/_/g, " ")}
                  </Badge>
                  <span style={{ fontSize: ".76rem", color: "#e8f4ee", fontWeight: 600 }}>{event.message}</span>
                </div>
                <span style={{ fontFamily: "var(--mono)", fontSize: ".68rem", color: "#7a9e92" }}>
                  #{event.sequence}
                </span>
              </div>
              <div style={{ fontSize: ".69rem", color: "#7a9e92", display: "flex", gap: 8, flexWrap: "wrap" }}>
                <span>{new Date(event.created_at).toLocaleString()}</span>
                {typeof event.payload?.phase_name === "string" && <span>phase {String(event.payload.phase_name)}</span>}
                {typeof event.payload?.role === "string" && <span>role {String(event.payload.role)}</span>}
                {typeof event.payload?.reason === "string" && <span>reason {String(event.payload.reason)}</span>}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState icon="⋯" text="No timeline events recorded yet." />
      )}
    </Panel>
  );
}

function SourcePanel({ sourceStatus }: { sourceStatus: SourceStatus | null }) {
  const sourceInput = sourceStatus?.source_input || {};
  const sourceContext = sourceStatus?.source_context || {};
  const sourceType = String(sourceInput.type || "none");
  const status = String(sourceContext.status || (sourceType === "none" ? "skipped" : "pending"));
  const resolvedPath = String(sourceContext.resolved_path || "");
  const url = String((sourceInput.github as Record<string, unknown> | undefined)?.url || "");
  const localPath = String((sourceInput.local as Record<string, unknown> | undefined)?.path || "");
  const uploadId = String((sourceInput.upload as Record<string, unknown> | undefined)?.staged_upload_id || "");
  return (
    <Panel title="Source Intake" meta={`${sourceType} · ${status}`}>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 8 }}>
        <Badge variant={sourceType === "none" ? "default" : "blue"}>{sourceType}</Badge>
        <Badge variant={status === "ready" ? "ok" : status === "failed" ? "danger" : "default"}>{status}</Badge>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: ".73rem", color: "#7a9e92" }}>
        {url ? <div>GitHub: {url}</div> : null}
        {localPath ? <div>Local path: {localPath}</div> : null}
        {uploadId ? <div>Upload: {uploadId}</div> : null}
        {resolvedPath ? <div>Resolved: {resolvedPath}</div> : null}
        {!url && !localPath && !uploadId && <div>No white-box source attached to this run.</div>}
      </div>
    </Panel>
  );
}

// ─── Phase ─────────────────────────────────────────────────────────────────
function PhasePanel({ phase }: { phase: RunPhase | null }) {
  if (!phase)
    return (
      <Panel title="Engagement Phase">
        <EmptyState icon="◎" text="No phase state loaded." />
      </Panel>
    );
  const completed = normalizeCompletedPhases(phase.completed);
  const currentDisplay = toDisplayPhase(phase.current);
  return (
    <Panel title="Engagement Phase" meta={currentDisplay}>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {DISPLAY_PHASES.map((p, i) => {
          const done = completed.includes(p);
          const active = p === currentDisplay && (currentDisplay as string) !== "completed";
          return (
            <div key={p} style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div
                style={{
                  width: 20,
                  height: 20,
                  borderRadius: "50%",
                  flexShrink: 0,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  background: done ? "rgba(25,195,125,.18)" : active ? "rgba(244,184,96,.18)" : "rgba(255,255,255,.04)",
                  border: `1px solid ${done ? "rgba(25,195,125,.5)" : active ? "rgba(244,184,96,.6)" : "rgba(140,185,165,.12)"}`,
                  fontSize: ".62rem",
                  fontWeight: 700,
                  color: done ? "#19c37d" : active ? "#f4b860" : "rgba(122,158,146,.4)",
                }}
              >
                {done ? "✓" : active ? "●" : i + 1}
              </div>
              <div
                style={{
                  fontSize: ".75rem",
                  fontWeight: active ? 700 : 500,
                  color: done ? "#19c37d" : active ? "#f4b860" : "rgba(122,158,146,.5)",
                  textTransform: "capitalize",
                  flex: 1,
                }}
              >
                {p}
              </div>
              {active && <StatusDot status="running" size={6} />}
            </div>
          );
        })}
      </div>
      {phase.reason && (
        <div
          style={{
            marginTop: 12,
            padding: "8px 10px",
            borderRadius: 8,
            background: "rgba(244,184,96,.07)",
            border: "1px solid rgba(244,184,96,.15)",
            fontSize: ".72rem",
            color: "#f4b860",
          }}
        >
          {phase.reason}
        </div>
      )}
    </Panel>
  );
}

// ─── Vectors ───────────────────────────────────────────────────────────────
function VectorsPanel({
  vectors,
  onSelect,
  onPromote,
  selectedRunId,
}: {
  vectors: Vector[];
  onSelect: (v: Vector) => void;
  onPromote: (v: Vector) => void;
  selectedRunId: string | undefined;
}) {
  const selectedCount = vectors.filter((row) => row.status === "planned" || row.status === "selected").length;
  return (
    <Panel title="Attack Vectors" meta={`${vectors.length} candidates · ${selectedCount} selected`} style={{ gridColumn: "span 2" }}>
      {vectors.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {vectors.map((v) => {
            const businessImpact =
              typeof v.metadata?.business_impact === "string" ? (v.metadata.business_impact as string) : "";
            return (
              <div
                key={v.id}
                style={{
                  padding: "12px 14px",
                  borderRadius: 12,
                  background: "rgba(255,255,255,.025)",
                  border: "1px solid rgba(140,185,165,.13)",
                  transition: "border-color .2s",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    justifyContent: "space-between",
                    gap: 10,
                    marginBottom: 6,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <SevBadge severity={v.severity} />
                    <span style={{ fontSize: ".82rem", fontWeight: 600, color: "#e8f4ee" }}>{v.title}</span>
                  </div>
                  <Badge variant={v.status === "selected" ? "ok" : "default"}>{v.status}</Badge>
                </div>
                <p style={{ margin: "0 0 6px", fontSize: ".78rem", color: "#7a9e92", lineHeight: 1.5 }}>
                  {v.summary}
                </p>
                {businessImpact && (
                  <div
                    style={{
                      padding: "7px 10px",
                      borderRadius: 8,
                      background: "rgba(249,115,22,.06)",
                      border: "1px solid rgba(249,115,22,.15)",
                      fontSize: ".72rem",
                      color: "#f4b860",
                      lineHeight: 1.4,
                      marginBottom: 8,
                    }}
                  >
                    <span style={{ fontWeight: 700 }}>Business impact: </span>
                    {businessImpact}
                  </div>
                )}
                <div style={{ marginBottom: 8 }}>
                  <div style={{ fontSize: ".67rem", color: "#7a9e92", marginBottom: 4 }}>Confidence</div>
                  <ConfBar value={v.confidence} />
                </div>
                {v.next_action && (
                  <div style={{ fontSize: ".72rem", color: "#63b3ed", marginBottom: 10 }}>
                    → {v.next_action}
                  </div>
                )}
                {selectedRunId && (
                  <div style={{ display: "flex", gap: 6 }}>
                    <Btn size="xs" variant="green" onClick={() => onSelect(v)}>
                      Select
                    </Btn>
                    <Btn size="xs" variant="ghost" onClick={() => onPromote(v)}>
                      Promote Finding
                    </Btn>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <EmptyState icon="◈" text="No attack vectors identified yet." />
      )}
    </Panel>
  );
}

// ─── CVE, Memory, Chains ────────────────────────────────────────────────────
function CvePanel({ facts }: { facts: Fact[] }) {
  return (
    <Panel title="Intel Findings" meta={`${facts.length} items`}>
      {facts.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {facts.map((f, i) => (
            <div
              key={f.id || i}
              style={{
                padding: "9px 11px",
                borderRadius: 10,
                background: "rgba(255,255,255,.025)",
                border: "1px solid rgba(140,185,165,.1)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                <span
                  style={{ fontFamily: "var(--mono)", fontSize: ".75rem", color: "#f4b860", fontWeight: 600 }}
                >
                  {f.value}
                </span>
                <Badge variant="default">{f.kind}</Badge>
                <span style={{ fontSize: ".68rem", color: "#7a9e92" }}>
                  {Math.round(f.confidence * 100)}% match
                </span>
              </div>
              {f.tags?.length > 0 && (
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 5 }}>
                  {f.tags.map((t) => (
                    <Badge key={t} variant="default">
                      {t}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <EmptyState icon="⊙" text="No intel items yet." />
      )}
    </Panel>
  );
}

function MemoryPanel({ hits }: { hits: Array<Record<string, unknown>> }) {
  return (
    <Panel title="Prior Experience" meta="Similar engagements">
      {hits.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {hits.slice(0, 5).map((h, i) => (
            <div
              key={i}
              style={{
                padding: "9px 11px",
                borderRadius: 10,
                background: "rgba(255,255,255,.025)",
                border: "1px solid rgba(140,185,165,.1)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 8,
                  marginBottom: 4,
                }}
              >
                <span style={{ fontSize: ".75rem", fontWeight: 600, color: "#e8f4ee" }}>
                  {String(h.title ?? "Memory hit")}
                </span>
                {h.rank !== undefined && h.rank !== null && (
                  <Badge variant="default">rank {String(h.rank)}</Badge>
                )}
              </div>
              <p style={{ margin: 0, fontSize: ".73rem", color: "#7a9e92", lineHeight: 1.45 }}>
                {String(h.summary_short ?? h.summary ?? "")}
              </p>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState icon="⌬" text="No similar prior engagements found." />
      )}
    </Panel>
  );
}

function ChainsPanel({
  chains,
  onPromote,
  selectedRunId,
}: {
  chains: AttackChain[];
  onPromote: (c: AttackChain) => void;
  selectedRunId: string | undefined;
}) {
  return (
    <Panel title="Attack Chains" meta={`${chains.length} modelled`}>
      {chains.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {chains.map((c) => (
            <div
              key={c.id}
              style={{
                padding: "10px 12px",
                borderRadius: 10,
                background: "rgba(255,255,255,.025)",
                border: "1px solid rgba(140,185,165,.1)",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 5 }}
              >
                <span style={{ fontSize: ".78rem", fontWeight: 600, color: "#f4b860" }}>{c.name}</span>
                <span style={{ fontFamily: "var(--mono)", fontSize: ".7rem", color: "#7a9e92" }}>
                  score {c.score?.toFixed(2)}
                </span>
              </div>
              {c.mitre_ids?.length > 0 && (
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
                  {c.mitre_ids.map((id) => (
                    <Badge key={id} variant="amber">
                      {id}
                    </Badge>
                  ))}
                </div>
              )}
              <p style={{ margin: "0 0 8px", fontSize: ".72rem", color: "#7a9e92" }}>{c.notes}</p>
              {selectedRunId && (
                <Btn size="xs" variant="amber" onClick={() => onPromote(c)}>
                  Promote Finding
                </Btn>
              )}
            </div>
          ))}
        </div>
      ) : (
        <EmptyState icon="⛓" text="No attack chains modelled yet." />
      )}
    </Panel>
  );
}

function BrowserPanel({
  state,
  selectedRunId,
  onOpenPath,
}: {
  state: BrowserState | null;
  selectedRunId: string | undefined;
  onOpenPath: (path: string) => void;
}) {
  if (!state) {
    return (
      <Panel title="Browser Assessment">
        <EmptyState icon="◉" text="No browser assessment data yet." />
      </Panel>
    );
  }
  const endpoints = Array.isArray(state.network_summary?.endpoints)
    ? (state.network_summary.endpoints as Array<Record<string, unknown>>)
    : [];
  const sessionSummary = (state.session_summary || {}) as Record<string, unknown>;
  const finalStorage = ((sessionSummary["final_storage_summary"] as Record<string, unknown> | undefined) || {});
  const authTransitions = Array.isArray(state.auth_transitions) ? state.auth_transitions : [];
  const domDiffs = Array.isArray(state.dom_diffs) ? state.dom_diffs : [];
  const jsSignals = Array.isArray(state.js_signals) ? state.js_signals : [];
  const routeHints = Array.isArray(state.route_hints) ? state.route_hints : [];
  return (
    <Panel title="Browser Assessment" meta={`${state.status} · ${state.pages_visited} pages`}>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Badge variant="default">auth: {state.authenticated}</Badge>
          <Badge variant="blue">routes: {state.routes_discovered}</Badge>
          <Badge variant="amber">forms: {state.forms.length}</Badge>
          <Badge variant="ok">screenshots: {state.screenshots.length}</Badge>
          <Badge variant="default">signals: {jsSignals.length}</Badge>
        </div>
        <div style={{ fontSize: ".72rem", color: "#7a9e92", lineHeight: 1.45 }}>
          <div>Entry: {state.entry_url || "(none)"}</div>
          <div>Current: {state.current_url || "(none)"}</div>
          {!!Object.keys(sessionSummary).length && (
            <div>
              Storage: cookies {String(finalStorage["cookie_count"] ?? "0")} · local {String(finalStorage["local_storage_keys"] ?? "0")} ·
              session {String(finalStorage["session_storage_keys"] ?? "0")}
            </div>
          )}
        </div>
        {state.blocked_actions.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {state.blocked_actions.slice(0, 4).map((line, i) => (
              <div key={i} style={{ fontSize: ".7rem", color: "#f4b860" }}>
                {line}
              </div>
            ))}
          </div>
        )}
        {authTransitions.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <Label>Auth State</Label>
            {authTransitions.slice(0, 4).map((item, idx) => (
              <div key={idx} style={{ fontSize: ".69rem", color: "#a6c3b7", lineHeight: 1.45 }}>
                {String(item.stage || "state")} · {String(item.status || "observed")}
                {item.url ? ` · ${String(item.url)}` : ""}
              </div>
            ))}
          </div>
        )}
        {domDiffs.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <Label>State Deltas</Label>
            {domDiffs.slice(0, 3).map((item, idx) => (
              <div key={idx} style={{ fontSize: ".69rem", color: "#a6c3b7", lineHeight: 1.45 }}>
                {String(item.stage || "navigation")} · forms {String(item.form_delta ?? 0)} · links {String(item.link_delta ?? 0)} · cookies{" "}
                {String(item.cookie_delta ?? 0)}
              </div>
            ))}
          </div>
        )}
        {endpoints.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <Label>Observed Endpoints</Label>
            {endpoints.slice(0, 5).map((item, idx) => (
              <div key={idx} style={{ fontSize: ".69rem", color: "#a6c3b7", fontFamily: "var(--mono)" }}>
                {String(item.endpoint || "")} ({String(item.count || "0")})
              </div>
            ))}
          </div>
        )}
        {routeHints.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <Label>Route Hints</Label>
            {routeHints.slice(0, 4).map((item, idx) => (
              <div key={idx} style={{ fontSize: ".69rem", color: "#a6c3b7", fontFamily: "var(--mono)" }}>
                {String(item.hint || "")}
              </div>
            ))}
          </div>
        )}
        {jsSignals.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <Label>Client Signals</Label>
            {jsSignals.slice(0, 4).map((item, idx) => (
              <div key={idx} style={{ fontSize: ".69rem", color: "#a6c3b7", lineHeight: 1.45 }}>
                {String(item.kind || "signal")} · {String(item.signal || "")}
              </div>
            ))}
          </div>
        )}
        {state.screenshots.length > 0 && selectedRunId && (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {state.screenshots.slice(0, 4).map((path) => (
              <Btn key={path} size="xs" variant="ghost" onClick={() => onOpenPath(path)}>
                Screenshot
              </Btn>
            ))}
          </div>
        )}
      </div>
    </Panel>
  );
}

// ─── Results ────────────────────────────────────────────────────────────────
function ResultsPanel({
  results,
  selectedRunId,
  onOpenPath,
}: {
  results: RunResults | null;
  selectedRunId: string | undefined;
  onOpenPath: (path: string) => void;
}) {
  const findings = results?.findings || [];
  const artifacts = results?.artifacts || [];
  const validatedCount = findings.filter((row) => ["validated", "confirmed", "draft"].includes(String(row.status || "").toLowerCase())).length;
  return (
    <Panel title="Findings & Report" meta={`${validatedCount} validated · ${artifacts.length} artifacts`} style={{ gridColumn: "span 2" }}>
      {results ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {results.executive_summary && (
            <div
              style={{
                padding: "9px 11px",
                borderRadius: 10,
                background: "rgba(25,195,125,.07)",
                border: "1px solid rgba(25,195,125,.2)",
                fontSize: ".74rem",
                color: "#e8f4ee",
                lineHeight: 1.5,
              }}
            >
              {results.executive_summary}
            </div>
          )}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div>
            <Label>Confirmed Findings ({findings.length})</Label>
            <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
              {findings.length ? (
                findings.map((f) => (
                  <div
                    key={f.id}
                    style={{
                      padding: "9px 11px",
                      borderRadius: 10,
                      background: "rgba(255,255,255,.025)",
                      border: "1px solid rgba(140,185,165,.1)",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 4 }}>
                      <SevBadge severity={f.severity} />
                      <span style={{ fontSize: ".76rem", fontWeight: 600, color: "#e8f4ee" }}>{f.title}</span>
                    </div>
                    <p style={{ margin: 0, fontSize: ".72rem", color: "#7a9e92" }}>{f.summary}</p>
                  </div>
                ))
              ) : (
                <EmptyState icon="◇" text="No confirmed findings yet." />
              )}
            </div>
          </div>
          <div>
            <Label>Evidence & Artifacts ({artifacts.length})</Label>
            <div style={{ display: "flex", flexDirection: "column", gap: 7, maxHeight: 280, overflowY: "auto" }}>
              {artifacts.map((a, i) => (
                <div
                  key={a.id || i}
                  style={{
                    padding: "9px 11px",
                    borderRadius: 10,
                    background: "rgba(255,255,255,.025)",
                    border: "1px solid rgba(140,185,165,.1)",
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                  }}
                >
                  <Badge variant="default">{a.kind}</Badge>
                  <span
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: ".7rem",
                      color: "#7a9e92",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      flex: 1,
                    }}
                  >
                    {a.path}
                  </span>
                  {selectedRunId && (
                    <Btn size="xs" variant="ghost" onClick={() => onOpenPath(a.path)}>
                      Open
                    </Btn>
                  )}
                </div>
              ))}
            </div>
            {!results.report_path && (
              <div
                style={{
                  marginTop: 10,
                  padding: "9px 11px",
                  borderRadius: 10,
                  background: "rgba(244,184,96,.05)",
                  border: "1px solid rgba(244,184,96,.15)",
                  fontSize: ".73rem",
                  color: "#7a9e92",
                }}
              >
                Report will be generated automatically when the engagement completes.
              </div>
            )}
            {results.report_path && (
              <div
                style={{
                  marginTop: 10,
                  padding: "9px 11px",
                  borderRadius: 10,
                  background: "rgba(25,195,125,.07)",
                  border: "1px solid rgba(25,195,125,.2)",
                }}
              >
                <div style={{ fontSize: ".68rem", color: "#19c37d", fontWeight: 600, marginBottom: 2 }}>
                  Report Ready
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div style={{ fontFamily: "var(--mono)", fontSize: ".7rem", color: "#7a9e92", flex: 1 }}>
                    {results.report_path}
                  </div>
                  {selectedRunId && (
                    <Btn size="xs" variant="green" onClick={() => onOpenPath(results.report_path || "")}>
                      Open
                    </Btn>
                  )}
                  {selectedRunId && results.report_json_path && (
                    <Btn size="xs" variant="ghost" onClick={() => onOpenPath(results.report_json_path || "")}>
                      JSON
                    </Btn>
                  )}
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 8, flexWrap: "wrap" }}>
                  {selectedRunId && results.comprehensive_report_path && (
                    <Btn size="xs" variant="green" onClick={() => onOpenPath(results.comprehensive_report_path || "")}>
                      Comprehensive MD
                    </Btn>
                  )}
                  {selectedRunId && results.comprehensive_report_json_path && (
                    <Btn size="xs" variant="ghost" onClick={() => onOpenPath(results.comprehensive_report_json_path || "")}>
                      Comprehensive JSON
                    </Btn>
                  )}
                  {selectedRunId && results.artifact_index_path && (
                    <Btn size="xs" variant="ghost" onClick={() => onOpenPath(results.artifact_index_path || "")}>
                      Artifact Index
                    </Btn>
                  )}
                  {selectedRunId && results.timeline_csv_path && (
                    <Btn size="xs" variant="ghost" onClick={() => onOpenPath(results.timeline_csv_path || "")}>
                      Timeline CSV
                    </Btn>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
        </div>
      ) : (
        <EmptyState icon="◇" text="No results yet." />
      )}
    </Panel>
  );
}

function ReplayPanel({ replay }: { replay: ReplayState | null }) {
  return (
    <Panel title="Replay" meta={replay ? `${replay.summary?.event_count || 0} events` : "history"}>
      {replay ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            <Badge variant="blue">events {Number(replay.summary?.event_count || 0)}</Badge>
            <Badge variant="amber">phase transitions {Number(replay.summary?.phase_transition_count || 0)}</Badge>
            <Badge variant="warn">approvals {Number(replay.summary?.approval_count || 0)}</Badge>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {(replay.phase_history || []).slice(-12).map((entry, index) => (
              <div
                key={`${String(entry.at || index)}-${String(entry.phase || index)}`}
                style={{
                  padding: "9px 11px",
                  borderRadius: 10,
                  background: "rgba(255,255,255,.025)",
                  border: "1px solid rgba(140,185,165,.1)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: "space-between" }}>
                  <span style={{ fontSize: ".76rem", color: "#e8f4ee", fontWeight: 600 }}>
                    {String(entry.phase || "unknown")}
                  </span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: ".68rem", color: "#7a9e92" }}>
                    {String(entry.at || "")}
                  </span>
                </div>
                <div style={{ fontSize: ".71rem", color: "#7a9e92", marginTop: 4 }}>
                  {String(entry.reason || "n/a")}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <EmptyState icon="↺" text="Replay history not available yet." />
      )}
    </Panel>
  );
}

// ─── Approvals ──────────────────────────────────────────────────────────────
function ApprovalsPanel({
  approvals,
  onApprove,
  onReject,
}: {
  approvals: Approval[];
  onApprove: (a: Approval) => void;
  onReject: (a: Approval) => void;
}) {
  const pending = approvals.filter((a) => a.status === "pending").length;
  return (
    <Panel
      title="Approvals"
      meta="Actions requiring your sign-off"
      action={pending > 0 ? <Badge variant="warn">{pending} waiting</Badge> : null}
      style={{ gridColumn: "span 2" }}
    >
      {approvals.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {approvals.map((a) => (
            <div
              key={a.id}
              style={{
                padding: "12px 14px",
                borderRadius: 12,
                background: "rgba(249,115,22,.05)",
                border: `1px solid ${a.status === "pending" ? "rgba(249,115,22,.2)" : "rgba(140,185,165,.12)"}`,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <Badge variant={a.status === "pending" ? "warn" : a.status === "approved" ? "ok" : "danger"}>
                  {a.status}
                </Badge>
                <span style={{ fontSize: ".8rem", fontWeight: 600, color: "#e8f4ee" }}>{a.title}</span>
              </div>
              <p style={{ margin: "0 0 10px", fontSize: ".76rem", color: "#7a9e92", lineHeight: 1.5 }}>
                {a.detail}
              </p>
              {a.status === "pending" && (
                <div style={{ display: "flex", gap: 8 }}>
                  <Btn size="sm" variant="green" onClick={() => onApprove(a)}>
                    Approve
                  </Btn>
                  <Btn size="sm" variant="danger" onClick={() => onReject(a)}>
                    Reject
                  </Btn>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <EmptyState icon="✓" text="No actions pending approval." />
      )}
    </Panel>
  );
}

// ─── Skills ─────────────────────────────────────────────────────────────────
function SkillsPanel({
  applications,
  onApply,
  selectedRunId,
}: {
  applications: RunSkillApplication[];
  onApply: () => void;
  selectedRunId: string | undefined;
}) {
  const total = applications.reduce((n, a) => n + (a.skills?.length || 0), 0);
  return (
    <Panel
      title="Agent Skill Packs"
      meta={`${total} active`}
      action={
        selectedRunId ? (
          <Btn size="xs" variant="ghost" onClick={onApply}>
            Reapply
          </Btn>
        ) : null
      }
    >
      {applications.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {applications.map((a) => (
            <div
              key={a.agent_role}
              style={{
                padding: "9px 11px",
                borderRadius: 10,
                background: "rgba(255,255,255,.025)",
                border: "1px solid rgba(140,185,165,.1)",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}
              >
                <span
                  style={{ fontSize: ".75rem", fontWeight: 600, color: "#e8f4ee", textTransform: "capitalize" }}
                >
                  {a.agent_role.replace(/_/g, " ")}
                </span>
                <Badge variant="default">{a.skills?.length || 0} skills</Badge>
              </div>
              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                {(a.skills || []).slice(0, 6).map((s) => (
                  <Badge key={s.id} variant="blue">
                    {s.id}
                  </Badge>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState icon="◈" text="No skill packs loaded." />
      )}
    </Panel>
  );
}

// ─── Notes ─────────────────────────────────────────────────────────────────
function NotesPanel({
  note,
  setNote,
  classification,
  setClassification,
  onSave,
  canSave,
}: {
  note: string;
  setNote: (v: string) => void;
  classification: "unrestricted" | "internal" | "sensitive";
  setClassification: (c: "unrestricted" | "internal" | "sensitive") => void;
  onSave: () => void;
  canSave: boolean;
}) {
  const warn = classification !== "unrestricted";
  return (
    <Panel title="Operator Notes">
      <textarea
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="Add notes, observations, or context for this engagement…"
        style={{
          width: "100%",
          minHeight: 80,
          resize: "vertical",
          padding: "10px 12px",
          background: "rgba(6,12,12,.9)",
          border: "1px solid rgba(140,185,165,.18)",
          borderRadius: 10,
          color: "#e8f4ee",
          fontSize: ".78rem",
          lineHeight: 1.5,
          marginBottom: 8,
          boxSizing: "border-box",
        }}
      />
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <Label>Classification</Label>
        <select
          value={classification}
          onChange={(e) => setClassification(e.target.value as "unrestricted" | "internal" | "sensitive")}
          style={{
            padding: "6px 10px",
            background: "rgba(6,12,12,.9)",
            border: "1px solid rgba(140,185,165,.18)",
            borderRadius: 8,
            color: "#e8f4ee",
            fontSize: ".76rem",
          }}
        >
          <option value="unrestricted">Unrestricted</option>
          <option value="internal">Internal</option>
          <option value="sensitive">Sensitive</option>
        </select>
      </div>
      {warn ? (
        <div
          style={{
            padding: "8px 10px",
            marginBottom: 8,
            border: "1px solid rgba(249,115,22,.35)",
            background: "rgba(249,115,22,.08)",
            borderRadius: 8,
            fontSize: ".72rem",
            color: "#f4b860",
          }}
        >
          This note is marked <strong>{classification}</strong>. Do not paste secrets or PII — content is persisted server-side.
        </div>
      ) : null}
      <Btn size="sm" onClick={onSave} disabled={!canSave}>
        Save Note
      </Btn>
    </Panel>
  );
}

// ─── Account ────────────────────────────────────────────────────────────────
function AccountPanel({
  user,
  connected,
  onTest,
  testing,
  onLogout,
}: {
  user: AuthUser;
  connected: boolean;
  onTest: () => void;
  testing: boolean;
  onLogout: () => void;
}) {
  return (
    <Panel title="Account" style={{ gridColumn: "span 2" }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <div>
          <Label>Signed in as</Label>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
            <span style={{ fontSize: ".82rem", color: "#e8f4ee", fontWeight: 600 }}>{user.username}</span>
            <Badge variant={user.role === "admin" ? "amber" : user.role === "operator" ? "blue" : "default"}>
              {user.role}
            </Badge>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Btn size="sm" variant="primary" onClick={onTest} disabled={testing}>
              {testing ? "Testing…" : "Test Connection"}
            </Btn>
            <Badge variant={connected ? "ok" : "danger"}>{connected ? "Connected" : "Disconnected"}</Badge>
            <Btn size="sm" variant="danger" onClick={onLogout}>
              Sign out
            </Btn>
          </div>
        </div>
        <div
          style={{
            padding: "12px 14px",
            borderRadius: 12,
            background: "rgba(255,255,255,.02)",
            border: "1px solid rgba(140,185,165,.1)",
          }}
        >
          <div style={{ fontSize: ".74rem", fontWeight: 600, color: "#e8f4ee", marginBottom: 8 }}>Session</div>
          <p style={{ margin: "0 0 8px", fontSize: ".73rem", color: "#7a9e92", lineHeight: 1.55 }}>
            Authentication uses an httpOnly session cookie. Mutating requests carry an X-CSRF-Token header.
          </p>
          <p style={{ margin: 0, fontSize: ".73rem", color: "#7a9e92", lineHeight: 1.55 }}>
            Role determines which actions are visible. Ask an admin to change your role.
          </p>
        </div>
      </div>
    </Panel>
  );
}

// ─── Banner ─────────────────────────────────────────────────────────────────
function PendingApprovalsBanner({
  approvals,
  onApprove,
  onReject,
}: {
  approvals: Approval[];
  onApprove: (a: Approval) => void;
  onReject: (a: Approval) => void;
}) {
  const pending = approvals.filter((a) => a.status === "pending");
  if (!pending.length) return null;
  return (
    <div style={{ marginBottom: 12, display: "flex", flexDirection: "column", gap: 8 }}>
      {pending.map((a) => (
        <div
          key={a.id}
          style={{
            display: "grid",
            gridTemplateColumns: "1fr auto",
            gap: 16,
            alignItems: "center",
            padding: "13px 18px",
            borderRadius: 14,
            background: "linear-gradient(135deg,rgba(249,115,22,.1),rgba(239,68,68,.07))",
            border: "1px solid rgba(249,115,22,.35)",
            animation: "vx-fadein .2s ease",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
            <div
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: "#f97316",
                flexShrink: 0,
                animation: "vx-pulse 1.8s ease-in-out infinite",
                boxShadow: "0 0 0 4px rgba(249,115,22,.2)",
              }}
            />
            <div style={{ minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 3 }}>
                <Badge variant="warn">Approval Required</Badge>
                <span
                  style={{
                    fontSize: ".82rem",
                    fontWeight: 600,
                    color: "#e8f4ee",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {a.title}
                </span>
              </div>
              <div
                style={{
                  fontSize: ".74rem",
                  color: "#7a9e92",
                  lineHeight: 1.4,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {(a.detail || "").slice(0, 140)}
                {(a.detail || "").length > 140 ? "…" : ""}
              </div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
            <Btn size="sm" variant="green" onClick={() => onApprove(a)}>
              Approve
            </Btn>
            <Btn size="sm" variant="danger" onClick={() => onReject(a)}>
              Reject
            </Btn>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Sidebar ───────────────────────────────────────────────────────────────
function Sidebar({
  runs,
  selected,
  onSelect,
  mode,
  setMode,
  target,
  setTarget,
  sourceType,
  setSourceType,
  githubUrl,
  setGithubUrl,
  githubRef,
  setGithubRef,
  localPath,
  setLocalPath,
  onUpload,
  uploadLabel,
}: {
  runs: Run[];
  selected: Run | null;
  onSelect: (r: Run) => void;
  mode: string;
  setMode: (v: string) => void;
  target: string;
  setTarget: (v: string) => void;
  sourceType: "none" | "github" | "local" | "upload";
  setSourceType: (v: "none" | "github" | "local" | "upload") => void;
  githubUrl: string;
  setGithubUrl: (v: string) => void;
  githubRef: string;
  setGithubRef: (v: string) => void;
  localPath: string;
  setLocalPath: (v: string) => void;
  onUpload: (file: File) => void;
  uploadLabel: string;
}) {
  return (
    <aside className="vx-sidebar">
      <div className="vx-sidebar-inner">
        <div
          style={{
            marginBottom: 14,
            border: "1px solid rgba(217,58,73,.24)",
            borderRadius: 8,
            padding: 10,
            background: "rgba(255,255,255,.02)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <div
              style={{
                width: 24,
                height: 24,
                borderRadius: 6,
                background: "linear-gradient(145deg,#25080d,#511019)",
                border: "1px solid rgba(217,58,73,.4)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: ".7rem",
                color: "#ff6d7a",
                fontWeight: 700,
              }}
            >
              VX
            </div>
            <div
              style={{
                fontSize: ".62rem",
                fontWeight: 700,
                letterSpacing: ".1em",
                textTransform: "uppercase",
                color: "#a69599",
              }}
            >
              Autonomous Offensive Security Suite
            </div>
          </div>
          <div
            style={{
              fontSize: "2.1rem",
              fontWeight: 700,
              letterSpacing: ".14em",
              lineHeight: 0.9,
              color: "#19c37d",
              fontFamily: "var(--mono)",
            }}
          >
            VANTIX
          </div>
          <div style={{ fontSize: ".68rem", color: "#a69599", marginTop: 6 }}>Recon · Exploit · Forge · Report</div>
        </div>
        <div style={{ display: "flex", gap: 5, marginBottom: 18, flexWrap: "wrap" }}>
          <Badge variant="ok">● Codex</Badge>
          <Badge variant="ok">● Worker</Badge>
        </div>
        <div style={{ marginBottom: 16 }}>
          <div
            style={{
              fontSize: ".66rem",
              fontWeight: 700,
              letterSpacing: ".1em",
              textTransform: "uppercase",
              color: "#7a9e92",
              marginBottom: 7,
            }}
          >
            Module
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {MODES.map((m) => (
              <button
                key={m}
                onClick={() => setMode(m)}
                style={{
                  padding: "3px 9px",
                  borderRadius: 6,
                  fontSize: ".68rem",
                  fontWeight: 600,
                  background: mode === m ? "rgba(217,58,73,.2)" : "rgba(255,255,255,.04)",
                  border: `1px solid ${mode === m ? "rgba(217,58,73,.45)" : "rgba(217,58,73,.18)"}`,
                  color: mode === m ? "#ff6d7a" : "#a69599",
                  transition: "all .15s",
                }}
              >
                {m}
              </button>
            ))}
          </div>
        </div>
        <div style={{ marginBottom: 20 }}>
          <div
            style={{
              fontSize: ".66rem",
              fontWeight: 700,
              letterSpacing: ".1em",
              textTransform: "uppercase",
              color: "#7a9e92",
              marginBottom: 6,
            }}
          >
            Target
          </div>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="10.10.10.10 or https://target"
            style={{
              width: "100%",
              padding: "8px 11px",
              background: "rgba(5,10,10,.9)",
              border: "1px solid rgba(217,58,73,.25)",
              borderRadius: 8,
              color: "#e8f4ee",
              fontSize: ".76rem",
            }}
          />
          <div style={{ fontSize: ".66rem", color: "#7a9e92", marginTop: 5 }}>
            Use the chat to launch or continue an engagement.
          </div>
        </div>
        <div style={{ marginBottom: 18 }}>
          <div style={{ fontSize: ".66rem", fontWeight: 700, letterSpacing: ".1em", textTransform: "uppercase", color: "#7a9e92", marginBottom: 6 }}>
            Source (White-box)
          </div>
          <select
            value={sourceType}
            onChange={(e) => setSourceType(e.target.value as "none" | "github" | "local" | "upload")}
            style={{ width: "100%", padding: "8px 10px", background: "rgba(5,10,10,.9)", border: "1px solid rgba(217,58,73,.25)", borderRadius: 8, color: "#e8f4ee", fontSize: ".74rem", marginBottom: 6 }}
          >
            <option value="none">None (black-box)</option>
            <option value="github">GitHub Repo</option>
            <option value="local">Local Path</option>
            <option value="upload">Upload Zip</option>
          </select>
          {sourceType === "github" && (
            <div style={{ display: "grid", gap: 6 }}>
              <input
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                placeholder="https://github.com/org/repo"
                style={{ width: "100%", padding: "7px 10px", background: "rgba(5,10,10,.9)", border: "1px solid rgba(217,58,73,.2)", borderRadius: 8, color: "#e8f4ee", fontSize: ".72rem" }}
              />
              <input
                value={githubRef}
                onChange={(e) => setGithubRef(e.target.value)}
                placeholder="branch/tag/commit (optional)"
                style={{ width: "100%", padding: "7px 10px", background: "rgba(5,10,10,.9)", border: "1px solid rgba(217,58,73,.2)", borderRadius: 8, color: "#e8f4ee", fontSize: ".72rem" }}
              />
            </div>
          )}
          {sourceType === "local" && (
            <input
              value={localPath}
              onChange={(e) => setLocalPath(e.target.value)}
              placeholder="/path/to/source"
              style={{ width: "100%", padding: "7px 10px", background: "rgba(5,10,10,.9)", border: "1px solid rgba(217,58,73,.2)", borderRadius: 8, color: "#e8f4ee", fontSize: ".72rem" }}
            />
          )}
          {sourceType === "upload" && (
            <div style={{ display: "grid", gap: 6 }}>
              <input
                type="file"
                accept=".zip,application/zip"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) onUpload(file);
                }}
                style={{ width: "100%", padding: "4px", fontSize: ".7rem", color: "#e8f4ee" }}
              />
              <div style={{ fontSize: ".65rem", color: "#7a9e92" }}>{uploadLabel || "No upload staged yet."}</div>
            </div>
          )}
        </div>
        <div>
          <div
            style={{
              fontSize: ".66rem",
              fontWeight: 700,
              letterSpacing: ".1em",
              textTransform: "uppercase",
              color: "#7a9e92",
              marginBottom: 8,
            }}
          >
            Recent Engagements
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
            {runs.length === 0 && (
              <div style={{ fontSize: ".7rem", color: "#7a9e92" }}>No runs yet.</div>
            )}
            {runs.map((run) => {
              const variant: Variant =
                run.status === "running" ? "amber" : run.status === "completed" ? "ok" : run.status === "failed" ? "danger" : "default";
              return (
                <button
                  key={run.id}
                  className={`vx-run-card ${selected?.id === run.id ? "active" : ""}`}
                  onClick={() => onSelect(run)}
                >
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                    <span
                      style={{
                        fontFamily: "var(--mono)",
                        fontSize: ".72rem",
                        fontWeight: 600,
                        color: "#e8f4ee",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {run.workspace_id}
                    </span>
                    <Badge variant={variant}>{run.status}</Badge>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <StatusDot status={run.status} size={6} />
                    <span style={{ fontSize: ".68rem", color: "#7a9e92" }}>{run.mode}</span>
                  </div>
                  <div
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: ".66rem",
                      color: "#7a9e92",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {run.target}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </aside>
  );
}

// ─── Top bar ───────────────────────────────────────────────────────────────
function TopBar({
  run,
  phase,
  workflowState,
  statusMsg,
  onRefresh,
  onPause,
  onRetry,
  onReplan,
  onCancel,
}: {
  run: Run | null;
  phase: RunPhase | null;
  workflowState: WorkflowState | null;
  statusMsg: string;
  onRefresh: () => void;
  onPause: () => void;
  onRetry: () => void;
  onReplan: () => void;
  onCancel: () => void;
}) {
  const runVariant: Variant =
    run?.status === "running"
      ? "amber"
      : run?.status === "completed"
      ? "ok"
      : run?.status === "failed" || run?.status === "blocked"
      ? "danger"
      : "default";
  return (
    <div className="vx-topbar">
      <div style={{ minWidth: 0, flex: 1 }}>
        <div
          style={{
            fontSize: ".63rem",
            fontWeight: 700,
            letterSpacing: ".12em",
            textTransform: "uppercase",
            color: "#7a9e92",
            marginBottom: 4,
          }}
        >
          Vantix Orchestrator
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <span style={{ fontFamily: "var(--mono)", fontSize: "1rem", fontWeight: 700, color: "#e8f4ee" }}>
            {run ? run.workspace_id : "No active engagement"}
          </span>
          {run && <Badge variant={runVariant}>{run.status}</Badge>}
          {run && <Badge variant="default">{run.mode}</Badge>}
          {phase && <Badge variant="amber">↳ {phase.current}</Badge>}
          {workflowState?.workers?.length ? <Badge variant="blue">workers {metricNumber(workflowState, "active_worker_count")}</Badge> : null}
          {metricNumber(workflowState, "approval_pending_count") > 0 ? (
            <Badge variant="warn">approvals {metricNumber(workflowState, "approval_pending_count")}</Badge>
          ) : null}
        </div>
        {run && (
          <div
            style={{
              fontFamily: "var(--mono)",
              fontSize: ".7rem",
              color: "#7a9e92",
              marginTop: 4,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {run.target} — {(run.objective || "").slice(0, 90)}
            {(run.objective || "").length > 90 ? "…" : ""}
          </div>
        )}
        {workflowState?.workflow?.blocked_reason ? (
          <div style={{ fontSize: ".72rem", color: "#ef4444", marginTop: 4 }}>
            Blocked: {workflowState.workflow.blocked_reason}
          </div>
        ) : null}
        {statusMsg && <div style={{ fontSize: ".72rem", color: "#f4b860", marginTop: 4 }}>{statusMsg}</div>}
      </div>
      {run && (
        <div style={{ display: "flex", gap: 6, flexShrink: 0, flexWrap: "wrap", justifyContent: "flex-end" }}>
          <Btn size="sm" variant="ghost" onClick={onRefresh}>
            Refresh
          </Btn>
          <Btn size="sm" variant="ghost" onClick={onPause}>
            Pause
          </Btn>
          <Btn size="sm" variant="ghost" onClick={onRetry}>
            Retry
          </Btn>
          <Btn size="sm" variant="amber" onClick={onReplan}>
            Replan
          </Btn>
          <Btn size="sm" variant="danger" onClick={onCancel}>
            Cancel
          </Btn>
        </div>
      )}
    </div>
  );
}

// ─── App ───────────────────────────────────────────────────────────────────
type Tab = "overview" | "intel" | "results" | "config";

export default function App() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [connected, setConnected] = useState(false);
  const [testing, setTesting] = useState(false);
  const [note, setNote] = useState("");
  const [noteClassification, setNoteClassification] = useState<"unrestricted" | "internal" | "sensitive">("unrestricted");

  const [runs, setRuns] = useState<Run[]>([]);
  const [selectedRun, setSelectedRun] = useState<Run | null>(null);
  const [phase, setPhase] = useState<RunPhase | null>(null);
  const [workflowState, setWorkflowState] = useState<WorkflowState | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [messages, setMessages] = useState<RunMessage[]>([]);
  const [vectors, setVectors] = useState<Vector[]>([]);
  const [facts, setFacts] = useState<Fact[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [results, setResults] = useState<RunResults | null>(null);
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [skillApps, setSkillApps] = useState<RunSkillApplication[]>([]);
  const [agents, setAgents] = useState<AgentSession[]>([]);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [learning, setLearning] = useState<Array<Record<string, unknown>>>([]);
  const [browserState, setBrowserState] = useState<BrowserState | null>(null);
  const [sourceStatus, setSourceStatus] = useState<SourceStatus | null>(null);
  const [replayState, setReplayState] = useState<ReplayState | null>(null);
  const [termLines, setTermLines] = useState<string[]>([]);

  const [tab, setTab] = useState<Tab>("overview");
  const [chatText, setChatText] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const [mode, setMode] = useState("pentest");
  const [target, setTarget] = useState("");
  const [sourceType, setSourceType] = useState<"none" | "github" | "local" | "upload">("none");
  const [githubUrl, setGithubUrl] = useState("");
  const [githubRef, setGithubRef] = useState("");
  const [localPath, setLocalPath] = useState("");
  const [stagedUploadId, setStagedUploadId] = useState("");

  const streamRef = useRef<EventSource | null>(null);
  const selectedRunRef = useRef<string>("");
  const terminalSequenceRef = useRef<Record<string, number>>({});

  const flash = useCallback((msg: string) => {
    setStatusMsg(msg);
    window.setTimeout(() => setStatusMsg(""), 5000);
  }, []);

  const handleLogout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // ignore — we still drop client state below
    }
    setUser(null);
    setConnected(false);
  }, []);

  const testConnection = useCallback(async () => {
    setTesting(true);
    try {
      await api.systemStatus();
      setConnected(true);
      flash("Connected to live API");
    } catch (error) {
      setConnected(false);
      if (error instanceof ApiError && error.status === 401) {
        setUser(null);
      } else {
        flash(`Cannot reach API: ${error instanceof Error ? error.message : String(error)}`);
      }
    } finally {
      setTesting(false);
    }
  }, [flash]);

  // Bootstrap: detect existing session via cookie, else show Login
  useEffect(() => {
    hydrateCsrfFromCookie();
    (async () => {
      try {
        const me = await api.me();
        setUser(me);
        setConnected(true);
      } catch {
        setUser(null);
      } finally {
        setAuthChecked(true);
      }
    })();
  }, []);

  const refreshRuns = useCallback(async () => {
    try {
      const rows = await api.listRuns();
      setRuns(rows);
      setSelectedRun((current) => {
        if (!current) return current;
        const refreshed = rows.find((item) => item.id === current.id);
        return refreshed || null;
      });
    } catch (error) {
      flash(`Run list failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }, [flash]);

  const refreshRun = useCallback(
    async (runId: string, opts?: { incrementalTerminal?: boolean }) => {
      try {
        const incrementalTerminal = Boolean(opts?.incrementalTerminal);
        const sinceSequence = terminalSequenceRef.current[runId] || 0;
        const failures: string[] = [];
        const track = <T,>(label: string, fallback: T) =>
          (err: unknown) => {
            failures.push(label);
            // eslint-disable-next-line no-console
            console.warn(`[refreshRun] ${label} failed:`, err);
            return fallback;
          };
        const [run, graph, runApprovals, workflow, runSourceStatus, runReplay, runFacts, learningHits, runMessages, runEvents, runVectors, runResults, runSkills, runChains, runBrowserState, runTerminal] =
          await Promise.all([
            api.getRun(runId),
            api.getGraph(runId),
            api.getApprovals(runId).catch(track<Approval[]>("approvals", [])),
            api.getWorkflowState(runId).catch(track<WorkflowState | null>("workflow", null)),
            api.getSourceStatus(runId).catch(track<SourceStatus | null>("source", null)),
            api.getReplay(runId).catch(track<ReplayState | null>("replay", null)),
            api.getFacts(runId).catch(track<Fact[]>("facts", [])),
            api.getLearning(runId).catch(track("learning", { run_id: runId, mode: "", results: [] as Array<Record<string, unknown>> })),
            api.getMessages(runId).catch(track<RunMessage[]>("messages", [])),
            api.getEvents(runId, 0, 300).catch(track<EventRecord[]>("events", [])),
            api.getVectors(runId).catch(track<Vector[]>("vectors", [])),
            api.getResults(runId).catch(track<RunResults | null>("results", null)),
            api.getSkills(runId).catch(track<RunSkillApplication[]>("skills", [])),
            api.getAttackChains(runId).catch(track<AttackChain[]>("chains", [])),
            api.getBrowserState(runId).catch(track<BrowserState | null>("browser", null)),
            api.getTerminal(runId, incrementalTerminal ? sinceSequence : 0, 250, !incrementalTerminal).catch(
              track("terminal", { run_id: runId, content: "", last_sequence: sinceSequence }),
            ),
          ]);
        if (selectedRunRef.current !== runId) return;
        if (failures.length > 0) {
          flash(`Partial load: ${failures.join(", ")} unavailable`);
        }
        setSelectedRun(run);
        setRuns((rows) => rows.map((item) => (item.id === run.id ? run : item)));
        setPhase(graph.phase);
        setWorkflowState(workflow);
        setSourceStatus(runSourceStatus);
        setReplayState(runReplay);
        setAgents(graph.agents);
        setTasks(graph.tasks);
        setApprovals(runApprovals.length ? runApprovals : graph.approvals);
        setFacts(runFacts);
        setLearning(learningHits.results);
        setEvents(runEvents);
        setMessages(mergeTimeline(runMessages, runEvents));
        setVectors(runVectors);
        setResults(runResults);
        setFindings(runResults?.findings || []);
        setSkillApps(runSkills);
        setChains(runChains);
        setBrowserState(runBrowserState);
        const delta = runTerminal?.content ? runTerminal.content.split("\n").filter(Boolean) : [];
        terminalSequenceRef.current[runId] = runTerminal?.last_sequence || terminalSequenceRef.current[runId] || 0;
        if (!incrementalTerminal) {
          setTermLines(delta.slice(-250));
        } else if (delta.length) {
          setTermLines((lines) => [...lines, ...delta].slice(-250));
        }
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) {
          setSelectedRun(null);
          setWorkflowState(null);
          setSourceStatus(null);
          setReplayState(null);
          setEvents([]);
          flash("Selected run no longer exists.");
          refreshRuns();
          return;
        }
        flash(`Load error: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
    [flash, refreshRuns],
  );

  // Load run list when connected
  useEffect(() => {
    if (!connected) return;
    (async () => {
      await refreshRuns();
    })();
  }, [connected, refreshRuns]);

  // Watch selected run; poll / stream while in live mode
  useEffect(() => {
    streamRef.current?.close();
    streamRef.current = null;
    setTermLines([]);
    if (!connected || !selectedRun) return;
    selectedRunRef.current = selectedRun.id;
    terminalSequenceRef.current[selectedRun.id] = 0;
    refreshRun(selectedRun.id, { incrementalTerminal: false });
    const pollHandle = window.setInterval(() => {
      if (selectedRunRef.current !== selectedRun.id) return;
      refreshRun(selectedRun.id, { incrementalTerminal: true });
    }, 2000);
    let source: EventSource | null = null;
    try {
      source = new EventSource(`/api/v1/runs/${selectedRun.id}/stream`);
      source.onmessage = (event) => {
        if (selectedRunRef.current !== selectedRun.id) return;
        try {
          const data = JSON.parse(event.data) as EventRecord;
          if (data.event_type === "terminal") {
            terminalSequenceRef.current[selectedRun.id] = data.sequence;
            setTermLines((lines) => [...lines.slice(-199), data.message]);
          } else {
            refreshRun(selectedRun.id, { incrementalTerminal: true });
          }
        } catch {
          /* ignore */
        }
      };
      source.onerror = () => {
        source?.close();
        refreshRun(selectedRun.id, { incrementalTerminal: true });
      };
      streamRef.current = source;
    } catch {
      // EventSource unavailable — silent
    }
    return () => {
      window.clearInterval(pollHandle);
      source?.close();
    };
  }, [connected, selectedRun?.id, refreshRun]);

  function buildSourceInput(): SourceInput {
    if (sourceType === "github") return { type: "github", github: { url: githubUrl.trim(), ref: githubRef.trim() || undefined } };
    if (sourceType === "local") return { type: "local", local: { path: localPath.trim() } };
    if (sourceType === "upload") return { type: "upload", upload: { staged_upload_id: stagedUploadId.trim() } };
    return { type: "none" };
  }

  async function submitChatMessage(message: string, forceNew: boolean) {
    const sourceInput = buildSourceInput();
    const sourceMetadata = { source_input: sourceInput, ...(forceNew ? { start_new_run: true } : {}) };
    const res = await api.submitChat({
      message,
      run_id: selectedRun && !forceNew ? selectedRun.id : undefined,
      mode,
      target: forceNew || !selectedRun ? target || undefined : undefined,
      metadata: sourceMetadata,
    });
    setSelectedRun(res.run);
    flash(res.scheduler_status);
    await refreshRuns();
    await refreshRun(res.run.id);
  }

  async function handleSend(event: FormEvent) {
    event.preventDefault();
    if (!chatText.trim()) return;
    const txt = chatText;
    const sourceInput = buildSourceInput();
    const newTarget = target.trim();
    const targetChanged = Boolean(selectedRun && newTarget && newTarget !== (selectedRun.target || ""));
    const sourceAttached = sourceInput.type !== "none";
    const shouldStartNew = Boolean(selectedRun && (targetChanged || sourceAttached));
    setChatText("");
    const userMsg: RunMessage = {
      id: `m${Date.now()}`,
      run_id: selectedRun?.id || "",
      role: "user",
      author: "Operator",
      content: txt,
      metadata: {},
      created_at: "",
    };
    setMessages((m) => [...m, userMsg]);
    setChatLoading(true);
    try {
      await submitChatMessage(txt, shouldStartNew);
    } catch (err) {
      setMessages((m) => [
        ...m,
        {
          id: `m${Date.now() + 1}`,
          run_id: selectedRun?.id || "",
          role: "system",
          author: "System",
          content: `Error: ${err instanceof Error ? err.message : String(err)}`,
          metadata: {},
          created_at: "",
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  }

  async function handleUploadSource(file: File) {
    try {
      const staged = await api.stageSourceUpload(file);
      setStagedUploadId(staged.staged_upload_id);
      flash(`Upload staged: ${staged.filename}`);
    } catch (error) {
      flash(`Upload failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async function handleApprove(a: Approval) {
    try {
      await api.approve(a.id);
    } catch (error) {
      flash(`Approve failed: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    if (selectedRun) {
      await refreshRun(selectedRun.id, { incrementalTerminal: true });
      await refreshRuns();
      try {
        const rows = await api.getApprovals(selectedRun.id);
        setApprovals(rows);
      } catch {
        // ignore; refreshRun already attempted
      }
    }
    setApprovals((ap) => ap.map((x) => (x.id === a.id ? { ...x, status: "approved" } : x)));
    flash(`Approved: ${a.title}`);
  }
  async function handleReject(a: Approval) {
    try {
      await api.reject(a.id);
    } catch (error) {
      flash(`Reject failed: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    if (selectedRun) {
      await refreshRun(selectedRun.id, { incrementalTerminal: true });
      await refreshRuns();
      try {
        const rows = await api.getApprovals(selectedRun.id);
        setApprovals(rows);
      } catch {
        // ignore; refreshRun already attempted
      }
    }
    setApprovals((ap) => ap.map((x) => (x.id === a.id ? { ...x, status: "rejected" } : x)));
    flash(`Rejected: ${a.title}`);
  }
  async function handleSelectVector(v: Vector) {
    if (selectedRun) {
      try {
        await api.selectVector(selectedRun.id, v.id);
      } catch (error) {
        flash(`Select failed: ${error instanceof Error ? error.message : String(error)}`);
        return;
      }
      refreshRun(selectedRun.id);
    }
    setVectors((vs) => vs.map((x) => (x.id === v.id ? { ...x, status: "selected" } : x)));
    flash(`Vector selected: ${v.title}`);
  }
  async function handlePromoteVector(v: Vector) {
    if (!selectedRun) return;
    try {
      await api.promoteFinding(selectedRun.id, {
        source_kind: "vector",
        source_id: v.id,
        title: v.title,
        severity: v.severity,
        summary: v.summary,
        evidence: v.evidence,
      });
    } catch (error) {
      flash(`Promote failed: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    refreshRun(selectedRun.id);
    flash(`Promoted: ${v.title}`);
  }
  async function handlePromoteChain(c: AttackChain) {
    if (!selectedRun) return;
    try {
      await api.promoteFinding(selectedRun.id, {
        source_kind: "attack_chain",
        source_id: c.id,
        title: c.name,
        evidence: c.notes,
      });
    } catch (error) {
      flash(`Promote failed: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    refreshRun(selectedRun.id);
    flash(`Chain promoted: ${c.name}`);
  }
  async function handleApplySkills() {
    if (!selectedRun) return;
    try {
      await api.applySkills(selectedRun.id);
      refreshRun(selectedRun.id);
      flash("Skills reapplied");
    } catch (error) {
      flash(`Apply failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  async function handleSaveNote() {
    if (!selectedRun || !note.trim()) return;
    try {
      await api.addNote(selectedRun.id, note, noteClassification);
    } catch (error) {
      flash(`Save failed: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    setNote("");
    setNoteClassification("unrestricted");
    flash("Note saved");
  }

  function handleSelectRun(run: Run) {
    setSelectedRun(run);
    selectedRunRef.current = run.id;
    terminalSequenceRef.current[run.id] = 0;
    setTermLines([]);
    refreshRun(run.id, { incrementalTerminal: false });
  }
  const cveFacts = useMemo(
    () =>
      facts.filter((f) => {
        const kind = String(f.kind || "").toLowerCase();
        if (["port", "service", "host", "banner", "version"].includes(kind)) return false;
        if (String(f.source || "").toLowerCase() === "scheduler") return false;
        return ["cve", "intel", "exploit", "attack_chain", "vuln", "vulnerability"].includes(kind);
      }),
    [facts],
  );

  const TABS: Array<{ id: Tab; label: string }> = [
    { id: "overview", label: "Overview" },
    { id: "intel", label: "Intel" },
    { id: "results", label: "Results & Report" },
    { id: "config", label: "Config" },
  ];

  async function runAction(action: "pause" | "retry" | "replan" | "cancel" | "refresh") {
    if (!selectedRun) return;
    if (action === "refresh") {
      refreshRun(selectedRun.id);
      flash("Refreshed");
      return;
    }
    try {
      if (action === "pause") await api.pauseRun(selectedRun.id);
      else if (action === "retry") await api.retryRun(selectedRun.id);
      else if (action === "replan") await api.replanRun(selectedRun.id);
      else if (action === "cancel") await api.cancelRun(selectedRun.id);
      flash(`${action} issued`);
      refreshRuns();
      refreshRun(selectedRun.id);
    } catch (error) {
      flash(error instanceof Error ? error.message : String(error));
    }
  }

  async function handleOpenPath(path: string) {
    if (!selectedRun || !path) return;
    try {
      const blob = await api.fetchRunFileBlob(selectedRun.id, path);
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank", "noopener,noreferrer");
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (error) {
      flash(`Open failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  if (!authChecked) {
    return <div className="login-shell"><div className="muted">Loading…</div></div>;
  }
  if (!user) {
    return (
      <Login
        onSuccess={(u) => {
          setUser(u);
          setAuthChecked(true);
          testConnection();
        }}
      />
    );
  }

  return (
    <div className="vx-shell">
      <Sidebar
        runs={runs}
        selected={selectedRun}
        onSelect={handleSelectRun}
        mode={mode}
        setMode={setMode}
        target={target}
        setTarget={setTarget}
        sourceType={sourceType}
        setSourceType={setSourceType}
        githubUrl={githubUrl}
        setGithubUrl={setGithubUrl}
        githubRef={githubRef}
        setGithubRef={setGithubRef}
        localPath={localPath}
        setLocalPath={setLocalPath}
        onUpload={handleUploadSource}
        uploadLabel={stagedUploadId ? `Staged: ${stagedUploadId}` : ""}
      />
      <main className="vx-main">
        <TopBar
          run={selectedRun}
          phase={phase}
          workflowState={workflowState}
          statusMsg={statusMsg}
          onRefresh={() => runAction("refresh")}
          onPause={() => runAction("pause")}
          onRetry={() => runAction("retry")}
          onReplan={() => runAction("replan")}
          onCancel={() => runAction("cancel")}
        />
        <RiskBar run={selectedRun} findings={findings} phase={phase} connected={connected} />
        <PendingApprovalsBanner approvals={approvals} onApprove={handleApprove} onReject={handleReject} />

        <div className="vx-tabs">
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`vx-tab ${tab === t.id ? "active" : ""}`}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>

        {tab === "overview" && (
          <div className="vx-grid">
            <ExecSummary run={selectedRun} findings={findings} phase={phase} approvals={approvals} />
            <ChatPanel
              messages={messages}
              chatText={chatText}
              setChatText={setChatText}
              onSend={handleSend}
              loading={chatLoading}
            />
            <PhasePanel phase={phase} />
            <AgentsPanel agents={agents} tasks={tasks} roles={ROLES} phase={phase} />
            <ControlCenterPanel workflowState={workflowState} approvals={approvals} />
            <TimelinePanel events={events} />
            <TerminalPanel lines={termLines} />
          </div>
        )}

        {tab === "intel" && (
          <div className="vx-grid">
            <VectorsPanel
              vectors={vectors}
              selectedRunId={selectedRun?.id}
              onSelect={handleSelectVector}
              onPromote={handlePromoteVector}
            />
            <CvePanel facts={cveFacts} />
            <BrowserPanel state={browserState} selectedRunId={selectedRun?.id} onOpenPath={handleOpenPath} />
            <MemoryPanel hits={learning} />
            <ChainsPanel chains={chains} onPromote={handlePromoteChain} selectedRunId={selectedRun?.id} />
          </div>
        )}

        {tab === "results" && (
          <div className="vx-grid">
            <ResultsPanel results={results} selectedRunId={selectedRun?.id} onOpenPath={handleOpenPath} />
            <ReplayPanel replay={replayState} />
          </div>
        )}

        {tab === "config" && (
          <div className="vx-grid">
            <ApprovalsPanel approvals={approvals} onApprove={handleApprove} onReject={handleReject} />
            <ControlCenterPanel workflowState={workflowState} approvals={approvals} />
            <SourcePanel sourceStatus={sourceStatus} />
            <SkillsPanel applications={skillApps} onApply={handleApplySkills} selectedRunId={selectedRun?.id} />
            <NotesPanel
              note={note}
              setNote={setNote}
              classification={noteClassification}
              setClassification={setNoteClassification}
              onSave={handleSaveNote}
              canSave={Boolean(selectedRun && note.trim()) && user?.role !== "viewer"}
            />
            {user ? (
              <AccountPanel
                user={user}
                connected={connected}
                onTest={testConnection}
                testing={testing}
                onLogout={handleLogout}
              />
            ) : null}
          </div>
        )}
      </main>
    </div>
  );
}
