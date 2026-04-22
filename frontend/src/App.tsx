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
  critical: { bg: "var(--danger-soft)", color: "var(--danger)", border: "var(--danger)" },
  high:     { bg: "var(--warn-soft)",   color: "var(--warn)",   border: "var(--warn)" },
  medium:   { bg: "var(--info-soft)",   color: "var(--info)",   border: "var(--info)" },
  low:      { bg: "var(--ok-soft)",     color: "var(--ok)",     border: "var(--ok)" },
  ok:       { bg: "var(--ok-soft)",     color: "var(--ok)",     border: "var(--ok)" },
  warn:     { bg: "var(--warn-soft)",   color: "var(--warn)",   border: "var(--warn)" },
  danger:   { bg: "var(--danger-soft)", color: "var(--danger)", border: "var(--danger)" },
  amber:    { bg: "var(--warn-soft)",   color: "var(--warn)",   border: "var(--warn)" },
  blue:     { bg: "var(--info-soft)",   color: "var(--info)",   border: "var(--info)" },
  default:  { bg: "var(--surface-3)",   color: "var(--ink-dim)", border: "var(--line-strong)" },
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
        height: 20,
        padding: "0 8px",
        borderRadius: 99,
        fontSize: ".68rem",
        fontWeight: 600,
        letterSpacing: ".04em",
        textTransform: "uppercase",
        background: c.bg,
        color: c.color,
        border: `1px solid ${c.border}`,
        whiteSpace: "nowrap",
        lineHeight: 1,
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

// P3-5 — hypothesis / validated / refuted lifecycle chip for a vector.
function VectorLifecycleBadge({ vector }: { vector: Vector }) {
  const meta = (vector.metadata || {}) as Record<string, unknown>;
  const status = String(vector.status || "").toLowerCase();
  const refuted =
    status === "refuted" || meta.refuted === true || String(meta.fact_kind || "") === "negative_evidence";
  const validated = !refuted && (status === "validated" || meta.validated === true);
  if (refuted) return <Badge variant="danger">refuted</Badge>;
  if (validated) return <Badge variant="ok">validated</Badge>;
  return <Badge variant="default">hypothesis</Badge>;
}

function StatusDot({ status, size = 8 }: { status?: string; size?: number }) {
  const cols: Record<string, string> = {
    running: "var(--warn)",
    completed: "var(--ok)",
    failed: "var(--danger)",
    blocked: "var(--danger)",
    pending: "var(--ink-muted)",
    idle: "var(--ink-muted)",
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
  const color = pct >= 80 ? "var(--ok)" : pct >= 50 ? "var(--warn)" : "var(--danger)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div
        style={{
          flex: 1,
          height: 3,
          background: "var(--surface-3)",
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
          color: "var(--ink-dim)",
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
        color: "var(--ink-dim)",
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
        border: "2px solid var(--ok)",
        borderTopColor: "var(--ok)",
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
    primary: { background: "var(--accent)", color: "var(--accent-ink)", border: "1px solid var(--accent)" },
    ghost: { background: "var(--surface-2)", color: "var(--ink)", border: "1px solid var(--line-strong)" },
    danger: { background: "var(--danger-soft)", color: "var(--danger)", border: "1px solid var(--danger)" },
    amber: { background: "var(--warn-soft)", color: "var(--warn)", border: "1px solid var(--warn)" },
    green: { background: "var(--ok-soft)", color: "var(--ok)", border: "1px solid var(--ok)" },
    blue: { background: "var(--info-soft)", color: "var(--info)", border: "1px solid var(--info)" },
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
        fontSize: ".66rem",
        fontWeight: 600,
        letterSpacing: ".1em",
        textTransform: "uppercase",
        color: "var(--ink-dim)",
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
  scroll = false,
}: {
  title: string;
  meta?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  style?: CSSProperties;
  loading?: boolean;
  scroll?: boolean;
}) {
  const body = scroll ? <div className="vx-panel-scroll">{children}</div> : children;
  return (
    <article className="vx-panel" style={style}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          marginBottom: 14,
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span
            style={{
              fontSize: ".72rem",
              fontWeight: 700,
              letterSpacing: ".09em",
              textTransform: "uppercase",
              color: "var(--ink)",
            }}
          >
            {title}
          </span>
          {meta && <span style={{ fontSize: ".72rem", color: "var(--ink-dim)" }}>{meta}</span>}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {loading && <Spinner />}
          {action}
        </div>
      </div>
      {body}
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
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginRight: 4 }}>
        <StatusDot status={run.status} size={7} />
        <span
          style={{ fontFamily: "var(--mono)", fontSize: ".74rem", fontWeight: 600, color: "var(--ink)" }}
        >
          {run.workspace_id}
        </span>
      </div>
      <div className="vx-riskbar-sep" />
      {risk && (
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span className="vx-label">Risk</span>
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
      <div className="vx-riskbar-sep" />
      <div style={{ display: "flex", gap: 10 }}>
        {[
          ["critical", "var(--danger)"],
          ["high", "var(--warn)"],
          ["medium", "var(--info)"],
          ["low", "var(--ok)"],
        ].map(([k, c]) => (
          <div key={k} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <span
              style={{ width: 6, height: 6, borderRadius: "50%", background: c, display: "block", flexShrink: 0 }}
            />
            <span
              style={{
                fontSize: ".74rem",
                color: counts[k] > 0 ? "var(--ink)" : "var(--ink-dim)",
                fontWeight: counts[k] > 0 ? 600 : 400,
                fontFamily: "var(--mono)",
              }}
            >
              {counts[k]}
            </span>
            <span style={{ fontSize: ".68rem", color: "var(--ink-dim)", textTransform: "capitalize" }}>
              {k}
            </span>
          </div>
        ))}
      </div>
      <div className="vx-riskbar-sep" />
      <div style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 160 }}>
        <span className="vx-label">Progress</span>
        <div
          style={{
            flex: 1,
            height: 4,
            background: "var(--surface-3)",
            borderRadius: 99,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${phasePct}%`,
              height: "100%",
              background: "var(--accent)",
              borderRadius: 99,
              transition: "width .5s",
            }}
          />
        </div>
        <span
          style={{ fontFamily: "var(--mono)", fontSize: ".72rem", color: "var(--ink-dim)", whiteSpace: "nowrap" }}
        >
          {phasePct}%
        </span>
      </div>
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
        {connected ? <Badge variant="ok">● Live</Badge> : <Badge variant="danger">Offline</Badge>}
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
  const cardStyle: CSSProperties = {
    padding: "10px 12px",
    background: "var(--surface)",
    border: "1px solid var(--line)",
    borderRadius: "var(--radius-md)",
    display: "flex",
    flexDirection: "column",
    minHeight: 0,
    minWidth: 0,
    overflow: "hidden",
    boxShadow: "var(--shadow-sm)",
  };
  const headStyle: CSSProperties = {
    fontSize: ".64rem",
    fontWeight: 700,
    letterSpacing: ".1em",
    textTransform: "uppercase",
    color: "var(--ink-dim)",
    marginBottom: 8,
    flexShrink: 0,
  };
  const bulletStyle: CSSProperties = { fontSize: ".72rem", color: "var(--ink)", lineHeight: 1.4 };
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr 1fr",
        gap: 10,
        flexShrink: 0,
      }}
    >
      <div style={cardStyle}>
        <div style={headStyle}>Engagement Status</div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {risk && (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                width: 44,
                height: 44,
                borderRadius: 10,
                background: SEV[risk.variant].bg,
                border: `1px solid ${SEV[risk.variant].border}`,
                flexShrink: 0,
              }}
            >
              <span
                style={{
                  fontFamily: "var(--mono)",
                  fontSize: ".95rem",
                  fontWeight: 700,
                  color: SEV[risk.variant].color,
                  lineHeight: 1,
                }}
              >
                {risk.score}
              </span>
              <span
                style={{
                  fontSize: ".5rem",
                  color: SEV[risk.variant].color,
                  letterSpacing: ".06em",
                  textTransform: "uppercase",
                }}
              >
                risk
              </span>
            </div>
          )}
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: ".8rem", fontWeight: 700, color: "var(--ink)" }}>
              {risk?.level || "Pending"} Risk
            </div>
            <div style={{ fontSize: ".7rem", color: "var(--ink-dim)" }}>
              {phaseLabels[currentDisplay] || "Initializing"}
            </div>
            <div
              style={{
                fontSize: ".68rem",
                color: "var(--ink-dim)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {run.target}
            </div>
          </div>
        </div>
        {pendingApprovals.length > 0 && (
          <div
            style={{
              marginTop: 8,
              padding: "6px 9px",
              borderRadius: 8,
              background: "var(--warn-soft)",
              border: "1px solid var(--warn)",
              fontSize: ".7rem",
              color: "var(--warn)",
            }}
          >
            ⚠ {pendingApprovals.length} action{pendingApprovals.length > 1 ? "s" : ""} awaiting approval
          </div>
        )}
      </div>

      <div style={cardStyle}>
        <div style={headStyle}>Confirmed Findings</div>
        {findings.length ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {findings.slice(0, 3).map((f) => (
              <div key={f.id} style={{ display: "flex", alignItems: "flex-start", gap: 8, minWidth: 0 }}>
                <SevBadge severity={f.severity} />
                <div style={{ minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: ".74rem",
                      fontWeight: 600,
                      color: "var(--ink)",
                      lineHeight: 1.3,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {f.title}
                  </div>
                  <div
                    style={{
                      fontSize: ".68rem",
                      color: "var(--ink-dim)",
                      lineHeight: 1.35,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {f.summary || ""}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ fontSize: ".72rem", color: "var(--ink-dim)" }}>
            No confirmed findings yet — scan in progress.
          </div>
        )}
      </div>

      <div style={cardStyle}>
        <div style={headStyle}>Recommended Next Steps</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
          {pendingApprovals.length > 0 && (
            <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
              <span style={{ color: "var(--warn)", fontSize: ".75rem", flexShrink: 0 }}>→</span>
              <span style={bulletStyle}>
                Review and approve actions in <strong style={{ color: "var(--warn)" }}>Config</strong>
              </span>
            </div>
          )}
          {criticals.length > 0 && (
            <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
              <span style={{ color: "var(--danger)", fontSize: ".75rem", flexShrink: 0 }}>→</span>
              <span style={bulletStyle}>
                Patch {criticals.length} critical vuln{criticals.length > 1 ? "s" : ""} immediately
              </span>
            </div>
          )}
          {highs.length > 0 && (
            <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
              <span style={{ color: "var(--warn)", fontSize: ".75rem", flexShrink: 0 }}>→</span>
              <span style={bulletStyle}>
                Remediate {highs.length} high-severity issue{highs.length > 1 ? "s" : ""} within 14 days
              </span>
            </div>
          )}
          <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
            <span style={{ color: "var(--ok)", fontSize: ".75rem", flexShrink: 0 }}>→</span>
            <span style={bulletStyle}>Full report available once engagement completes</span>
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
  style,
}: {
  messages: RunMessage[];
  chatText: string;
  setChatText: (v: string) => void;
  onSend: (e: FormEvent) => void;
  loading: boolean;
  style?: CSSProperties;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages]);
  const rStyle: Record<string, { color: string; label: string }> = {
    user: { color: "var(--warn)", label: "Operator" },
    orchestrator: { color: "var(--accent)", label: "Vantix" },
    agent: { color: "var(--info)", label: "Agent" },
    system: { color: "var(--ink-dim)", label: "System" },
  };
  return (
    <Panel
      title="Mission Chat"
      meta="Guides and replans the engagement"
      loading={loading}
      style={style}
    >
      <div
        ref={scrollRef}
        style={{
          flex: 1,
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          gap: 10,
          minHeight: 0,
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
                    borderRadius: isUser ? "12px 12px 2px 12px" : "12px 12px 12px 2px",
                    background: isUser ? "var(--accent-soft)" : "var(--surface-2)",
                    border: `1px solid ${isUser ? "var(--accent)" : "var(--line)"}`,
                    fontSize: ".82rem",
                    color: "var(--ink)",
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
      <form onSubmit={onSend} style={{ display: "flex", gap: 8, marginTop: 12, alignItems: "flex-end", flexShrink: 0 }}>
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
            minHeight: 44,
            maxHeight: 100,
            resize: "vertical",
            padding: "10px 12px",
            background: "var(--surface-2)",
            border: "1px solid var(--line-strong)",
            borderRadius: 8,
            color: "var(--ink)",
            fontSize: ".82rem",
            lineHeight: 1.5,
          }}
        />
        <Btn type="submit" size="md" style={{ whiteSpace: "nowrap", height: 44 }}>
          Send
        </Btn>
      </form>
    </Panel>
  );
}

// ─── Terminal ───────────────────────────────────────────────────────────────
function TerminalPanel({ lines, style }: { lines: string[]; style?: CSSProperties }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);
  const colorLine = (l: string): string => {
    if (!l) return "var(--ink-dim)";
    if (l.startsWith("[!]") || l.includes("CRITICAL") || l.includes("←")) return "var(--danger)";
    if (l.startsWith("[+]") || l.includes(" open")) return "var(--ok)";
    if (l.startsWith("[*]")) return "var(--info)";
    if (l.includes("CVE-")) return "var(--warn)";
    if (l.startsWith("|") || l.startsWith("  ")) return "var(--ink-soft)";
    return "var(--ink-dim)";
  };
  return (
    <Panel title="Live Activity" meta="Technical execution output" style={style}>
      <div
        ref={ref}
        style={{
          flex: 1,
          minHeight: 0,
          fontFamily: "var(--mono)",
          fontSize: ".76rem",
          lineHeight: 1.65,
          background: "var(--bg-deep)",
          border: "1px solid var(--line)",
          borderRadius: 8,
          padding: "12px 14px",
          overflowY: "auto",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
        }}
      >
        {lines.length === 0 && (
          <div style={{ color: "var(--ink-dim)" }}>No live terminal output yet.</div>
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
            background: "var(--accent)",
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
  style,
}: {
  agents: AgentSession[];
  tasks: Task[];
  roles: string[];
  phase: RunPhase | null;
  style?: CSSProperties;
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
    <Panel title="Agent Team" meta="Specialist agents" style={style} scroll>
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
            running: "var(--warn)",
            completed: "var(--ok)",
            failed: "var(--danger)",
            blocked: "var(--danger)",
            pending: "var(--ink-dim)",
            standby: "var(--ink-dim)",
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
                background: "var(--surface-2)",
                border: `1px solid ${status === "running" ? "var(--line-strong)" : "var(--line)"}`,
              }}
            >
              <StatusDot status={status === "standby" ? "idle" : status} size={7} />
              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    fontSize: ".73rem",
                    fontWeight: 600,
                    color: "var(--ink)",
                    textTransform: "capitalize",
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {role.replace(/_/g, " ")}
                </div>
                <div style={{ fontSize: ".67rem", color: sc[status] || "var(--ink-dim)", marginTop: 1 }}>
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
  style,
}: {
  workflowState: WorkflowState | null;
  approvals: Approval[];
  style?: CSSProperties;
}) {
  const pendingApprovals = approvals.filter((row) => row.status === "pending").length;
  const blockedClasses = Array.isArray(workflowState?.metrics?.blocked_reason_classes)
    ? (workflowState?.metrics?.blocked_reason_classes as string[])
    : [];
  const phaseDurations = workflowState?.metrics?.phase_durations_seconds as Record<string, number> | undefined;
  return (
    <Panel title="Control Center" meta="Workflow health" style={style} scroll>
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
            background: "var(--surface-2)",
            border: "1px solid var(--line)",
          }}
        >
          <div style={{ fontSize: ".67rem", color: "var(--ink-dim)", textTransform: "uppercase", letterSpacing: ".08em", marginBottom: 6 }}>
            Active Workflow
          </div>
          <div style={{ fontSize: ".8rem", color: "var(--ink)", fontWeight: 600 }}>
            {workflowState?.workflow?.current_phase || "n/a"}
          </div>
          <div style={{ fontSize: ".72rem", color: "var(--ink-dim)", marginTop: 4 }}>
            claim age {metricNumber(workflowState, "current_claim_age_seconds").toFixed(1)}s
          </div>
          <div style={{ fontSize: ".72rem", color: "var(--ink-dim)" }}>
            phase age {metricNumber(workflowState, "current_phase_duration_seconds").toFixed(1)}s
          </div>
          <div style={{ fontSize: ".72rem", color: "var(--ink-dim)" }}>
            latest heartbeat {(workflowState?.metrics?.latest_heartbeat_at as string) || "n/a"}
          </div>
        </div>
        <div
          style={{
            padding: "10px 12px",
            borderRadius: 10,
            background: "var(--surface-2)",
            border: "1px solid var(--line)",
          }}
        >
          <div style={{ fontSize: ".67rem", color: "var(--ink-dim)", textTransform: "uppercase", letterSpacing: ".08em", marginBottom: 6 }}>
            Governance
          </div>
          <div style={{ fontSize: ".72rem", color: "var(--ink-dim)", marginBottom: 4 }}>
            resolved approvals {metricNumber(workflowState, "approval_resolved_count")}
          </div>
          <div style={{ fontSize: ".72rem", color: "var(--ink-dim)", marginBottom: 4 }}>
            avg approval latency {metricNumber(workflowState, "approval_latency_seconds_avg").toFixed(1)}s
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {blockedClasses.length ? blockedClasses.map((item) => (
              <Badge key={item} variant="amber">{item}</Badge>
            )) : <span style={{ fontSize: ".72rem", color: "var(--ink-dim)" }}>No blockers classified</span>}
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
                background: "var(--surface-2)",
                border: "1px solid var(--line)",
                display: "grid",
                gridTemplateColumns: "minmax(0,1fr) auto",
                gap: 8,
              }}
            >
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: ".74rem", color: "var(--ink)", fontWeight: 600, fontFamily: "var(--mono)" }}>
                  {worker.worker_id}
                </div>
                <div style={{ fontSize: ".7rem", color: "var(--ink-dim)", marginTop: 2 }}>
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

function TimelinePanel({ events, style }: { events: EventRecord[]; style?: CSSProperties }) {
  const visibleEvents = events.filter((event) => !(event.event_type === "terminal" && String(event.level || "info").toLowerCase() === "info"));
  const hiddenTerminalCount = Math.max(0, events.length - visibleEvents.length);
  return (
    <Panel
      title="Attack Timeline"
      meta={`${visibleEvents.length} events${hiddenTerminalCount ? ` · ${hiddenTerminalCount} terminal lines hidden` : ""}`}
      style={style}
      scroll
    >
      {visibleEvents.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 320, overflowY: "auto" }}>
          {visibleEvents.map((event) => (
            <div
              key={event.id}
              style={{
                padding: "10px 12px",
                borderRadius: 10,
                background: "var(--surface-2)",
                border: "1px solid var(--line)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: "space-between", marginBottom: 4 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <Badge variant={eventBadgeVariant(event.event_type)}>
                    {EVENT_LABELS[event.event_type] || event.event_type.replace(/_/g, " ")}
                  </Badge>
                  <span style={{ fontSize: ".76rem", color: "var(--ink)", fontWeight: 600 }}>{event.message}</span>
                </div>
                <span style={{ fontFamily: "var(--mono)", fontSize: ".68rem", color: "var(--ink-dim)" }}>
                  #{event.sequence}
                </span>
              </div>
              <div style={{ fontSize: ".69rem", color: "var(--ink-dim)", display: "flex", gap: 8, flexWrap: "wrap" }}>
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
      <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: ".73rem", color: "var(--ink-dim)" }}>
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
function PhasePanel({ phase, style }: { phase: RunPhase | null; style?: CSSProperties }) {
  if (!phase)
    return (
      <Panel title="Engagement Phase" style={style}>
        <EmptyState icon="◎" text="No phase state loaded." />
      </Panel>
    );
  const completed = normalizeCompletedPhases(phase.completed);
  const currentDisplay = toDisplayPhase(phase.current);
  return (
    <Panel title="Engagement Phase" meta={currentDisplay} style={style} scroll>
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
                  background: done ? "var(--ok-soft)" : active ? "var(--warn-soft)" : "var(--surface-2)",
                  border: `1px solid ${done ? "var(--ok)" : active ? "var(--warn)" : "var(--line)"}`,
                  fontSize: ".62rem",
                  fontWeight: 700,
                  color: done ? "var(--ok)" : active ? "var(--warn)" : "var(--ink-dim)",
                }}
              >
                {done ? "✓" : active ? "●" : i + 1}
              </div>
              <div
                style={{
                  fontSize: ".75rem",
                  fontWeight: active ? 700 : 500,
                  color: done ? "var(--ok)" : active ? "var(--warn)" : "var(--ink-dim)",
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
            background: "var(--warn-soft)",
            border: "1px solid var(--warn)",
            fontSize: ".72rem",
            color: "var(--warn)",
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
  style,
}: {
  vectors: Vector[];
  onSelect: (v: Vector) => void;
  onPromote: (v: Vector) => void;
  selectedRunId: string | undefined;
  style?: CSSProperties;
}) {
  const selectedCount = vectors.filter((row) => row.status === "planned" || row.status === "selected").length;
  return (
    <Panel title="Attack Vectors" meta={`${vectors.length} candidates · ${selectedCount} selected`} style={style} scroll>
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
                  background: "var(--surface-2)",
                  border: "1px solid var(--line)",
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
                    <VectorLifecycleBadge vector={v} />
                    <span style={{ fontSize: ".82rem", fontWeight: 600, color: "var(--ink)" }}>{v.title}</span>
                  </div>
                  <Badge variant={v.status === "selected" ? "ok" : "default"}>{v.status}</Badge>
                </div>
                <p style={{ margin: "0 0 6px", fontSize: ".78rem", color: "var(--ink-dim)", lineHeight: 1.5 }}>
                  {v.summary}
                </p>
                {businessImpact && (
                  <div
                    style={{
                      padding: "7px 10px",
                      borderRadius: 8,
                      background: "var(--warn-soft)",
                      border: "1px solid var(--warn)",
                      fontSize: ".72rem",
                      color: "var(--warn)",
                      lineHeight: 1.4,
                      marginBottom: 8,
                    }}
                  >
                    <span style={{ fontWeight: 700 }}>Business impact: </span>
                    {businessImpact}
                  </div>
                )}
                <div style={{ marginBottom: 8 }}>
                  <div style={{ fontSize: ".67rem", color: "var(--ink-dim)", marginBottom: 4 }}>Confidence</div>
                  <ConfBar value={v.confidence} />
                </div>
                {v.next_action && (
                  <div style={{ fontSize: ".72rem", color: "var(--info)", marginBottom: 10 }}>
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
function CvePanel({ facts, style }: { facts: Fact[]; style?: CSSProperties }) {
  return (
    <Panel title="Intel Findings" meta={`${facts.length} items`} style={style} scroll>
      {facts.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {facts.map((f, i) => (
            <div
              key={f.id || i}
              style={{
                padding: "9px 11px",
                borderRadius: 10,
                background: "var(--surface-2)",
                border: "1px solid var(--line)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                <span
                  style={{ fontFamily: "var(--mono)", fontSize: ".75rem", color: "var(--warn)", fontWeight: 600 }}
                >
                  {f.value}
                </span>
                <Badge variant="default">{f.kind}</Badge>
                <span style={{ fontSize: ".68rem", color: "var(--ink-dim)" }}>
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

function MemoryPanel({ hits, style }: { hits: Array<Record<string, unknown>>; style?: CSSProperties }) {
  return (
    <Panel title="Prior Experience" meta="Similar engagements" style={style} scroll>
      {hits.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {hits.slice(0, 5).map((h, i) => (
            <div
              key={i}
              style={{
                padding: "9px 11px",
                borderRadius: 10,
                background: "var(--surface-2)",
                border: "1px solid var(--line)",
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
                <span style={{ fontSize: ".75rem", fontWeight: 600, color: "var(--ink)" }}>
                  {String(h.title ?? "Memory hit")}
                </span>
                {h.rank !== undefined && h.rank !== null && (
                  <Badge variant="default">rank {String(h.rank)}</Badge>
                )}
              </div>
              <p style={{ margin: 0, fontSize: ".73rem", color: "var(--ink-dim)", lineHeight: 1.45 }}>
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
  style,
}: {
  chains: AttackChain[];
  onPromote: (c: AttackChain) => void;
  selectedRunId: string | undefined;
  style?: CSSProperties;
}) {
  return (
    <Panel title="Attack Chains" meta={`${chains.length} modelled`} style={style} scroll>
      {chains.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {chains.map((c) => (
            <div
              key={c.id}
              style={{
                padding: "10px 12px",
                borderRadius: 10,
                background: "var(--surface-2)",
                border: "1px solid var(--line)",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 5 }}
              >
                <span style={{ fontSize: ".78rem", fontWeight: 600, color: "var(--warn)" }}>{c.name}</span>
                <span style={{ fontFamily: "var(--mono)", fontSize: ".7rem", color: "var(--ink-dim)" }}>
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
              <p style={{ margin: "0 0 8px", fontSize: ".72rem", color: "var(--ink-dim)" }}>{c.notes}</p>
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
  style,
}: {
  state: BrowserState | null;
  selectedRunId: string | undefined;
  onOpenPath: (path: string) => void;
  style?: CSSProperties;
}) {
  if (!state) {
    return (
      <Panel title="Browser Assessment" style={style}>
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
    <Panel title="Browser Assessment" meta={`${state.status} · ${state.pages_visited} pages`} style={style} scroll>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Badge variant="default">auth: {state.authenticated}</Badge>
          <Badge variant="blue">routes: {state.routes_discovered}</Badge>
          <Badge variant="amber">forms: {state.forms.length}</Badge>
          <Badge variant="ok">screenshots: {state.screenshots.length}</Badge>
          <Badge variant="default">signals: {jsSignals.length}</Badge>
        </div>
        <div style={{ fontSize: ".72rem", color: "var(--ink-dim)", lineHeight: 1.45 }}>
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
              <div key={i} style={{ fontSize: ".7rem", color: "var(--warn)" }}>
                {line}
              </div>
            ))}
          </div>
        )}
        {authTransitions.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <Label>Auth State</Label>
            {authTransitions.slice(0, 4).map((item, idx) => (
              <div key={idx} style={{ fontSize: ".69rem", color: "var(--ink-soft)", lineHeight: 1.45 }}>
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
              <div key={idx} style={{ fontSize: ".69rem", color: "var(--ink-soft)", lineHeight: 1.45 }}>
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
              <div key={idx} style={{ fontSize: ".69rem", color: "var(--ink-soft)", fontFamily: "var(--mono)" }}>
                {String(item.endpoint || "")} ({String(item.count || "0")})
              </div>
            ))}
          </div>
        )}
        {routeHints.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <Label>Route Hints</Label>
            {routeHints.slice(0, 4).map((item, idx) => (
              <div key={idx} style={{ fontSize: ".69rem", color: "var(--ink-soft)", fontFamily: "var(--mono)" }}>
                {String(item.hint || "")}
              </div>
            ))}
          </div>
        )}
        {jsSignals.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <Label>Client Signals</Label>
            {jsSignals.slice(0, 4).map((item, idx) => (
              <div key={idx} style={{ fontSize: ".69rem", color: "var(--ink-soft)", lineHeight: 1.45 }}>
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
  events,
  style,
}: {
  results: RunResults | null;
  selectedRunId: string | undefined;
  onOpenPath: (path: string) => void;
  events?: EventRecord[];
  style?: CSSProperties;
}) {
  const findings = results?.findings || [];
  const artifacts = results?.artifacts || [];
  const dedupEvents = (events || []).filter((e) => e.event_type === "dedup_merged");
  const suppressedEvents = (events || []).filter((e) => e.event_type === "finding_suppressed");
  const validatedCount = findings.filter((row) => ["validated", "confirmed", "draft"].includes(String(row.status || "").toLowerCase())).length;
  const colStyle: CSSProperties = {
    display: "flex",
    flexDirection: "column",
    minHeight: 0,
    minWidth: 0,
  };
  const listStyle: CSSProperties = {
    display: "flex",
    flexDirection: "column",
    gap: 7,
    flex: "1 1 auto",
    minHeight: 0,
    overflowY: "auto",
    paddingRight: 4,
  };
  return (
    <Panel title="Findings & Report" meta={`${validatedCount} validated · ${artifacts.length} artifacts`} style={style}>
      {results ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 10, flex: "1 1 auto", minHeight: 0, minWidth: 0 }}>
          {(dedupEvents.length > 0 || suppressedEvents.length > 0) && (
            <div
              style={{
                padding: "8px 10px",
                borderRadius: 10,
                background: "var(--amber-soft, var(--surface-2))",
                border: "1px solid var(--amber, var(--line))",
                fontSize: ".74rem",
                color: "var(--ink)",
                lineHeight: 1.5,
                flexShrink: 0,
                display: "flex",
                gap: 14,
                flexWrap: "wrap",
              }}
            >
              {dedupEvents.length > 0 && (
                <span title={dedupEvents.map((e) => e.message).slice(-3).join(" · ")}>
                  <strong>{dedupEvents.length}</strong> finding
                  {dedupEvents.length === 1 ? "" : "s"} deduplicated
                </span>
              )}
              {suppressedEvents.length > 0 && (
                <span title={suppressedEvents.map((e) => e.message).slice(-3).join(" · ")}>
                  <strong>{suppressedEvents.length}</strong> finding
                  {suppressedEvents.length === 1 ? "" : "s"} suppressed by negative evidence
                </span>
              )}
            </div>
          )}
          {results.executive_summary && (
            <div
              style={{
                padding: "9px 11px",
                borderRadius: 10,
                background: "var(--ok-soft)",
                border: "1px solid var(--ok)",
                fontSize: ".74rem",
                color: "var(--ink)",
                lineHeight: 1.5,
                flexShrink: 0,
              }}
            >
              {results.executive_summary}
            </div>
          )}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 16,
              flex: "1 1 auto",
              minHeight: 0,
            }}
          >
          <div style={colStyle}>
            <Label>Confirmed Findings ({findings.length})</Label>
            <div style={listStyle}>
              {findings.length ? (
                findings.map((f) => (
                  <div
                    key={f.id}
                    style={{
                      padding: "9px 11px",
                      borderRadius: 10,
                      background: "var(--surface-2)",
                      border: "1px solid var(--line)",
                      minWidth: 0,
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 4, minWidth: 0 }}>
                      <SevBadge severity={f.severity} />
                      <span
                        style={{
                          fontSize: ".76rem",
                          fontWeight: 600,
                          color: "var(--ink)",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          minWidth: 0,
                        }}
                      >
                        {f.title}
                      </span>
                    </div>
                    <p style={{ margin: 0, fontSize: ".72rem", color: "var(--ink-dim)", wordBreak: "break-word" }}>{f.summary}</p>
                  </div>
                ))
              ) : (
                <EmptyState icon="◇" text="No confirmed findings yet." />
              )}
            </div>
          </div>
          <div style={colStyle}>
            <Label>Evidence & Artifacts ({artifacts.length})</Label>
            <div style={listStyle}>
              {artifacts.map((a, i) => (
                <div
                  key={a.id || i}
                  style={{
                    padding: "9px 11px",
                    borderRadius: 10,
                    background: "var(--surface-2)",
                    border: "1px solid var(--line)",
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    minWidth: 0,
                  }}
                >
                  <Badge variant="default">{a.kind}</Badge>
                  <span
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: ".7rem",
                      color: "var(--ink-dim)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      flex: "1 1 0",
                      minWidth: 0,
                    }}
                    title={a.path}
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
                  background: "var(--warn-soft)",
                  border: "1px solid var(--warn)",
                  fontSize: ".73rem",
                  color: "var(--ink-dim)",
                  flexShrink: 0,
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
                  background: "var(--ok-soft)",
                  border: "1px solid var(--ok)",
                  flexShrink: 0,
                  minWidth: 0,
                }}
              >
                <div style={{ fontSize: ".68rem", color: "var(--ok)", fontWeight: 600, marginBottom: 2 }}>
                  Report Ready
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                  <div
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: ".7rem",
                      color: "var(--ink-dim)",
                      flex: "1 1 0",
                      minWidth: 0,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={results.report_path}
                  >
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

function ReplayPanel({ replay, style }: { replay: ReplayState | null; style?: CSSProperties }) {
  return (
    <Panel title="Replay" meta={replay ? `${replay.summary?.event_count || 0} events` : "history"} style={style} scroll>
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
                  background: "var(--surface-2)",
                  border: "1px solid var(--line)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: "space-between" }}>
                  <span style={{ fontSize: ".76rem", color: "var(--ink)", fontWeight: 600 }}>
                    {String(entry.phase || "unknown")}
                  </span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: ".68rem", color: "var(--ink-dim)" }}>
                    {String(entry.at || "")}
                  </span>
                </div>
                <div style={{ fontSize: ".71rem", color: "var(--ink-dim)", marginTop: 4 }}>
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
// P3-4 — approval rows are cross-referenced against policy_decision run
// events so operators can see the full audit context (action kind, verdict,
// required approval tier, history) instead of just the single-line reason.
function policyDecisionsFromEvents(events: EventRecord[] | undefined) {
  return (events || [])
    .filter((e) => e.event_type === "policy_decision")
    .map((e) => ({
      id: e.id,
      at: e.created_at,
      level: e.level,
      message: e.message,
      action_kind: String((e.payload as Record<string, unknown>)?.action_kind || ""),
      verdict: String((e.payload as Record<string, unknown>)?.verdict || ""),
      reason: String((e.payload as Record<string, unknown>)?.reason || ""),
      audit: Boolean((e.payload as Record<string, unknown>)?.audit),
    }));
}

function ApprovalsPanel({
  approvals,
  onApprove,
  onReject,
  events,
}: {
  approvals: Approval[];
  onApprove: (a: Approval) => void;
  onReject: (a: Approval) => void;
  events?: EventRecord[];
}) {
  const pending = approvals.filter((a) => a.status === "pending").length;
  const decisions = policyDecisionsFromEvents(events);
  const [drawer, setDrawer] = useState<Approval | null>(null);

  function openDrawer(a: Approval) {
    setDrawer(a);
  }

  function matchingDecisions(a: Approval) {
    const needle = `${a.title} ${a.detail} ${a.reason}`.toLowerCase();
    return decisions.filter(
      (d) =>
        (d.action_kind && needle.includes(d.action_kind.toLowerCase())) ||
        (d.reason && needle.includes(d.reason.toLowerCase())) ||
        d.verdict === "require_approval" ||
        d.verdict === "block",
    );
  }

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
                background: "var(--warn-soft)",
                border: `1px solid ${a.status === "pending" ? "var(--warn)" : "var(--line)"}`,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <Badge variant={a.status === "pending" ? "warn" : a.status === "approved" ? "ok" : "danger"}>
                  {a.status}
                </Badge>
                <span style={{ fontSize: ".8rem", fontWeight: 600, color: "var(--ink)" }}>{a.title}</span>
                <Btn size="xs" variant="ghost" onClick={() => openDrawer(a)}>
                  Audit
                </Btn>
              </div>
              <p style={{ margin: "0 0 10px", fontSize: ".76rem", color: "var(--ink-dim)", lineHeight: 1.5 }}>
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

      {drawer ? (
        <aside
          role="dialog"
          aria-label="Approval audit"
          style={{
            position: "fixed",
            top: 0,
            right: 0,
            bottom: 0,
            width: "min(480px, 100%)",
            zIndex: 40,
            overflowY: "auto",
            background: "var(--surface-1)",
            borderLeft: "1px solid var(--line)",
            padding: 16,
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <h3 style={{ margin: 0 }}>Audit: {drawer.title}</h3>
            <Btn size="sm" variant="ghost" onClick={() => setDrawer(null)}>Close</Btn>
          </div>
          <p style={{ fontSize: ".76rem", color: "var(--ink-dim)" }}>
            Status <strong>{drawer.status}</strong> · Reason <strong>{drawer.reason || "—"}</strong>
          </p>
          <h4 style={{ marginTop: 12 }}>Policy decisions ({matchingDecisions(drawer).length})</h4>
          {matchingDecisions(drawer).length ? (
            <ul style={{ fontSize: ".74rem", paddingLeft: 18 }}>
              {matchingDecisions(drawer).map((d) => (
                <li key={d.id} style={{ marginBottom: 6 }}>
                  <div>
                    <Badge variant={d.verdict === "block" ? "danger" : d.verdict === "require_approval" ? "warn" : "default"}>
                      {d.verdict || "—"}
                    </Badge>{" "}
                    <strong>{d.action_kind || "unknown"}</strong>
                    {d.audit ? <span style={{ color: "var(--ink-dim)" }}> · audited</span> : null}
                  </div>
                  <div style={{ color: "var(--ink-dim)" }}>{d.reason || d.message}</div>
                  <div style={{ fontSize: ".68rem", color: "var(--ink-muted)" }}>{d.at}</div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="empty">No matching policy decisions in the current event window.</p>
          )}
          <h4 style={{ marginTop: 12 }}>Grant history</h4>
          <p style={{ fontSize: ".74rem", color: "var(--ink-dim)" }}>
            All approvals for this run:{" "}
            {approvals.map((a) => `${a.title}=${a.status}`).join(" · ") || "none"}
          </p>
        </aside>
      ) : null}
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
                background: "var(--surface-2)",
                border: "1px solid var(--line)",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}
              >
                <span
                  style={{ fontSize: ".75rem", fontWeight: 600, color: "var(--ink)", textTransform: "capitalize" }}
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

function HighRiskSurfacesPanel({
  run,
  onSave,
}: {
  run: Run | null;
  onSave: (payload: { enabled: boolean; label: string }) => Promise<void>;
}) {
  const validation = (run?.config?.validation as Record<string, unknown> | undefined) || {};
  const raw = (validation.high_risk_surfaces as Record<string, unknown> | undefined) || {};
  const currentEnabled = raw.enabled === undefined ? true : Boolean(raw.enabled);
  const currentLabel = typeof raw.label === "string" && raw.label.trim() ? raw.label.trim() : "High Risk Surfaces";
  const [enabled, setEnabled] = useState(currentEnabled);
  const [label, setLabel] = useState(currentLabel);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setEnabled(currentEnabled);
    setLabel(currentLabel);
  }, [currentEnabled, currentLabel, run?.id]);

  const dirty = enabled !== currentEnabled || label.trim() !== currentLabel;

  async function handleSave() {
    if (!run) return;
    setSaving(true);
    try {
      await onSave({ enabled, label: label.trim() || "High Risk Surfaces" });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Panel title="High Risk Surfaces" meta={enabled ? "enabled by default" : "disabled for this run"}>
      {!run ? (
        <EmptyState text="Select a run to control high-risk validation." />
      ) : (
        <>
          <div
            style={{
              padding: "12px 14px",
              borderRadius: 10,
              background: "var(--surface-2)",
              border: "1px solid var(--line)",
              marginBottom: 12,
            }}
          >
            <div style={{ fontSize: ".74rem", color: "var(--ink)", lineHeight: 1.55 }}>
              Controls whether Vantix automatically validates high-impact surfaces such as state mutation, local file read, persistence-adjacent, RCE-adjacent, and availability probes.
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
            <Btn size="sm" variant={enabled ? "green" : "ghost"} onClick={() => setEnabled((v) => !v)}>
              {enabled ? "Enabled" : "Disabled"}
            </Btn>
            <span style={{ fontSize: ".76rem", color: "var(--ink-dim)" }}>
              When disabled, those probes are skipped and recorded as skipped validation attempts.
            </span>
          </div>
          <div style={{ marginBottom: 12 }}>
            <Label>LLM-facing label</Label>
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="High Risk Surfaces"
              style={{
                width: "100%",
                padding: "10px 12px",
                background: "var(--surface-2)",
                border: "1px solid var(--line-strong)",
                borderRadius: 8,
                color: "var(--ink)",
                fontSize: ".78rem",
                boxSizing: "border-box",
              }}
            />
          </div>
          <Btn size="sm" onClick={handleSave} disabled={!dirty || saving}>
            {saving ? "Saving…" : "Save Setting"}
          </Btn>
        </>
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
          background: "var(--surface-2)",
          border: "1px solid var(--line-strong)",
          borderRadius: 10,
          color: "var(--ink)",
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
            background: "var(--surface-2)",
            border: "1px solid var(--line-strong)",
            borderRadius: 8,
            color: "var(--ink)",
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
            border: "1px solid var(--warn)",
            background: "var(--warn-soft)",
            borderRadius: 8,
            fontSize: ".72rem",
            color: "var(--warn)",
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
            <span style={{ fontSize: ".82rem", color: "var(--ink)", fontWeight: 600 }}>{user.username}</span>
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
            background: "var(--surface-2)",
            border: "1px solid var(--line)",
          }}
        >
          <div style={{ fontSize: ".74rem", fontWeight: 600, color: "var(--ink)", marginBottom: 8 }}>Session</div>
          <p style={{ margin: "0 0 8px", fontSize: ".73rem", color: "var(--ink-dim)", lineHeight: 1.55 }}>
            Authentication uses an httpOnly session cookie. Mutating requests carry an X-CSRF-Token header.
          </p>
          <p style={{ margin: 0, fontSize: ".73rem", color: "var(--ink-dim)", lineHeight: 1.55 }}>
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
            background: "var(--warn-soft)",
            border: "1px solid var(--warn)",
            animation: "vx-fadein .2s ease",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
            <div
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: "var(--warn)",
                flexShrink: 0,
                animation: "vx-pulse 1.8s ease-in-out infinite",
                boxShadow: "0 0 0 4px var(--warn)",
              }}
            />
            <div style={{ minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 3 }}>
                <Badge variant="warn">Approval Required</Badge>
                <span
                  style={{
                    fontSize: ".82rem",
                    fontWeight: 600,
                    color: "var(--ink)",
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
                  color: "var(--ink-dim)",
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
            marginBottom: 18,
            borderBottom: "1px solid var(--line)",
            paddingBottom: 16,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
            <div
              style={{
                width: 30,
                height: 30,
                borderRadius: 7,
                background: "var(--accent-soft)",
                border: "1px solid var(--accent)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: ".72rem",
                color: "var(--accent)",
                fontWeight: 700,
                letterSpacing: ".02em",
              }}
            >
              VX
            </div>
            <div>
              <div
                style={{
                  fontSize: "1.05rem",
                  fontWeight: 600,
                  letterSpacing: "-0.005em",
                  lineHeight: 1,
                  color: "var(--ink)",
                }}
              >
                Vantix
              </div>
              <div
                style={{
                  fontSize: ".62rem",
                  fontWeight: 500,
                  letterSpacing: ".08em",
                  textTransform: "uppercase",
                  color: "var(--ink-dim)",
                  marginTop: 3,
                }}
              >
                Offensive Security Suite
              </div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <Badge variant="ok">● Codex</Badge>
            <Badge variant="ok">● Worker</Badge>
          </div>
        </div>
        <div style={{ marginBottom: 18 }}>
          <div className="vx-label" style={{ marginBottom: 8 }}>
            Source (White-box)
          </div>
          <select
            value={sourceType}
            onChange={(e) => setSourceType(e.target.value as "none" | "github" | "local" | "upload")}
            style={{ width: "100%", padding: "9px 11px", fontSize: ".78rem", marginBottom: 8 }}
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
                style={{ width: "100%", padding: "8px 11px", fontSize: ".76rem" }}
              />
              <input
                value={githubRef}
                onChange={(e) => setGithubRef(e.target.value)}
                placeholder="branch/tag/commit (optional)"
                style={{ width: "100%", padding: "8px 11px", fontSize: ".76rem" }}
              />
            </div>
          )}
          {sourceType === "local" && (
            <input
              value={localPath}
              onChange={(e) => setLocalPath(e.target.value)}
              placeholder="/path/to/source"
              style={{ width: "100%", padding: "8px 11px", fontSize: ".76rem" }}
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
                style={{ width: "100%", padding: "6px", fontSize: ".74rem", color: "var(--ink)" }}
              />
              <div style={{ fontSize: ".7rem", color: "var(--ink-dim)" }}>{uploadLabel || "No upload staged yet."}</div>
            </div>
          )}
        </div>
        <div>
          <div className="vx-label" style={{ marginBottom: 10 }}>
            Recent Engagements
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {runs.length === 0 && (
              <div style={{ fontSize: ".74rem", color: "var(--ink-dim)" }}>No runs yet.</div>
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
                        color: "var(--ink)",
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
                    <span style={{ fontSize: ".68rem", color: "var(--ink-dim)" }}>{run.mode}</span>
                  </div>
                  <div
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: ".66rem",
                      color: "var(--ink-dim)",
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
  theme,
  onToggleTheme,
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
  theme: "dark" | "light";
  onToggleTheme: () => void;
}) {
  const runVariant: Variant =
    run?.status === "running"
      ? "amber"
      : run?.status === "completed"
      ? "ok"
      : run?.status === "failed" || run?.status === "blocked"
      ? "danger"
      : "default";
  const phaseLabel = phase?.current ? String(phase.current) : "";
  const statusLabel = run?.status ? String(run.status) : "";
  const showPhase = phaseLabel && phaseLabel.toLowerCase() !== statusLabel.toLowerCase();
  return (
    <div className="vx-topbar">
      <div style={{ minWidth: 0, flex: 1 }}>
        <div
          style={{
            fontSize: ".62rem",
            fontWeight: 600,
            letterSpacing: ".1em",
            textTransform: "uppercase",
            color: "var(--ink-dim)",
            marginBottom: 4,
          }}
        >
          Vantix Orchestrator
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <span
            style={{
              fontFamily: "var(--mono)",
              fontSize: ".95rem",
              fontWeight: 600,
              color: "var(--ink)",
              letterSpacing: "-0.01em",
            }}
          >
            {run ? run.workspace_id : "No active engagement"}
          </span>
          {run && <Badge variant={runVariant}>{run.status}</Badge>}
          {showPhase && <Badge variant="blue">{phaseLabel}</Badge>}
          {workflowState?.workers?.length ? (
            <Badge variant="default">
              {metricNumber(workflowState, "active_worker_count")} workers
            </Badge>
          ) : null}
          {metricNumber(workflowState, "approval_pending_count") > 0 ? (
            <Badge variant="warn">approvals {metricNumber(workflowState, "approval_pending_count")}</Badge>
          ) : null}
        </div>
        {run && (
          <div
            style={{
              fontFamily: "var(--mono)",
              fontSize: ".72rem",
              color: "var(--ink-dim)",
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
          <div style={{ fontSize: ".72rem", color: "var(--danger)", marginTop: 4 }}>
            Blocked: {workflowState.workflow.blocked_reason}
          </div>
        ) : null}
        {statusMsg && <div style={{ fontSize: ".72rem", color: "var(--warn)", marginTop: 4 }}>{statusMsg}</div>}
      </div>
      <div style={{ display: "flex", gap: 6, flexShrink: 0, flexWrap: "wrap", alignItems: "center", justifyContent: "flex-end" }}>
        {run && (
          <>
            <Btn size="sm" variant="ghost" onClick={onRefresh}>Refresh</Btn>
            <Btn size="sm" variant="ghost" onClick={onPause}>Pause</Btn>
            <Btn size="sm" variant="ghost" onClick={onRetry}>Retry</Btn>
            <Btn size="sm" variant="amber" onClick={onReplan}>Replan</Btn>
            <Btn size="sm" variant="danger" onClick={onCancel}>Cancel</Btn>
          </>
        )}
        <button
          type="button"
          className="vx-theme-toggle"
          onClick={onToggleTheme}
          title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          aria-label="Toggle theme"
        >
          {theme === "dark" ? (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="4" />
              <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
            </svg>
          )}
        </button>
      </div>
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
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    if (typeof window === "undefined") return "dark";
    const stored = window.localStorage.getItem("vx-theme");
    return stored === "light" ? "light" : "dark";
  });
  useEffect(() => {
    if (typeof document === "undefined") return;
    document.documentElement.setAttribute("data-theme", theme);
    try {
      window.localStorage.setItem("vx-theme", theme);
    } catch {}
  }, [theme]);
  const toggleTheme = useCallback(() => {
    setTheme((t) => (t === "dark" ? "light" : "dark"));
  }, []);
  const [chatText, setChatText] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const mode = "pentest";
  const [sourceType, setSourceType] = useState<"none" | "github" | "local" | "upload">("none");
  const [githubUrl, setGithubUrl] = useState("");
  const [githubRef, setGithubRef] = useState("");
  const [localPath, setLocalPath] = useState("");
  const [stagedUploadId, setStagedUploadId] = useState("");

  const streamRef = useRef<EventSource | null>(null);
  const selectedRunRef = useRef<string>("");
  const terminalSequenceRef = useRef<Record<string, number>>({});
  const refreshInFlightRef = useRef<Record<string, boolean>>({});
  const refreshPendingRef = useRef<Record<string, { incrementalTerminal: boolean } | null>>({});

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
      const requestedIncremental = Boolean(opts?.incrementalTerminal);
      if (refreshInFlightRef.current[runId]) {
        const existing = refreshPendingRef.current[runId];
        refreshPendingRef.current[runId] = {
          incrementalTerminal: Boolean(existing?.incrementalTerminal) && requestedIncremental,
        };
        return;
      }
      refreshInFlightRef.current[runId] = true;
      try {
        const incrementalTerminal = requestedIncremental;
        const fullRefresh = !incrementalTerminal;
        const loadOverview = fullRefresh || tab === "overview";
        const loadIntel = fullRefresh || tab === "intel";
        const loadResults = fullRefresh || tab === "results";
        const loadConfig = fullRefresh || tab === "config";
        const sinceSequence = terminalSequenceRef.current[runId] || 0;
        const failures: string[] = [];
        const track = <T,>(label: string, fallback: T) =>
          (err: unknown) => {
            failures.push(label);
            // eslint-disable-next-line no-console
            console.warn(`[refreshRun] ${label} failed:`, err);
            return fallback;
          };
        const maybeLoad = <T,>(enabled: boolean, task: Promise<T>, label: string, fallback: T) =>
          enabled ? task.catch(track<T>(label, fallback)) : Promise.resolve(undefined as T | undefined);
        const [run, graph, runApprovals, workflow, runSourceStatus, runReplay, runFacts, learningHits, runMessages, runEvents, runVectors, runResults, runSkills, runChains, runBrowserState, runTerminal] =
          await Promise.all([
            api.getRun(runId),
            api.getGraph(runId),
            api.getApprovals(runId).catch(track<Approval[]>("approvals", [])),
            api.getWorkflowState(runId).catch(track<WorkflowState | null>("workflow", null)),
            api.getSourceStatus(runId).catch(track<SourceStatus | null>("source", null)),
            maybeLoad(loadConfig, api.getReplay(runId), "replay", null),
            maybeLoad(loadIntel, api.getFacts(runId), "facts", [] as Fact[]),
            maybeLoad(loadIntel, api.getLearning(runId), "learning", { run_id: runId, mode: "", results: [] as Array<Record<string, unknown>> }),
            maybeLoad(loadOverview, api.getMessages(runId), "messages", [] as RunMessage[]),
            maybeLoad(loadOverview, api.getEvents(runId, 0, 300), "events", [] as EventRecord[]),
            maybeLoad(loadOverview || loadResults, api.getVectors(runId), "vectors", [] as Vector[]),
            maybeLoad(loadOverview || loadResults, api.getResults(runId), "results", null),
            maybeLoad(loadIntel, api.getSkills(runId), "skills", [] as RunSkillApplication[]),
            maybeLoad(loadIntel, api.getAttackChains(runId), "chains", [] as AttackChain[]),
            maybeLoad(loadOverview || loadResults, api.getBrowserState(runId), "browser", null),
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
        setAgents(graph.agents);
        setTasks(graph.tasks);
        setApprovals(runApprovals.length ? runApprovals : graph.approvals);
        if (runReplay !== undefined) setReplayState(runReplay);
        if (runFacts !== undefined) setFacts(runFacts);
        if (learningHits !== undefined) setLearning(learningHits.results);
        if (runEvents !== undefined) setEvents(runEvents);
        if (runMessages !== undefined && runEvents !== undefined) setMessages(mergeTimeline(runMessages, runEvents));
        if (runVectors !== undefined) setVectors(runVectors);
        if (runResults !== undefined) {
          setResults(runResults);
          setFindings(runResults?.findings || []);
        }
        if (runSkills !== undefined) setSkillApps(runSkills);
        if (runChains !== undefined) setChains(runChains);
        if (runBrowserState !== undefined) setBrowserState(runBrowserState);
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
      } finally {
        refreshInFlightRef.current[runId] = false;
        const pending = refreshPendingRef.current[runId];
        refreshPendingRef.current[runId] = null;
        if (pending && selectedRunRef.current === runId) {
          void refreshRun(runId, pending);
        }
      }
    },
    [flash, refreshRuns, tab],
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
    }, 5000);
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
    const sourceAttached = sourceInput.type !== "none";
    const shouldStartNew = Boolean(selectedRun && sourceAttached);
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
  async function handleSaveHighRiskSurfaces(payload: { enabled: boolean; label: string }) {
    if (!selectedRun) return;
    try {
      const updated = await api.updateValidationConfig(selectedRun.id, payload);
      setSelectedRun(updated);
      setRuns((rows) => rows.map((item) => (item.id === updated.id ? updated : item)));
      await refreshRun(updated.id, { incrementalTerminal: false });
      flash(`High Risk Surfaces ${payload.enabled ? "enabled" : "disabled"} for this run`);
    } catch (error) {
      flash(`Save failed: ${error instanceof Error ? error.message : String(error)}`);
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
          theme={theme}
          onToggleTheme={toggleTheme}
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
          <div className="vx-workspace vx-workspace-split">
            <div className="vx-col" style={{ overflow: "hidden" }}>
              <ExecSummary run={selectedRun} findings={findings} phase={phase} approvals={approvals} />
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 10,
                  flex: "1 1 auto",
                  minHeight: 0,
                }}
              >
                <ChatPanel
                  messages={messages}
                  chatText={chatText}
                  setChatText={setChatText}
                  onSend={handleSend}
                  loading={chatLoading}
                  style={{ flex: "1 1 0", minHeight: 0 }}
                />
                <TerminalPanel lines={termLines} style={{ flex: "1 1 0", minHeight: 0 }} />
              </div>
            </div>
            <div className="vx-col" style={{ overflow: "hidden" }}>
              <PhasePanel phase={phase} style={{ flex: "1 1 0", minHeight: 0 }} />
              <AgentsPanel
                agents={agents}
                tasks={tasks}
                roles={ROLES}
                phase={phase}
                style={{ flex: "1 1 0", minHeight: 0 }}
              />
              <ControlCenterPanel
                workflowState={workflowState}
                approvals={approvals}
                style={{ flex: "1 1 0", minHeight: 0 }}
              />
              <TimelinePanel events={events} style={{ flex: "1 1 0", minHeight: 0 }} />
            </div>
          </div>
        )}

        {tab === "intel" && (
          <div className="vx-workspace vx-workspace-split">
            <div className="vx-col" style={{ overflow: "hidden" }}>
              <VectorsPanel
                vectors={vectors}
                selectedRunId={selectedRun?.id}
                onSelect={handleSelectVector}
                onPromote={handlePromoteVector}
                style={{ flex: "1 1 0", minHeight: 0 }}
              />
              <BrowserPanel
                state={browserState}
                selectedRunId={selectedRun?.id}
                onOpenPath={handleOpenPath}
                style={{ flex: "1 1 0", minHeight: 0 }}
              />
            </div>
            <div className="vx-col" style={{ overflow: "hidden" }}>
              <CvePanel facts={cveFacts} style={{ flex: "1 1 0", minHeight: 0 }} />
              <ChainsPanel
                chains={chains}
                onPromote={handlePromoteChain}
                selectedRunId={selectedRun?.id}
                style={{ flex: "1 1 0", minHeight: 0 }}
              />
              <MemoryPanel hits={learning} style={{ flex: "1 1 0", minHeight: 0 }} />
            </div>
          </div>
        )}

        {tab === "results" && (
          <div className="vx-workspace vx-workspace-split">
            <div className="vx-col" style={{ overflow: "hidden" }}>
              <ResultsPanel
                results={results}
                selectedRunId={selectedRun?.id}
                onOpenPath={handleOpenPath}
                events={events}
                style={{ flex: "1 1 auto", minHeight: 0 }}
              />
            </div>
            <div className="vx-col" style={{ overflow: "hidden" }}>
              <ReplayPanel replay={replayState} style={{ flex: "1 1 auto", minHeight: 0 }} />
            </div>
          </div>
        )}

        {tab === "config" && (
          <div className="vx-workspace vx-workspace-split">
            <div className="vx-col">
              <ApprovalsPanel approvals={approvals} onApprove={handleApprove} onReject={handleReject} events={events} />
              <HighRiskSurfacesPanel run={selectedRun} onSave={handleSaveHighRiskSurfaces} />
              <SourcePanel sourceStatus={sourceStatus} />
              <SkillsPanel applications={skillApps} onApply={handleApplySkills} selectedRunId={selectedRun?.id} />
            </div>
            <div className="vx-col">
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
          </div>
        )}
      </main>
    </div>
  );
}
