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
  EventRecord,
  Fact,
  Finding,
  Run,
  RunMessage,
  RunPhase,
  RunResults,
  RunSkillApplication,
  Task,
  Vector,
  api,
  getApiToken,
  setApiToken as persistApiToken,
} from "./api";

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
  default: { bg: "rgba(255,255,255,.05)", color: "#7a9e92", border: "rgba(140,185,165,.15)" },
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

type BtnVariant = "primary" | "ghost" | "danger" | "amber" | "green";
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
    primary: { background: "linear-gradient(135deg,#19c37d,#b2f2d1)", color: "#021a0f", border: "none" },
    ghost: { background: "rgba(255,255,255,.04)", color: "#e8f4ee", border: "1px solid rgba(140,185,165,.18)" },
    danger: { background: "rgba(239,68,68,.1)", color: "#ef4444", border: "1px solid rgba(239,68,68,.3)" },
    amber: { background: "rgba(244,184,96,.1)", color: "#f4b860", border: "1px solid rgba(244,184,96,.3)" },
    green: { background: "rgba(25,195,125,.1)", color: "#19c37d", border: "1px solid rgba(25,195,125,.3)" },
  };
  const ss: Record<BtnSize, CSSProperties> = {
    xs: { padding: "3px 8px", fontSize: ".68rem", borderRadius: 6 },
    sm: { padding: "5px 10px", fontSize: ".72rem", borderRadius: 8 },
    md: { padding: "8px 14px", fontSize: ".78rem", borderRadius: 10 },
    lg: { padding: "11px 20px", fontSize: ".84rem", borderRadius: 12 },
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

// ─── Static lists / mocks ───────────────────────────────────────────────────
const ROLES = ["orchestrator", "recon", "knowledge_base", "vector_store", "researcher", "developer", "executor", "reporter"];
const MODES = ["pentest", "ctf", "koth", "bugbounty", "windows-ctf", "windows-koth"];

const MOCK_RUNS: Run[] = [
  {
    id: "run_demo_1",
    engagement_id: "eng_demo",
    mode: "pentest",
    workspace_id: "ws-demo-1",
    status: "running",
    target: "10.10.14.5",
    objective: "Demo — full pentest engagement against a lab host.",
    config: {},
  },
];
const MOCK_MESSAGES: RunMessage[] = [
  {
    id: "m1",
    run_id: "run_demo_1",
    role: "user",
    author: "Operator",
    content: "Full test of 10.10.14.5 — webapp and infrastructure review.",
    metadata: {},
    created_at: "",
  },
  {
    id: "m2",
    run_id: "run_demo_1",
    role: "orchestrator",
    author: "Vantix",
    content: "Acknowledged. Initialising recon phase and spawning specialist agents.",
    metadata: {},
    created_at: "",
  },
];
const MOCK_PHASE: RunPhase = {
  current: "recon",
  completed: ["init"],
  pending: ["exploit", "validate", "post-exploit", "report"],
  updated_at: "",
  reason: "Running in demo mode — connect the API to see live data.",
  history: [],
};
const MOCK_VECTORS: Vector[] = [
  {
    id: "v1",
    title: "Apache 2.4.49 Remote Code Execution (CVE-2021-41773)",
    summary: "Unauthenticated RCE surfaced by the recon agent — mod_cgi enabled.",
    source: "recon",
    confidence: 0.96,
    severity: "critical",
    status: "queued",
    evidence: "nmap + curl PoC confirmed",
    next_action: "Execute mod_cgi RCE payload",
    metadata: { business_impact: "Full server compromise." },
    created_at: "",
  },
];
const MOCK_APPROVALS: Approval[] = [];
const MOCK_FINDINGS: Finding[] = [];
const TERMINAL_LINES = [
  "[*] Starting Nmap scan on demo target…",
  "22/tcp    open  ssh      OpenSSH 8.2p1",
  "80/tcp    open  http     Apache httpd 2.4.49",
  "[+] Recon phase staged (demo mode).",
];

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
  demoMode,
}: {
  run: Run | null;
  findings: Finding[];
  phase: RunPhase | null;
  demoMode: boolean;
}) {
  if (!run) return null;
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => {
    const k = (f.severity || "").toLowerCase();
    if (counts[k] !== undefined) counts[k]++;
  });
  const risk = calcRisk(findings);
  const ALL = ["init", "recon", "exploit", "validate", "post-exploit", "report"];
  const done = phase?.completed?.length || 0;
  const phasePct = Math.round((done / ALL.length) * 100);
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
          {phase?.current || "init"}
        </span>
      </div>
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
        {demoMode ? <Badge variant="amber">Demo Mode</Badge> : <Badge variant="ok">● Live API</Badge>}
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
  };
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
                {phaseLabels[phase?.current || ""] || "Initializing"}
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
}: {
  agents: AgentSession[];
  tasks: Task[];
  roles: string[];
}) {
  return (
    <Panel title="Agent Team" meta="Specialist agents">
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        {roles.map((role) => {
          const agent = agents.find((a) => a.role === role);
          const task = tasks.find(
            (t) => t.kind?.includes(role.replace("_", "-")) || t.kind?.includes(role),
          );
          const status = agent?.status || task?.status || "pending";
          const sc: Record<string, string> = {
            running: "#f4b860",
            completed: "#19c37d",
            failed: "#ef4444",
            blocked: "#ef4444",
            pending: "#7a9e92",
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
                border: `1px solid rgba(140,185,165,${status === "running" ? 0.22 : 0.1})`,
              }}
            >
              <StatusDot status={status} size={7} />
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

// ─── Phase ─────────────────────────────────────────────────────────────────
function PhasePanel({ phase }: { phase: RunPhase | null }) {
  if (!phase)
    return (
      <Panel title="Engagement Phase">
        <EmptyState icon="◎" text="No phase state loaded." />
      </Panel>
    );
  const ALL = ["init", "recon", "exploit", "validate", "post-exploit", "report"];
  return (
    <Panel title="Engagement Phase" meta={phase.current}>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {ALL.map((p, i) => {
          const done = phase.completed?.includes(p);
          const active = p === phase.current;
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
  return (
    <Panel title="Attack Vectors" meta={`${vectors.length} candidates`} style={{ gridColumn: "span 2" }}>
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
    <Panel title="Known Vulnerabilities" meta={`${facts.length} matched`}>
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
        <EmptyState icon="⊙" text="No CVE matches yet." />
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

// ─── Results ────────────────────────────────────────────────────────────────
function ResultsPanel({ results }: { results: RunResults | null }) {
  const findings = results?.findings || [];
  const artifacts = results?.artifacts || [];
  return (
    <Panel title="Findings & Report" meta="Confirmed vulnerabilities" style={{ gridColumn: "span 2" }}>
      {results ? (
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
            <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
              {artifacts.slice(0, 6).map((a, i) => (
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
                    }}
                  >
                    {a.path}
                  </span>
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
                <div style={{ fontFamily: "var(--mono)", fontSize: ".7rem", color: "#7a9e92" }}>
                  {results.report_path}
                </div>
              </div>
            )}
          </div>
        </div>
      ) : (
        <EmptyState icon="◇" text="No results yet." />
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
  onSave,
  canSave,
}: {
  note: string;
  setNote: (v: string) => void;
  onSave: () => void;
  canSave: boolean;
}) {
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
      <Btn size="sm" onClick={onSave} disabled={!canSave}>
        Save Note
      </Btn>
    </Panel>
  );
}

// ─── API config ─────────────────────────────────────────────────────────────
function ApiConfigPanel({
  apiToken,
  setApiTokenValue,
  demoMode,
  onTest,
  testing,
}: {
  apiToken: string;
  setApiTokenValue: (v: string) => void;
  demoMode: boolean;
  onTest: () => void;
  testing: boolean;
}) {
  return (
    <Panel title="API Connection" style={{ gridColumn: "span 2" }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <div>
          <Label>API Token</Label>
          <input
            type="password"
            value={apiToken}
            onChange={(e) => setApiTokenValue(e.target.value)}
            placeholder="SECOPS_API_TOKEN"
            style={{
              width: "100%",
              padding: "8px 12px",
              background: "rgba(5,10,10,.9)",
              border: "1px solid rgba(140,185,165,.18)",
              borderRadius: 10,
              color: "#e8f4ee",
              fontSize: ".78rem",
              marginBottom: 10,
              boxSizing: "border-box",
            }}
          />
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Btn size="sm" variant="primary" onClick={onTest} disabled={testing}>
              {testing ? "Testing…" : "Test Connection"}
            </Btn>
            <Badge variant={demoMode ? "amber" : "ok"}>{demoMode ? "Demo Mode" : "Connected"}</Badge>
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
          <div style={{ fontSize: ".74rem", fontWeight: 600, color: "#e8f4ee", marginBottom: 8 }}>
            About Demo Mode
          </div>
          <p style={{ margin: "0 0 8px", fontSize: ".73rem", color: "#7a9e92", lineHeight: 1.55 }}>
            When the backend cannot be reached, Vantix runs in Demo Mode using sample data so you can explore the UI.
          </p>
          <p style={{ margin: 0, fontSize: ".73rem", color: "#7a9e92", lineHeight: 1.55 }}>
            Supply a token above (stored in browser local storage) and click Test Connection to talk to the live API.
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
}: {
  runs: Run[];
  selected: Run | null;
  onSelect: (r: Run) => void;
  mode: string;
  setMode: (v: string) => void;
  target: string;
  setTarget: (v: string) => void;
}) {
  return (
    <aside className="vx-sidebar">
      <div className="vx-sidebar-inner">
        <div style={{ marginBottom: 22 }}>
          <div
            style={{
              fontSize: ".62rem",
              fontWeight: 700,
              letterSpacing: ".18em",
              textTransform: "uppercase",
              color: "#f4b860",
              marginBottom: 6,
            }}
          >
            Autonomous Offensive Security Suite
          </div>
          <div
            style={{
              fontSize: "2.5rem",
              fontWeight: 700,
              letterSpacing: ".14em",
              lineHeight: 0.9,
              color: "#19c37d",
              fontFamily: "var(--mono)",
            }}
          >
            VANTIX
          </div>
          <div style={{ fontSize: ".7rem", color: "#7a9e92", marginTop: 6 }}>Recon · Exploit · Forge · Report</div>
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
                  borderRadius: 7,
                  fontSize: ".68rem",
                  fontWeight: 600,
                  background: mode === m ? "rgba(25,195,125,.15)" : "rgba(255,255,255,.04)",
                  border: `1px solid ${mode === m ? "rgba(25,195,125,.4)" : "rgba(140,185,165,.12)"}`,
                  color: mode === m ? "#19c37d" : "#7a9e92",
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
              border: "1px solid rgba(140,185,165,.18)",
              borderRadius: 10,
              color: "#e8f4ee",
              fontSize: ".76rem",
            }}
          />
          <div style={{ fontSize: ".66rem", color: "#7a9e92", marginTop: 5 }}>
            Use the chat to launch or continue an engagement.
          </div>
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
  statusMsg,
  onRefresh,
  onPause,
  onRetry,
  onReplan,
  onCancel,
}: {
  run: Run | null;
  phase: RunPhase | null;
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
  const [apiToken, setApiTokenState] = useState(getApiToken());
  const [demoMode, setDemoMode] = useState(true);
  const [testing, setTesting] = useState(false);

  const [runs, setRuns] = useState<Run[]>(MOCK_RUNS);
  const [selectedRun, setSelectedRun] = useState<Run | null>(MOCK_RUNS[0]);
  const [phase, setPhase] = useState<RunPhase | null>(MOCK_PHASE);
  const [messages, setMessages] = useState<RunMessage[]>(MOCK_MESSAGES);
  const [vectors, setVectors] = useState<Vector[]>(MOCK_VECTORS);
  const [facts, setFacts] = useState<Fact[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>(MOCK_APPROVALS);
  const [findings, setFindings] = useState<Finding[]>(MOCK_FINDINGS);
  const [results, setResults] = useState<RunResults | null>(null);
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [skillApps, setSkillApps] = useState<RunSkillApplication[]>([]);
  const [agents, setAgents] = useState<AgentSession[]>([]);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [learning, setLearning] = useState<Array<Record<string, unknown>>>([]);
  const [termLines, setTermLines] = useState<string[]>([]);

  const [tab, setTab] = useState<Tab>("overview");
  const [chatText, setChatText] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [note, setNote] = useState("");
  const [statusMsg, setStatusMsg] = useState("");
  const [mode, setMode] = useState("pentest");
  const [target, setTarget] = useState("");

  const streamRef = useRef<EventSource | null>(null);

  const flash = useCallback((msg: string) => {
    setStatusMsg(msg);
    window.setTimeout(() => setStatusMsg(""), 5000);
  }, []);

  const setApiTokenValue = useCallback((value: string) => {
    setApiTokenState(value);
    persistApiToken(value);
  }, []);

  const testConnection = useCallback(async () => {
    setTesting(true);
    try {
      await api.systemStatus();
      setDemoMode(false);
      flash("Connected to live API");
    } catch {
      setDemoMode(true);
      flash("Cannot reach API — running in demo mode");
    } finally {
      setTesting(false);
    }
  }, [flash]);

  // Initial connection probe
  useEffect(() => {
    testConnection();
  }, [testConnection]);

  const refreshRuns = useCallback(async () => {
    try {
      const rows = await api.listRuns();
      setRuns(rows);
    } catch {
      // silent — demo mode
    }
  }, []);

  const refreshRun = useCallback(
    async (runId: string) => {
      try {
        const [run, graph, runFacts, learningHits, runMessages, runVectors, runResults, runSkills, runChains] =
          await Promise.all([
            api.getRun(runId),
            api.getGraph(runId),
            api.getFacts(runId).catch(() => [] as Fact[]),
            api.getLearning(runId).catch(() => ({ run_id: runId, mode: "", results: [] as Array<Record<string, unknown>> })),
            api.getMessages(runId).catch(() => [] as RunMessage[]),
            api.getVectors(runId).catch(() => [] as Vector[]),
            api.getResults(runId).catch(() => null as RunResults | null),
            api.getSkills(runId).catch(() => [] as RunSkillApplication[]),
            api.getAttackChains(runId).catch(() => [] as AttackChain[]),
          ]);
        setSelectedRun(run);
        setPhase(graph.phase);
        setAgents(graph.agents);
        setTasks(graph.tasks);
        setApprovals(graph.approvals);
        setFacts(runFacts);
        setLearning(learningHits.results);
        setMessages(runMessages);
        setVectors(runVectors);
        setResults(runResults);
        setFindings(runResults?.findings || []);
        setSkillApps(runSkills);
        setChains(runChains);
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) {
          setSelectedRun(null);
          flash("Selected run no longer exists.");
          refreshRuns();
          return;
        }
        flash(`Load error: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
    [flash, refreshRuns],
  );

  // Load run list + select first when switching out of demo mode
  useEffect(() => {
    if (demoMode) return;
    (async () => {
      await refreshRuns();
    })();
  }, [demoMode, refreshRuns]);

  // Watch selected run; poll / stream while in live mode
  useEffect(() => {
    streamRef.current?.close();
    streamRef.current = null;
    if (demoMode || !selectedRun) return;
    refreshRun(selectedRun.id);
    if (apiToken) {
      const interval = window.setInterval(() => refreshRun(selectedRun.id), 3000);
      return () => window.clearInterval(interval);
    }
    try {
      const source = new EventSource(`/api/v1/runs/${selectedRun.id}/stream`);
      source.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as EventRecord;
          if (data.event_type === "terminal") {
            setTermLines((lines) => [...lines.slice(-199), data.message]);
          } else {
            refreshRun(selectedRun.id);
          }
        } catch {
          /* ignore */
        }
      };
      source.onerror = () => {
        source.close();
        refreshRun(selectedRun.id);
      };
      streamRef.current = source;
      return () => source.close();
    } catch {
      // EventSource unavailable — silent
    }
  }, [demoMode, selectedRun?.id, apiToken, refreshRun]);

  // Live terminal text from results summary (fallback) when in live mode with no stream
  useEffect(() => {
    if (demoMode) return;
    const summary = results?.terminal_summary;
    if (summary && streamRef.current === null) {
      setTermLines(summary.split("\n"));
    }
  }, [demoMode, results?.terminal_summary]);

  // Demo mode streams the canned terminal lines
  useEffect(() => {
    if (!demoMode) return;
    setTermLines([]);
    let i = 0;
    const id = window.setInterval(() => {
      if (i < TERMINAL_LINES.length) {
        setTermLines((l) => [...l, TERMINAL_LINES[i]]);
        i++;
      } else {
        window.clearInterval(id);
      }
    }, 250);
    return () => window.clearInterval(id);
  }, [demoMode]);

  async function handleSend(event: FormEvent) {
    event.preventDefault();
    if (!chatText.trim()) return;
    const txt = chatText;
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
    if (demoMode) {
      window.setTimeout(
        () =>
          setMessages((m) => [
            ...m,
            {
              id: `m${Date.now() + 1}`,
              run_id: selectedRun?.id || "",
              role: "orchestrator",
              author: "Vantix",
              content: `Received: "${txt}". Connect the API in the Config tab to dispatch a real engagement.`,
              metadata: {},
              created_at: "",
            },
          ]),
        700,
      );
      return;
    }
    setChatLoading(true);
    try {
      const res = await api.submitChat({
        message: txt,
        run_id: selectedRun?.id,
        mode,
        target: selectedRun ? undefined : target || undefined,
      });
      setSelectedRun(res.run);
      flash(res.scheduler_status);
      await refreshRuns();
      await refreshRun(res.run.id);
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

  async function handleApprove(a: Approval) {
    if (!demoMode) {
      try {
        await api.approve(a.id);
      } catch (error) {
        flash(`Approve failed: ${error instanceof Error ? error.message : String(error)}`);
        return;
      }
      if (selectedRun) refreshRun(selectedRun.id);
    }
    setApprovals((ap) => ap.map((x) => (x.id === a.id ? { ...x, status: "approved" } : x)));
    flash(`Approved: ${a.title}`);
  }
  async function handleReject(a: Approval) {
    if (!demoMode) {
      try {
        await api.reject(a.id);
      } catch (error) {
        flash(`Reject failed: ${error instanceof Error ? error.message : String(error)}`);
        return;
      }
      if (selectedRun) refreshRun(selectedRun.id);
    }
    setApprovals((ap) => ap.map((x) => (x.id === a.id ? { ...x, status: "rejected" } : x)));
    flash(`Rejected: ${a.title}`);
  }
  async function handleSelectVector(v: Vector) {
    if (!demoMode && selectedRun) {
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
    if (!demoMode) {
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
    }
    flash(`Promoted: ${v.title}`);
  }
  async function handlePromoteChain(c: AttackChain) {
    if (!selectedRun) return;
    if (!demoMode) {
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
    }
    flash(`Chain promoted: ${c.name}`);
  }
  async function handleApplySkills() {
    if (!selectedRun) return;
    if (demoMode) {
      flash("Skills reapplied (demo)");
      return;
    }
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
    if (!demoMode) {
      try {
        await api.addNote(selectedRun.id, note);
      } catch (error) {
        flash(`Save failed: ${error instanceof Error ? error.message : String(error)}`);
        return;
      }
    }
    setNote("");
    flash("Note saved");
  }

  function handleSelectRun(run: Run) {
    setSelectedRun(run);
    if (demoMode) return;
    refreshRun(run.id);
  }

  const cveFacts = useMemo(() => facts.filter((f) => f.kind === "cve"), [facts]);

  const TABS: Array<{ id: Tab; label: string }> = [
    { id: "overview", label: "Overview" },
    { id: "intel", label: "Intel" },
    { id: "results", label: "Results & Report" },
    { id: "config", label: "Config" },
  ];

  async function runAction(action: "pause" | "retry" | "replan" | "cancel" | "refresh") {
    if (!selectedRun) return;
    if (action === "refresh") {
      if (!demoMode) refreshRun(selectedRun.id);
      flash("Refreshed");
      return;
    }
    if (demoMode) {
      flash(`${action} (demo)`);
      return;
    }
    try {
      if (action === "pause") await api.pauseRun(selectedRun.id);
      else if (action === "retry") await api.retryRun(selectedRun.id);
      else if (action === "replan") await api.replanRun(selectedRun.id);
      else if (action === "cancel") await api.cancelRun(selectedRun.id);
      flash(`${action} issued`);
      refreshRun(selectedRun.id);
    } catch (error) {
      flash(error instanceof Error ? error.message : String(error));
    }
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
      />
      <main style={{ padding: 20, minWidth: 0, display: "flex", flexDirection: "column" }}>
        <TopBar
          run={selectedRun}
          phase={phase}
          statusMsg={statusMsg}
          onRefresh={() => runAction("refresh")}
          onPause={() => runAction("pause")}
          onRetry={() => runAction("retry")}
          onReplan={() => runAction("replan")}
          onCancel={() => runAction("cancel")}
        />
        <RiskBar run={selectedRun} findings={findings} phase={phase} demoMode={demoMode} />
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
            <AgentsPanel agents={agents} tasks={tasks} roles={ROLES} />
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
            <MemoryPanel hits={learning} />
            <ChainsPanel chains={chains} onPromote={handlePromoteChain} selectedRunId={selectedRun?.id} />
          </div>
        )}

        {tab === "results" && (
          <div className="vx-grid">
            <ResultsPanel results={results} />
          </div>
        )}

        {tab === "config" && (
          <div className="vx-grid">
            <ApprovalsPanel approvals={approvals} onApprove={handleApprove} onReject={handleReject} />
            <SkillsPanel applications={skillApps} onApply={handleApplySkills} selectedRunId={selectedRun?.id} />
            <NotesPanel
              note={note}
              setNote={setNote}
              onSave={handleSaveNote}
              canSave={Boolean(selectedRun && note.trim())}
            />
            <ApiConfigPanel
              apiToken={apiToken}
              setApiTokenValue={setApiTokenValue}
              demoMode={demoMode}
              onTest={testConnection}
              testing={testing}
            />
          </div>
        )}
      </main>
    </div>
  );
}
