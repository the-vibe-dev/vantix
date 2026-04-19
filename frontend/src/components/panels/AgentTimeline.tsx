import { AgentSession, Task } from "../../api";

export function AgentTimeline(props: { agents: AgentSession[]; tasks: Task[]; roles: string[] }) {
  return (
    <article className="panel">
      <header><h3>Specialists</h3><span>Scheduler roles</span></header>
      <div className="agent-grid">
        {props.roles.map((role) => {
          const agent = props.agents.find((item) => item.role === role);
          const task = props.tasks.find((item) => item.kind.includes(role.replace("_", "-")) || item.kind.includes(role));
          return <div key={role} className={`agent ${agent?.status || "pending"}`}><strong>{role.replace("_", " ")}</strong><span>{agent?.status || task?.status || "pending"}</span></div>;
        })}
      </div>
    </article>
  );
}
