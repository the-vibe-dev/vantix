import { Run, RunSkillApplication } from "../../api";

export function SkillPanel(props: { applications: RunSkillApplication[]; selectedRun: Run | null; onApply: () => void }) {
  const total = props.applications.reduce((count, item) => count + item.skills.length, 0);
  return (
    <article className="panel">
      <header>
        <h3>Skill Packs</h3>
        <span>{total} applied</span>
      </header>
      {props.selectedRun ? <button onClick={props.onApply}>Reapply Skills</button> : null}
      <ul className="skill-list">
        {props.applications.map((application) => (
          <li key={application.agent_role}>
            <strong>{application.agent_role.replace("_", " ")}</strong>
            <span>{application.skills.map((skill) => skill.id).join(", ") || "none"}</span>
            <small>{application.prompt_path}</small>
          </li>
        ))}
      </ul>
      {!props.applications.length ? <p className="empty">No skill applications yet.</p> : null}
    </article>
  );
}
