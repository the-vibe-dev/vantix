import { Handoff } from "../../api";

export function HandoffPanel({ handoff }: { handoff: Handoff | null }) {
  return (
    <article className="panel">
      <header>
        <h3>Agent Handoff</h3>
        <span>{handoff?.phase || "not ready"}</span>
      </header>
      {handoff ? (
        <>
          <p><strong>{handoff.target}</strong> / {handoff.mode} / {handoff.status}</p>
          <List items={handoff.next_actions} empty="No next actions." />
          <p className="hint">Scope: {handoff.scope}</p>
        </>
      ) : (
        <p className="empty">No handoff generated.</p>
      )}
    </article>
  );
}

function List({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <p className="empty">{empty}</p>;
  return <ul>{items.map((item, index) => <li key={`${item}-${index}`}><span>{item}</span></li>)}</ul>;
}
