import { Fact, Run } from "../../api";

export function TargetPanel({ selectedRun, facts }: { selectedRun: Run | null; facts: Fact[] }) {
  return <article className="panel"><header><h3>Target</h3><span>Profile</span></header>{selectedRun ? <><p><strong>{selectedRun.target}</strong></p><p>{selectedRun.objective}</p></> : <p className="empty">No target selected.</p>}<List items={facts.slice(0, 6).map((fact) => `${fact.kind}: ${fact.value}`)} /></article>;
}

function List({ items }: { items: string[] }) {
  if (!items.length) return <p className="empty">No records.</p>;
  return <ul>{items.map((item, index) => <li key={`${item}-${index}`}><span>{item}</span></li>)}</ul>;
}
