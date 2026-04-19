import { Fact } from "../../api";

export function CveIntelPanel({ cveFacts }: { cveFacts: Fact[] }) {
  return <article className="panel"><header><h3>CVE Intel</h3><span>{cveFacts.length} facts</span></header><List items={cveFacts.map((fact) => `${fact.value} (${fact.confidence})`)} empty="No CVE facts yet." /></article>;
}

function List({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <p className="empty">{empty}</p>;
  return <ul>{items.map((item, index) => <li key={`${item}-${index}`}><span>{item}</span></li>)}</ul>;
}
