import { PlanningBundle, RunResults } from "../../api";

export function ResultsPanel({ results, planningBundle }: { results: RunResults | null; planningBundle: PlanningBundle | null }) {
  return (
    <article className="panel">
      <header><h3>Results</h3><span>Evidence and artifacts</span></header>
      {results ? (
        <>
          <p>Status: {results.status}</p>
          <p>Report: {results.report_path || "not generated"}</p>
          <p>Report JSON: {results.report_json_path || "not generated"}</p>
          <List items={results.artifacts.slice(0, 6).map((artifact) => `${artifact.kind}: ${artifact.path}`)} empty="No artifacts yet." />
          {planningBundle?.missing_evidence?.length ? <List items={planningBundle.missing_evidence.slice(0, 4)} empty="" /> : null}
        </>
      ) : <p className="empty">No results yet.</p>}
    </article>
  );
}

function List({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <p className="empty">{empty}</p>;
  return <ul>{items.map((item, index) => <li key={`${item}-${index}`}><span>{item}</span></li>)}</ul>;
}
