export function MemoryPanel({ learning }: { learning: Array<Record<string, unknown>> }) {
  return <article className="panel"><header><h3>Memory</h3><span>Similar experience</span></header><ul>{learning.slice(0, 5).map((item, index) => <li key={index}><strong>{String(item.title ?? "Memory hit")}</strong><span>rank {String(item.rank ?? "")}</span><p>{String(item.summary_short ?? item.summary ?? "")}</p></li>)}</ul>{!learning.length ? <p className="empty">No memory hits loaded.</p> : null}</article>;
}
