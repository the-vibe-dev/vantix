import { Run, Vector } from "../../api";

export function VectorPanel({ vectors, selectedRun, onSelect, onPromote }: { vectors: Vector[]; selectedRun: Run | null; onSelect: (vector: Vector) => void; onPromote: (vector: Vector) => void }) {
  return <article className="panel"><header><h3>Vectors</h3><span>{vectors.length} candidates</span></header><ul>{vectors.map((vector) => <li key={vector.id}><strong>{vector.title}</strong><span>{vector.source} / {vector.status} / confidence {vector.confidence.toFixed(2)}</span><p>{vector.summary}</p><p>{vector.next_action}</p><div className="approval-actions">{selectedRun ? <button onClick={() => onSelect(vector)}>Select Vector</button> : null}{selectedRun ? <button onClick={() => onPromote(vector)}>Promote Finding</button> : null}</div></li>)}</ul>{!vectors.length ? <p className="empty">No candidate vectors yet.</p> : null}</article>;
}
