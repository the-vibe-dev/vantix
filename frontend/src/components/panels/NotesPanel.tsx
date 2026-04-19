export function NotesPanel(props: { note: string; setNote: (value: string) => void; canSave: boolean; onSave: () => void }) {
  return <article className="panel"><header><h3>Operator Notes</h3><span>Human guidance</span></header><textarea value={props.note} onChange={(event) => props.setNote(event.target.value)} placeholder="Add guidance when the run gets stuck." /><button onClick={props.onSave} disabled={!props.canSave}>Send Note</button></article>;
}
