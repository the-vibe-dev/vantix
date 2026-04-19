export function TerminalPanel({ terminalText, fallback }: { terminalText: string; fallback: string }) {
  return <article className="panel terminal"><header><h3>Live Terminal</h3><span>Runtime stream</span></header><pre>{terminalText || fallback}</pre></article>;
}
