export function TerminalPanel({ terminalText }: { terminalText: string }) {
  return <article className="panel terminal"><header><h3>Live Terminal</h3><span>Runtime stream</span></header><pre>{terminalText}</pre></article>;
}
