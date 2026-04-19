import { FormEvent } from "react";
import { RunMessage } from "../../api";

export function OrchestratorChat(props: { messages: RunMessage[]; chatText: string; setChatText: (value: string) => void; onSend: (event: FormEvent) => void }) {
  return (
    <article className="panel chat-panel">
      <header><h3>Orchestrator Chat</h3><span>Chat creates or replans runs</span></header>
      <div className="messages">
        {props.messages.length ? props.messages.map((message) => (
          <div key={message.id} className={`message ${message.role}`}>
            <strong>{message.author || message.role}</strong>
            <p>{message.content}</p>
          </div>
        )) : <p className="empty">Ask for a full test of a target to initialize Vantix.</p>}
      </div>
      <form className="chat-input" onSubmit={props.onSend}>
        <textarea value={props.chatText} onChange={(event) => props.setChatText(event.target.value)} placeholder="Full test of 10.10.10.10" />
        <button type="submit">Send to Vantix</button>
      </form>
    </article>
  );
}
