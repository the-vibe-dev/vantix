import { Approval } from "../../api";

export function ApprovalPanel({ approvals, onApprove, onReject }: { approvals: Approval[]; onApprove: (approval: Approval) => void; onReject: (approval: Approval) => void }) {
  return <article className="panel"><header><h3>Approvals</h3><span>{approvals.length} queued</span></header><ul>{approvals.map((approval) => <li key={approval.id}><strong>{approval.title}</strong><span>{approval.status} / {approval.reason}</span><p>{approval.detail}</p><div className="approval-actions"><button onClick={() => onApprove(approval)}>Approve</button><button onClick={() => onReject(approval)}>Reject</button></div></li>)}</ul>{!approvals.length ? <p className="empty">No approvals pending.</p> : null}</article>;
}
