import { AttackChain } from "../../api";

export function AttackChainPanel(props: { chains: AttackChain[]; onPromote?: (chain: AttackChain) => void }) {
  return (
    <article className="panel">
      <header>
        <h3>Attack Chains</h3>
        <span>{props.chains.length} paths</span>
      </header>
      <ul className="chain-list">
        {props.chains.map((chain) => (
          <li key={chain.id}>
            <strong>{chain.name}</strong>
            <span>{chain.status} / score {chain.score}</span>
            <p>{chain.notes || `${chain.steps.length} steps`}</p>
            {props.onPromote ? <button onClick={() => props.onPromote?.(chain)}>Promote Finding</button> : null}
          </li>
        ))}
      </ul>
      {!props.chains.length ? <p className="empty">No attack chains modeled yet.</p> : null}
    </article>
  );
}
