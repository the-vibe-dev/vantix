import { AttackChain } from "../../api";

export function AttackChainPanel({ chains }: { chains: AttackChain[] }) {
  return (
    <article className="panel">
      <header>
        <h3>Attack Chains</h3>
        <span>{chains.length} paths</span>
      </header>
      <ul className="chain-list">
        {chains.map((chain) => (
          <li key={chain.id}>
            <strong>{chain.name}</strong>
            <span>{chain.status} / score {chain.score}</span>
            <p>{chain.notes || `${chain.steps.length} steps`}</p>
          </li>
        ))}
      </ul>
      {!chains.length ? <p className="empty">No attack chains modeled yet.</p> : null}
    </article>
  );
}
