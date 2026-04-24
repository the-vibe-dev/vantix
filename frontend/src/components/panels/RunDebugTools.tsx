import { useState } from "react";
import { DecisionGraphDrawer } from "./DecisionGraphDrawer";
import { PolicyDecisionDrawer } from "./PolicyDecisionDrawer";
import { RunCompareDrawer } from "./RunCompareDrawer";

type Props = {
  runId: string;
  // Optional second run to seed the compare-drawer picker. If omitted,
  // the user is prompted for one inline.
  compareWithRunId?: string;
};

type Drawer = "none" | "policy" | "graph" | "compare";

// V2-20 + V2-21 promotion — single entry point exposing the three v2
// drawers (policy decisions, decision graph, run-diff) so operators can
// jump from any run view to verifiable provenance.
export function RunDebugTools({ runId, compareWithRunId }: Props) {
  const [active, setActive] = useState<Drawer>("none");
  const [otherRun, setOtherRun] = useState(compareWithRunId || "");

  const open = (drawer: Drawer) => () => setActive(drawer);
  const close = () => setActive("none");

  return (
    <>
      <div style={{ display: "flex", gap: ".5rem", flexWrap: "wrap" }}>
        <button onClick={open("policy")} aria-label="Open policy-decision drawer">
          Policy decisions
        </button>
        <button onClick={open("graph")} aria-label="Open decision-graph drawer">
          Decision graph
        </button>
        <div style={{ display: "flex", gap: ".25rem", alignItems: "center" }}>
          <input
            placeholder="run to diff against"
            value={otherRun}
            onChange={(e) => setOtherRun(e.target.value)}
            style={{ width: "16rem" }}
          />
          <button
            onClick={open("compare")}
            disabled={!otherRun || otherRun === runId}
            aria-label="Open run-diff drawer"
          >
            Compare
          </button>
        </div>
      </div>

      {active === "policy" ? <PolicyDecisionDrawer runId={runId} onClose={close} /> : null}
      {active === "graph" ? <DecisionGraphDrawer runId={runId} onClose={close} /> : null}
      {active === "compare" ? (
        <RunCompareDrawer runA={runId} runB={otherRun} onClose={close} />
      ) : null}
    </>
  );
}
