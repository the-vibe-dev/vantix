"""EvaluatorAgent — reviews observations and emits a Critique.

The Phase-1 default evaluator is rule-based: it flags any failure as a
reason to replan and aggregates success counts into a confidence score.
The LLM-backed evaluator arrives with Phase-3 replay support so its
critiques are cacheable.
"""

from __future__ import annotations

from secops.agents.base import BaseAgent
from secops.bus.messages import Critique, Observation


class EvaluatorAgent(BaseAgent):
    role = "evaluator"

    def __init__(self, *, replan_on_failure: bool = True) -> None:
        self._replan_on_failure = replan_on_failure

    def evaluate(self, observations: list[Observation]) -> Critique:
        if not observations:
            return Critique(turn_id=0, observations=[], should_replan=False, confidence=0.0)
        completed = [o for o in observations if o.status == "completed"]
        failed = [o for o in observations if o.status == "failed"]
        turn_id = max((0, *[o.metrics.get("turn_id", 0) for o in observations]))
        confidence = len(completed) / len(observations)
        if self._replan_on_failure and failed:
            should_replan = True
        elif confidence < 1.0:
            should_replan = True
        else:
            should_replan = False
        notes = ", ".join(o.summary for o in observations if o.summary)[:512]
        return Critique(
            turn_id=turn_id,
            observations=[o.action_id for o in observations],
            should_replan=should_replan,
            confidence=confidence,
            new_hypotheses=[],
            refuted_hypotheses=[],
            notes=notes,
        )
