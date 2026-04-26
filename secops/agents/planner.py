"""PlannerAgent — emits a Plan given a RunState.

The production planner will be LLM-backed; this module provides the
wiring skeleton plus a ``StaticPlanner`` used by tests and deterministic
replay. ``CachedPlannerAgent`` adds LlmCacheEntry lookup so a planner
that is otherwise LLM-bound becomes deterministic during replay
(``require_cache=True``) and benefits from cache reuse during normal
runs (``require_cache=False``).
"""

from __future__ import annotations

import json
from typing import Any, Callable

from sqlalchemy.orm import Session

from secops.agents.base import BaseAgent, RunState
from secops.bus.messages import Plan, ProposedAction


PlanFn = Callable[[RunState], Plan]
PromptFn = Callable[[RunState], Any]


class PlannerAgent(BaseAgent):
    role = "planner"

    def __init__(self, plan_fn: PlanFn) -> None:
        self._plan_fn = plan_fn

    def plan(self, state: RunState) -> Plan:
        plan = self._plan_fn(state)
        if plan.turn_id != state.turn_id:
            plan = plan.model_copy(update={"turn_id": state.turn_id})
        return plan


class StaticPlanner(PlannerAgent):
    """Returns the same ordered actions on every turn. Deterministic; for tests."""

    def __init__(self, actions: list[ProposedAction], *, rationale: str = "") -> None:
        def _fn(state: RunState) -> Plan:
            return Plan(turn_id=state.turn_id, rationale=rationale, actions=list(actions))

        super().__init__(_fn)


class ReplayCacheMiss(RuntimeError):
    """Raised when a CachedPlannerAgent in strict replay mode misses the cache."""


class CachedPlannerAgent(PlannerAgent):
    """LLM-backed planner with deterministic LlmCacheEntry lookup.

    On ``plan(state)``:
        1. Build (model, params, prompt) via the supplied callables.
        2. Look up LlmCacheEntry. On hit, decode the cached JSON Plan.
        3. On miss with ``require_cache=True``, raise ``ReplayCacheMiss``.
        4. On miss with ``require_cache=False``, call ``plan_fn``, persist the
           plan bytes via ``llm_cache.store``, and return.

    The cache stores the canonical-JSON serialization of the Plan model.
    """

    def __init__(
        self,
        plan_fn: PlanFn,
        *,
        db: Session,
        model: str,
        prompt_fn: PromptFn,
        params_fn: Callable[[RunState], Any] | None = None,
        require_cache: bool = False,
    ) -> None:
        super().__init__(plan_fn)
        self._db = db
        self._model = model
        self._prompt_fn = prompt_fn
        self._params_fn = params_fn or (lambda _state: {})
        self._require_cache = require_cache

    def plan(self, state: RunState) -> Plan:
        from secops.replay import llm_cache

        prompt = self._prompt_fn(state)
        params = self._params_fn(state)
        hit = llm_cache.lookup(self._db, model=self._model, params=params, prompt=prompt)
        if hit is not None:
            try:
                payload = json.loads(hit.response_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"corrupt llm_cache entry {hit.key_sha256[:12]}: {exc}") from exc
            cached_plan = Plan.model_validate(payload)
            if cached_plan.turn_id != state.turn_id:
                cached_plan = cached_plan.model_copy(update={"turn_id": state.turn_id})
            return cached_plan

        if self._require_cache:
            raise ReplayCacheMiss(
                f"llm_cache miss for model={self._model} turn={state.turn_id}; replay requires deterministic cache hit"
            )

        plan = super().plan(state)
        body = plan.model_dump_json().encode("utf-8")
        llm_cache.store(self._db, model=self._model, params=params, prompt=prompt, response=body)
        return plan
