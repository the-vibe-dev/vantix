"""V2-19 — Active-Directory specialist reference agent.

Built entirely on the public SDK surface. Given a frontier of services
(LDAP/SMB/Kerberos) or credential facts, it proposes bounded AD recon
actions (enumerate users, kerberoast, bloodhound-style collection).

Reference implementation; the actual execution of these actions is up
to tool adapters registered with the executor.
"""

from __future__ import annotations

from typing import Any

import vantix_sdk as vx


AD_ACTION_KIND = "ad_probe"
AD_SERVICE_PORTS = (":88", ":389", ":445", ":636", ":3268", ":3269")
MAX_ACTIONS_PER_TURN = 5


class AdAgent(vx.BaseAgent):
    """Propose Active Directory recon actions from graph frontier."""

    role = "specialist:active_directory"

    def __init__(self, *, action_kind: str = AD_ACTION_KIND, risk: str = "medium"):
        self._action_kind = action_kind
        self._risk = risk

    def plan(self, state: vx.RunState) -> vx.Plan:
        frontier = list(state.frontier or [])
        actions: list[vx.ProposedAction] = []
        for item in frontier[:MAX_ACTIONS_PER_TURN]:
            if not self._is_ad_candidate(item):
                continue
            label = str(item.get("label") or item.get("node_id") or "")
            actions.append(
                vx.ProposedAction(
                    action_type=self._action_kind,
                    objective=f"enumerate {label}",
                    risk=self._risk,  # type: ignore[arg-type]
                    inputs={"target": label, "source": item.get("kind", "")},
                )
            )
        return vx.Plan(
            turn_id=state.turn_id,
            rationale="AD specialist: enumerate directory, extract tickets where policy allows",
            actions=actions,
        )

    @staticmethod
    def _is_ad_candidate(item: dict[str, Any]) -> bool:
        kind = str(item.get("kind") or "")
        label = str(item.get("label") or "").lower()
        if kind in {"unexplored_service", "scored_edge"} and any(tok in label for tok in AD_SERVICE_PORTS):
            return True
        if kind in {"unexplored_service", "scored_edge"} and any(
            tok in label for tok in ("ldap", "smb", "kerberos", "activedirectory", "active-directory")
        ):
            return True
        if kind == "open_hypothesis":
            meta = (item.get("detail") or {}).get("metadata") or {}
            tags = [str(t).lower() for t in meta.get("tags", []) or []]
            return any(t in {"ad", "active_directory", "windows", "kerberos"} for t in tags)
        return False


__all__ = ["AdAgent", "AD_ACTION_KIND"]
