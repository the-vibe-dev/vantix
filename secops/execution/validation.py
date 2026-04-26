from __future__ import annotations

from typing import Any

from secops.execution.constants import (
    DEFAULT_VALIDATION_CONFIG,
    HIGH_RISK_RISK_TAGS,
    RISK_TAG_PATTERNS,
)
from secops.models import WorkspaceRun


class ValidationMixin:
    """Risk-tag normalization, impact bounds, validation metadata.

    Extracted from ExecutionManager. No external state besides
    constants imported above.
    """

    def _validation_config(self, run: WorkspaceRun) -> dict[str, Any]:
        cfg = dict(getattr(run, "config_json", None) or {})
        supplied = cfg.get("validation")
        if not isinstance(supplied, dict):
            supplied = {}
        merged = {**DEFAULT_VALIDATION_CONFIG, **supplied}
        high_risk_default = dict(DEFAULT_VALIDATION_CONFIG.get("high_risk_surfaces") or {})
        high_risk_supplied = supplied.get("high_risk_surfaces")
        if not isinstance(high_risk_supplied, dict):
            high_risk_supplied = {}
        high_risk = {**high_risk_default, **high_risk_supplied}
        mode = str(merged.get("risk_mode") or "always_attempt").strip().lower()
        if mode not in {"always_attempt", "operator_gated", "metadata_only"}:
            mode = "always_attempt"
        merged["risk_mode"] = mode
        high_risk["enabled"] = bool(high_risk.get("enabled", True))
        label = str(high_risk.get("label") or "").strip() or str(high_risk_default.get("label") or "High Risk Surfaces")
        high_risk["label"] = label[:80]
        merged["high_risk_surfaces"] = high_risk
        for key in (
            "allow_state_mutation",
            "allow_availability_tests",
            "allow_local_file_read_checks",
            "allow_persistence_adjacent_checks",
        ):
            merged[key] = bool(merged.get(key))
        try:
            merged["max_requests_per_vector"] = max(1, int(merged.get("max_requests_per_vector") or 1))
        except (TypeError, ValueError):
            merged["max_requests_per_vector"] = int(DEFAULT_VALIDATION_CONFIG["max_requests_per_vector"])
        try:
            merged["request_timeout_seconds"] = max(1, int(merged.get("request_timeout_seconds") or 8))
        except (TypeError, ValueError):
            merged["request_timeout_seconds"] = int(DEFAULT_VALIDATION_CONFIG["request_timeout_seconds"])
        return merged

    def _normalize_risk_tags(self, text: str) -> list[str]:
        lowered = f" {str(text or '').lower()} "
        tags: list[str] = []
        for tag, patterns in RISK_TAG_PATTERNS:
            if any(pattern in lowered for pattern in patterns):
                tags.append(tag)
        return tags

    def _high_risk_surfaces_config(self, validation_cfg: dict[str, Any]) -> dict[str, Any]:
        raw = validation_cfg.get("high_risk_surfaces")
        if not isinstance(raw, dict):
            raw = {}
        return {
            "enabled": bool(raw.get("enabled", True)),
            "label": str(raw.get("label") or "High Risk Surfaces").strip() or "High Risk Surfaces",
        }

    def _is_high_risk_surface(self, risk_tags: list[str]) -> bool:
        return bool(set(risk_tags or []).intersection(HIGH_RISK_RISK_TAGS))

    def _impact_bound_for_risk(self, risk_tags: list[str], validation_cfg: dict[str, Any]) -> str:
        tags = set(risk_tags or [])
        limit = int(validation_cfg.get("max_requests_per_vector") or 1)
        timeout = int(validation_cfg.get("request_timeout_seconds") or 8)
        parts = [f"max {limit} request(s) per vector", f"{timeout}s request timeout"]
        if "availability-impact" in tags:
            parts.append("bounded availability probe only; no sustained load")
        if "state-mutation" in tags:
            parts.append("single canary mutation where required")
        if "server-local-read" in tags:
            parts.append("single local-read proof request")
        if "persistence-adjacent" in tags:
            parts.append("harmless marker payload only")
        if "credential-exposure" in tags:
            parts.append("capture proof material in run artifacts")
        return "; ".join(parts)

    def _state_changed_for_risk(self, risk_tags: list[str]) -> bool:
        tags = set(risk_tags or [])
        return bool(tags.intersection({"state-mutation", "persistence-adjacent"}))

    def _append_validation_metadata(self, evidence: str, item: dict[str, Any]) -> str:
        block = [
            "Validation Metadata:",
            f"- Attempted: {'yes' if item.get('attempted', True) else 'no'}",
            f"- Risk Tags: {', '.join(str(tag) for tag in (item.get('risk_tags') or [])) or 'none'}",
            f"- Impact Bound: {item.get('impact_bound') or ''}",
            f"- State Changed: {'yes' if item.get('state_changed') else 'no'}",
            f"- Cleanup Attempted: {'yes' if item.get('cleanup_attempted') else 'no'}",
        ]
        why_not = str(item.get("why_not_attempted") or "").strip()
        if why_not:
            block.append(f"- Why Not Attempted: {why_not}")
        existing = str(evidence or "").rstrip()
        if "Validation Metadata:" in existing:
            return existing
        return f"{existing}\n\n" + "\n".join(block)
