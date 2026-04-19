from __future__ import annotations

from secops.services.intel_sources.base import SourceAdapter, SourceUpdateResult
from secops.services.intel_sources.registry import adapter_for, available_sources

__all__ = ["SourceAdapter", "SourceUpdateResult", "adapter_for", "available_sources"]
