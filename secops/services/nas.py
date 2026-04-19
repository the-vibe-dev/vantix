from __future__ import annotations

from secops.services.storage import RunPaths, StorageLayout

# Backwards-compatible aliases for older code/imports.
NASLayout = StorageLayout

__all__ = ["RunPaths", "StorageLayout", "NASLayout"]
