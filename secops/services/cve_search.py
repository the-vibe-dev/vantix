from __future__ import annotations

from typing import Any

import httpx

from secops.config import settings
from secops.db import SessionLocal
from secops.services.vuln_intel import VulnIntelService


class CVESearchService:
    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or settings.cve_search_url).rstrip("/")

    def search(self, vendor: str, product: str) -> dict[str, Any]:
        query = f"{vendor}/{product}"
        url = f"{self.base_url}/api/search/{vendor}/{product}"
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(url)
                response.raise_for_status()
                data = response.json()
        except Exception as exc:  # noqa: BLE001
            return {
                "source": "cve-search",
                "query": query,
                "results": [],
                "error": str(exc),
            }

        results = data.get("data", [])
        results.sort(key=lambda row: float(row.get("cvss", 0) or 0), reverse=True)
        try:
            with SessionLocal() as db:
                results = VulnIntelService(db).enrich_results(results)
        except Exception:  # noqa: BLE001
            # Enrichment must not break the mandatory first-pass CVE lookup path.
            pass
        return {"source": "cve-search", "query": query, "results": results[:20]}
