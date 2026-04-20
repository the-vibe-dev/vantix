from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from secops.config import settings
from secops.db import SessionLocal
from secops.services.intel_sources import adapter_for, available_sources
from secops.services.vuln_intel import VulnIntelService


class CVESearchService:
    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or settings.cve_search_url).rstrip("/")

    def search(
        self,
        vendor: str,
        product: str,
        *,
        limit: int = 20,
        live_on_miss: bool = True,
        live_sources: list[str] | None = None,
        live_limit: int = 200,
        always_search_external: bool = False,
    ) -> dict[str, Any]:
        query = f"{vendor}/{product}"
        url = f"{self.base_url}/api/search/{vendor}/{product}"
        local_error = ""
        local_results: list[dict[str, Any]] = []
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(url)
                response.raise_for_status()
                data = response.json()
                local_results = list(data.get("data", []))
        except Exception as exc:  # noqa: BLE001
            local_error = str(exc)

        local_results.sort(key=lambda row: float(row.get("cvss", 0) or 0), reverse=True)
        live_meta = {
            "attempted": False,
            "enabled": bool(live_on_miss or always_search_external),
            "sources": live_sources or [],
            "fetched_records": 0,
            "upserted": 0,
            "errors": [],
        }

        with SessionLocal() as db:
            intel = VulnIntelService(db)
            should_search_live = always_search_external or (live_on_miss and not local_results)
            if should_search_live:
                selected_sources = live_sources or available_sources(include_optional=False)
                live_meta["attempted"] = True
                live_meta["sources"] = selected_sources
                any_changes = False
                terms = list({term for term in [vendor.strip(), product.strip()] if term})
                for source_name in selected_sources:
                    try:
                        adapter = adapter_for(source_name)
                    except Exception as exc:  # noqa: BLE001
                        live_meta["errors"].append(f"{source_name}: {exc}")
                        continue
                    try:
                        result = adapter.fetch_since({"limit": live_limit})
                    except Exception as exc:  # noqa: BLE001
                        live_meta["errors"].append(f"{source_name}: {exc}")
                        continue
                    if result.error:
                        live_meta["errors"].append(f"{source_name}: {result.error}")
                        continue
                    filtered = []
                    for term in terms:
                        filtered.extend(intel.filter_records_by_term(result.records, term))
                    deduped: dict[tuple[str, str], Any] = {}
                    for row in filtered:
                        deduped[(row.source, row.external_id)] = row
                    filtered = list(deduped.values())
                    if not filtered:
                        continue
                    counts = intel.upsert_records(filtered, commit=False)
                    live_meta["fetched_records"] += len(filtered)
                    live_meta["upserted"] += int(counts.get("upserted", 0) or 0)
                    any_changes = True
                if any_changes:
                    db.commit()

            enriched_results = intel.enrich_results(local_results)
            if not enriched_results:
                enriched_results = self._rows_from_intel(intel, terms=[vendor, product], limit=limit)

        payload: dict[str, Any] = {"source": "cve-search", "query": query, "results": enriched_results[: max(1, min(limit, 100))], "live": live_meta}
        if local_error:
            payload["error"] = local_error
        return payload

    def _rows_from_intel(self, intel: VulnIntelService, *, terms: list[str], limit: int) -> list[dict[str, Any]]:
        combined: dict[str, dict[str, Any]] = {}
        for term in terms:
            term = term.strip()
            if not term:
                continue
            for item in intel.search(term, limit=max(limit * 2, 40)):
                cves = item.get("cve_ids") or []
                cve_id = str(cves[0]).upper() if cves else ""
                if not cve_id:
                    continue
                current = combined.get(cve_id)
                candidate = {
                    "id": cve_id,
                    "summary": item.get("summary") or item.get("title") or "",
                    "cvss": float(item.get("cvss", 0) or 0),
                    "Modified": item.get("modified_at"),
                    "Published": item.get("published_at"),
                    "intel": [item],
                    "priority_score": float(item.get("priority_score", 0) or 0),
                    "source": "vuln-intel",
                }
                if current is None or float(candidate["priority_score"]) > float(current.get("priority_score", 0) or 0):
                    combined[cve_id] = candidate
        rows = list(combined.values())
        rows.sort(key=lambda row: float(row.get("priority_score", 0) or 0), reverse=True)
        now = datetime.now(timezone.utc).isoformat()
        for row in rows:
            row["Modified"] = row.get("Modified") or now
            row["Published"] = row.get("Published") or now
        return rows[: max(1, min(limit, 100))]
