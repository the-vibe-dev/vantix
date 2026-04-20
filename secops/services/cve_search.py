from __future__ import annotations

from datetime import datetime, timezone
import re
import time
from typing import Any

import httpx
from sqlalchemy.exc import OperationalError

from secops.config import settings
from secops.db import SessionLocal
from secops.services.intel_sources import adapter_for, available_sources
from secops.services.vuln_intel import IntelRecord, VulnIntelService, parse_datetime


SERVICE_QUERY_ALIASES: dict[str, dict[str, list[Any]]] = {
    "jetdirect": {
        "queries": [("hp", "jetdirect"), ("hewlett-packard", "jetdirect"), ("jetdirect", "jetdirect")],
        "terms": ["jetdirect", "hp", "hewlett packard", "printer"],
    },
    "nessus": {
        "queries": [("tenable", "nessus"), ("nessus", "nessus")],
        "terms": ["nessus", "tenable"],
    },
    "rpcbind": {
        "queries": [("sun", "rpcbind"), ("rpcbind", "rpcbind"), ("portmap", "rpcbind"), ("sunrpc", "rpcbind")],
        "terms": ["rpcbind", "portmap", "sunrpc"],
    },
    "ssh": {
        "queries": [("openbsd", "openssh"), ("openssh", "openssh"), ("ssh", "ssh")],
        "terms": ["openssh", "ssh"],
    },
}


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
        query_candidates = self._query_candidates(vendor, product)
        primary_query = f"{query_candidates[0][0]}/{query_candidates[0][1]}"
        local_errors: list[str] = []
        local_results: list[dict[str, Any]] = []
        with httpx.Client(timeout=10.0) as client:
            for local_vendor, local_product in query_candidates:
                url = f"{self.base_url}/api/search/{local_vendor}/{local_product}"
                try:
                    response = client.get(url)
                    response.raise_for_status()
                    data = response.json()
                    local_results.extend(self._extract_local_results(data))
                except Exception as exc:  # noqa: BLE001
                    local_errors.append(f"{local_vendor}/{local_product}: {exc}")

        deduped_local: dict[str, dict[str, Any]] = {}
        for row in local_results:
            key = str(row.get("id") or "").upper() or str(row.get("cve") or "").upper()
            if not key:
                key = f"row-{len(deduped_local)}"
            current = deduped_local.get(key)
            if current is None or float(row.get("cvss", 0) or 0) > float(current.get("cvss", 0) or 0):
                deduped_local[key] = row
        local_results = list(deduped_local.values())

        local_results.sort(key=lambda row: float(row.get("cvss", 0) or 0), reverse=True)
        live_meta = {
            "attempted": False,
            "enabled": bool(live_on_miss or always_search_external),
            "sources": live_sources or [],
            "fetched_records": 0,
            "upserted": 0,
            "warnings": [],
            "errors": [],
        }

        max_attempts = 4
        enriched_results: list[dict[str, Any]] = []
        for attempt in range(1, max_attempts + 1):
            try:
                with SessionLocal() as db:
                    intel = VulnIntelService(db)
                    should_search_live = always_search_external or (live_on_miss and not local_results)
                    if should_search_live:
                        selected_sources = live_sources or available_sources(include_optional=False)
                        live_meta["attempted"] = True
                        live_meta["sources"] = selected_sources
                        any_changes = False
                        source_successes = 0
                        terms = self._search_terms(vendor, product)
                        for source_name in selected_sources:
                            try:
                                adapter = adapter_for(source_name)
                            except Exception as exc:  # noqa: BLE001
                                live_meta["warnings"].append(f"{source_name}: {exc}")
                                continue
                            try:
                                result = adapter.fetch_since({"limit": live_limit})
                            except Exception as exc:  # noqa: BLE001
                                live_meta["warnings"].append(f"{source_name}: {exc}")
                                continue
                            if result.error:
                                live_meta["warnings"].append(f"{source_name}: {result.error}")
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
                            source_successes += 1
                            any_changes = True
                        # Generic fallback for sparse service names (e.g., rpcbind) using NVD keyword search.
                        if live_meta["upserted"] == 0:
                            nvd_records = self._fetch_nvd_keyword_records(terms=terms, limit=min(max(live_limit, 20), 200))
                            if nvd_records:
                                counts = intel.upsert_records(nvd_records, commit=False)
                                live_meta["fetched_records"] += len(nvd_records)
                                live_meta["upserted"] += int(counts.get("upserted", 0) or 0)
                                source_successes += 1
                                any_changes = True
                        if any_changes:
                            db.commit()
                        # Only surface fatal errors when nothing useful was obtained.
                        if source_successes > 0 and live_meta["upserted"] > 0:
                            live_meta["errors"] = []
                        elif live_meta["warnings"]:
                            live_meta["errors"] = list(dict.fromkeys(live_meta["warnings"]))[:10]

                    enriched_results = intel.enrich_results(local_results)
                    if not enriched_results:
                        enriched_results = self._rows_from_intel(intel, terms=self._search_terms(vendor, product), limit=limit)
                    break
            except OperationalError as exc:
                message = str(exc).lower()
                if "database is locked" not in message and "database table is locked" not in message:
                    raise
                if attempt >= max_attempts:
                    live_meta["errors"].append(f"sqlite-lock: {exc}")
                    break
                time.sleep(0.2 * attempt)

        payload: dict[str, Any] = {
            "source": "cve-search",
            "query": primary_query,
            "queries": [f"{item[0]}/{item[1]}" for item in query_candidates],
            "results": enriched_results[: max(1, min(limit, 100))],
            "live": live_meta,
        }
        if local_errors:
            payload["errors"] = local_errors
            if not local_results:
                payload["error"] = local_errors[0]
        return payload

    def _fetch_nvd_keyword_records(self, *, terms: list[str], limit: int = 100) -> list[Any]:
        unique_terms = [term.strip() for term in terms if str(term).strip()]
        if not unique_terms:
            return []
        strong_terms = [item.lower() for item in unique_terms if len(item.strip()) >= 5]
        headers = {}
        if settings.nvd_nist_api_key:
            headers["apiKey"] = settings.nvd_nist_api_key
        collected: dict[str, Any] = {}
        with httpx.Client(timeout=20.0, headers=headers) as client:
            for term in unique_terms[:6]:
                try:
                    response = client.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"keywordSearch": term, "resultsPerPage": min(limit, 100)},
                    )
                    response.raise_for_status()
                    payload = response.json()
                except Exception:
                    continue
                vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
                if not isinstance(vulnerabilities, list):
                    continue
                for row in vulnerabilities:
                    cve = (row or {}).get("cve", {})
                    cve_id = str(cve.get("id") or "").strip().upper()
                    if not cve_id:
                        continue
                    descriptions = cve.get("descriptions") or []
                    summary = ""
                    if isinstance(descriptions, list):
                        for entry in descriptions:
                            if not isinstance(entry, dict):
                                continue
                            if str(entry.get("lang") or "").lower() == "en":
                                summary = str(entry.get("value") or "")
                                break
                        if not summary and descriptions:
                            summary = str((descriptions[0] or {}).get("value") or "")
                    metrics = cve.get("metrics") or {}
                    cvss = 0.0
                    if isinstance(metrics, dict):
                        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            entries = metrics.get(metric_key)
                            if isinstance(entries, list) and entries:
                                cvss_data = (entries[0] or {}).get("cvssData") or {}
                                try:
                                    cvss = float(cvss_data.get("baseScore") or 0.0)
                                except (TypeError, ValueError):
                                    cvss = 0.0
                                if cvss > 0:
                                    break
                    published = parse_datetime(cve.get("published"))
                    modified = parse_datetime(cve.get("lastModified"))
                    haystack = " ".join([cve_id, summary]).lower()
                    if strong_terms and not self._matches_any_term(haystack, strong_terms):
                        continue
                    collected[cve_id] = IntelRecord(
                        source="nvd_keyword",
                        external_id=cve_id,
                        title=cve_id,
                        summary=summary,
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        cve_ids=[cve_id],
                        aliases=[cve_id],
                        published_at=published,
                        modified_at=modified,
                        cvss=cvss,
                        confidence=0.78,
                        metadata={"provider": "nvd", "keyword": term},
                    )
                    if len(collected) >= limit:
                        break
                if len(collected) >= limit:
                    break
        return list(collected.values())

    def _matches_any_term(self, haystack: str, terms: list[str]) -> bool:
        for term in terms:
            token = str(term or "").strip().lower()
            if not token:
                continue
            if " " in token:
                if token in haystack:
                    return True
                continue
            pattern = rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])"
            if re.search(pattern, haystack):
                return True
        return False

    def _extract_local_results(self, payload: Any) -> list[dict[str, Any]]:
        # cve-search deployments in the wild return either {"data":[...]} or {"results":[...]}.
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            return []
        for key in ("data", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return []

    def _query_candidates(self, vendor: str, product: str) -> list[tuple[str, str]]:
        norm_vendor = vendor.strip().lower()
        norm_product = product.strip().lower()
        candidates: list[tuple[str, str]] = []
        alias_key = norm_product if norm_vendor == norm_product else ""
        alias = SERVICE_QUERY_ALIASES.get(alias_key)
        if alias:
            for item in alias.get("queries", []):
                if isinstance(item, tuple) and len(item) == 2:
                    cand_vendor = str(item[0]).strip()
                    cand_product = str(item[1]).strip()
                    if cand_vendor and cand_product:
                        candidates.append((cand_vendor, cand_product))
        if vendor.strip() and product.strip():
            candidates.append((vendor.strip(), product.strip()))
        deduped: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for cand in candidates:
            norm = (cand[0].lower(), cand[1].lower())
            if norm in seen:
                continue
            seen.add(norm)
            deduped.append(cand)
        return deduped or [(vendor.strip() or "unknown", product.strip() or "unknown")]

    def _search_terms(self, vendor: str, product: str) -> list[str]:
        terms = {vendor.strip(), product.strip()}
        norm_vendor = vendor.strip().lower()
        norm_product = product.strip().lower()
        alias_key = norm_product if norm_vendor == norm_product else ""
        alias = SERVICE_QUERY_ALIASES.get(alias_key, {})
        for term in alias.get("terms", []):
            terms.add(str(term).strip())
        return [term for term in sorted(terms) if term]

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
