from __future__ import annotations

from secops.config import settings
from secops.services.intel_sources.base import SourceUpdateResult, http_client
from secops.services.vuln_intel import IntelRecord, extract_cve_ids, parse_datetime


class VulnCheckAdapter:
    name = "vulncheck"
    source_type = "api"
    url = "https://api.vulncheck.com/v3/index/vulncheck-kev"

    def fetch_since(self, cursor: dict | None = None) -> SourceUpdateResult:
        if not settings.vulncheck_api_token:
            return SourceUpdateResult(source=self.name, records=[], cursor={"disabled": True, "reason": "VULNCHECK_API_TOKEN not set"})
        headers = {"Authorization": f"Bearer {settings.vulncheck_api_token}"}
        params = {"limit": int((cursor or {}).get("limit", 100))}
        try:
            with http_client(headers=headers) as client:
                data = client.get(self.url, params=params).raise_for_status().json()
        except Exception as exc:  # noqa: BLE001
            return SourceUpdateResult(source=self.name, records=[], error=str(exc))
        rows = data.get("data", data if isinstance(data, list) else [])
        records = []
        for row in rows:
            cves = extract_cve_ids(row.get("cve", ""), row.get("id", ""), row.get("title", ""), row.get("description", ""))
            records.append(
                IntelRecord(
                    source=self.name,
                    external_id=row.get("id") or (cves[0] if cves else ""),
                    title=row.get("title", ""),
                    summary=row.get("description", ""),
                    url=row.get("url", ""),
                    cve_ids=cves,
                    aliases=cves,
                    published_at=parse_datetime(row.get("date_added") or row.get("published")),
                    modified_at=parse_datetime(row.get("last_modified") or row.get("modified")),
                    kev=True,
                    exploit_available=bool(row.get("exploits") or row.get("exploit")),
                    confidence=0.85,
                    metadata=row,
                )
            )
        return SourceUpdateResult(source=self.name, records=records, cursor={"count": len(records)})
