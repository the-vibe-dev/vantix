from __future__ import annotations

from secops.config import settings
from secops.services.intel_sources.base import SourceUpdateResult, http_client, safe_float
from secops.services.vuln_intel import IntelRecord, extract_cve_ids, parse_datetime


class GithubAdvisoriesAdapter:
    name = "github_advisories"
    source_type = "api"
    url = "https://api.github.com/advisories"

    def fetch_since(self, cursor: dict | None = None) -> SourceUpdateResult:
        headers = {"Accept": "application/vnd.github+json"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
        params = {"per_page": cursor.get("per_page", 100) if cursor else 100, "sort": "published", "direction": "desc"}
        try:
            with http_client(headers=headers) as client:
                data = client.get(self.url, params=params).raise_for_status().json()
        except Exception as exc:  # noqa: BLE001
            return SourceUpdateResult(source=self.name, records=[], error=str(exc))
        records = []
        for row in data:
            aliases = [identifier.get("value", "") for identifier in row.get("identifiers", []) if isinstance(identifier, dict)]
            cves = extract_cve_ids(aliases, row.get("summary", ""), row.get("description", ""))
            cvss = safe_float((row.get("cvss") or {}).get("score"))
            records.append(
                IntelRecord(
                    source=self.name,
                    external_id=row.get("ghsa_id") or row.get("cve_id") or ":".join(aliases),
                    title=row.get("summary", ""),
                    summary=row.get("description", ""),
                    url=row.get("html_url", ""),
                    cve_ids=cves,
                    aliases=[alias for alias in aliases if alias],
                    published_at=parse_datetime(row.get("published_at")),
                    modified_at=parse_datetime(row.get("updated_at")),
                    severity=row.get("severity", ""),
                    cvss=cvss,
                    confidence=0.85,
                    metadata=row,
                )
            )
        return SourceUpdateResult(source=self.name, records=records, cursor={"count": len(records)})
