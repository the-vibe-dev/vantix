from __future__ import annotations

from typing import Any

import yaml

from secops.services.intel_sources.base import SourceUpdateResult, http_client, safe_float
from secops.services.vuln_intel import IntelRecord, extract_cve_ids, parse_datetime


class GitlabAdvisoriesAdapter:
    name = "gitlab_advisories"
    source_type = "gitlab-api"
    url = "https://gitlab.com/api/v4/projects/gitlab-org%2Fadvisories-community/repository/tree"
    raw_url = "https://gitlab.com/gitlab-org/advisories-community/-/raw/main/{path}"

    def fetch_since(self, cursor: dict | None = None) -> SourceUpdateResult:
        limit = int((cursor or {}).get("limit", 100))
        params = {"recursive": "true", "per_page": min(limit, 100)}
        try:
            with http_client() as client:
                tree = client.get(self.url, params=params).raise_for_status().json()
                paths = [row["path"] for row in tree if row.get("type") == "blob" and row.get("path", "").endswith((".yml", ".yaml"))]
                records = []
                for path in paths[:limit]:
                    text = client.get(self.raw_url.format(path=path)).raise_for_status().text
                    row = yaml.safe_load(text) or {}
                    records.append(self._record(path, row))
        except Exception as exc:  # noqa: BLE001
            return SourceUpdateResult(source=self.name, records=[], error=str(exc))
        return SourceUpdateResult(source=self.name, records=records, cursor={"count": len(records), "limit": limit})

    def _record(self, path: str, row: dict[str, Any]) -> IntelRecord:
        identifiers = row.get("identifiers") or []
        aliases = [str(item.get("value", "")) for item in identifiers if isinstance(item, dict)]
        cves = extract_cve_ids(aliases, row.get("title", ""), row.get("description", ""), path)
        cvss = 0.0
        cvss_v3 = row.get("cvss_v3") or row.get("cvss") or ""
        if isinstance(cvss_v3, dict):
            cvss = safe_float(cvss_v3.get("score"))
        return IntelRecord(
            source=self.name,
            external_id=row.get("identifier") or path,
            title=row.get("title", ""),
            summary=row.get("description", ""),
            url=self.raw_url.format(path=path),
            cve_ids=cves,
            aliases=aliases + cves,
            published_at=parse_datetime(row.get("date")),
            modified_at=parse_datetime(row.get("date")),
            severity=row.get("severity", ""),
            cvss=cvss,
            confidence=0.65,
            metadata={**row, "path": path, "metadata_only": True},
        )
