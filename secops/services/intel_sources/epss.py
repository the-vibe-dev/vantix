from __future__ import annotations

from secops.services.intel_sources.base import SourceUpdateResult, http_client, safe_float
from secops.services.vuln_intel import IntelRecord, parse_datetime


class EpssAdapter:
    name = "first_epss"
    source_type = "api"
    url = "https://api.first.org/data/v1/epss"

    def fetch_since(self, cursor: dict | None = None) -> SourceUpdateResult:
        params = {"date": cursor.get("date")} if cursor and cursor.get("date") else {}
        try:
            with http_client() as client:
                data = client.get(self.url, params=params).raise_for_status().json()
        except Exception as exc:  # noqa: BLE001
            return SourceUpdateResult(source=self.name, records=[], error=str(exc))
        records = []
        for row in data.get("data", []):
            cve_id = row.get("cve", "")
            records.append(
                IntelRecord(
                    source=self.name,
                    external_id=cve_id,
                    title=f"EPSS score for {cve_id}",
                    url="https://www.first.org/epss/",
                    cve_ids=[cve_id] if cve_id else [],
                    aliases=[cve_id] if cve_id else [],
                    published_at=parse_datetime(row.get("date")),
                    modified_at=parse_datetime(row.get("date")),
                    epss=safe_float(row.get("epss")),
                    epss_percentile=safe_float(row.get("percentile")),
                    confidence=0.9,
                    metadata=row,
                )
            )
        status = data.get("status")
        if isinstance(status, dict):
            status_date = str(status.get("date", ""))
        elif isinstance(status, str):
            status_date = status
        else:
            status_date = ""
        return SourceUpdateResult(
            source=self.name,
            records=records,
            cursor={"count": len(records), "date": status_date},
        )
