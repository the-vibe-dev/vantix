from __future__ import annotations

from secops.services.intel_sources.base import SourceUpdateResult, http_client
from secops.services.vuln_intel import IntelRecord, extract_cve_ids


class NucleiTemplatesAdapter:
    name = "nuclei_templates"
    source_type = "github-raw"
    url = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"

    def fetch_since(self, cursor: dict | None = None) -> SourceUpdateResult:
        try:
            with http_client() as client:
                data = client.get(self.url).raise_for_status().json()
        except Exception as exc:  # noqa: BLE001
            return SourceUpdateResult(source=self.name, records=[], error=str(exc))
        records = []
        iterable = data.items() if isinstance(data, dict) else enumerate(data if isinstance(data, list) else [])
        for key, value in iterable:
            text = f"{key} {value}"
            cves = extract_cve_ids(text)
            if not cves:
                continue
            records.append(
                IntelRecord(
                    source=self.name,
                    external_id=str(key),
                    title=f"Nuclei template coverage for {', '.join(cves)}",
                    url="https://github.com/projectdiscovery/nuclei-templates",
                    cve_ids=cves,
                    aliases=cves,
                    scanner_template_available=True,
                    confidence=0.7,
                    metadata={"template": value, "content_not_executed": True},
                )
            )
        return SourceUpdateResult(source=self.name, records=records, cursor={"count": len(records)})
