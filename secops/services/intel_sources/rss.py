from __future__ import annotations

import xml.etree.ElementTree as ET

from secops.services.intel_sources.base import SourceUpdateResult, http_client
from secops.services.vuln_intel import IntelRecord, extract_cve_ids, parse_datetime


class RssAdapter:
    name = "rss"
    source_type = "rss"
    url = ""
    confidence = 0.45

    def fetch_since(self, cursor: dict | None = None) -> SourceUpdateResult:
        try:
            with http_client() as client:
                text = client.get(self.url).raise_for_status().text
            root = ET.fromstring(text)
        except Exception as exc:  # noqa: BLE001
            return SourceUpdateResult(source=self.name, records=[], error=str(exc))
        items = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")
        records = []
        for item in items[: int((cursor or {}).get("limit", 100))]:
            title = self._text(item, "title")
            link = self._text(item, "link")
            summary = self._text(item, "description") or self._text(item, "summary")
            published = self._text(item, "pubDate") or self._text(item, "published") or self._text(item, "updated")
            cves = extract_cve_ids(title, summary, link)
            records.append(
                IntelRecord(
                    source=self.name,
                    external_id=link or title,
                    title=title,
                    summary=summary,
                    url=link,
                    cve_ids=cves,
                    aliases=cves,
                    published_at=parse_datetime(published),
                    modified_at=parse_datetime(published),
                    confidence=self.confidence,
                    metadata={"metadata_only": True},
                )
            )
        return SourceUpdateResult(source=self.name, records=records, cursor={"count": len(records)})

    def _text(self, item: ET.Element, tag: str) -> str:
        found = item.find(tag)
        if found is None:
            found = item.find(f"{{http://www.w3.org/2005/Atom}}{tag}")
        if found is None:
            return ""
        if tag == "link" and found.attrib.get("href"):
            return found.attrib["href"]
        return (found.text or "").strip()


class OpenwallOssSecurityAdapter(RssAdapter):
    name = "openwall_oss_security"
    url = "https://www.openwall.com/lists/oss-security/rss"


class SeclistsFullDisclosureAdapter(RssAdapter):
    name = "seclists_fulldisclosure"
    url = "https://seclists.org/rss/fulldisclosure.rss"
