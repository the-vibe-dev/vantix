from __future__ import annotations

import argparse
from typing import Any

from secops.config import settings
from secops.db import SessionLocal
from secops.services.cve_search import CVESearchService
from secops.services.intel_sources import adapter_for, available_sources
from secops.services.vuln_intel import VulnIntelService, normalize_cve_id


def create_cve_mcp():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised only without optional dep
        raise RuntimeError("Install the MCP extra first: pip install -e '.[dev]' or pip install 'mcp[cli]>=1,<2'") from exc

    mcp = FastMCP(
        "CTF CVE Intel",
        stateless_http=settings.cve_mcp_stateless,
        json_response=settings.cve_mcp_json_response,
    )

    @mcp.tool()
    def search_cves(
        vendor: str,
        product: str,
        limit: int = 20,
        live_on_miss: bool = True,
        sources: list[str] | None = None,
        live_limit: int = 200,
        always_search_external: bool = False,
    ) -> dict[str, Any]:
        """Search cve-search and local intel, optionally triggering live source refresh."""
        response = CVESearchService().search(
            vendor=vendor,
            product=product,
            limit=max(1, min(limit, 100)),
            live_on_miss=live_on_miss,
            live_sources=sources,
            live_limit=max(1, min(live_limit, 1000)),
            always_search_external=always_search_external,
        )
        response["results"] = response.get("results", [])[: max(1, min(limit, 100))]
        return response

    @mcp.tool()
    def search_intel(query: str, limit: int = 25, sources: list[str] | None = None, live_on_miss: bool = True) -> dict[str, Any]:
        """Search local vulnerability intel; when no cache hit, live fetch is enabled by default."""
        with SessionLocal() as db:
            service = VulnIntelService(db)
            intel = service.search(query, limit=max(1, min(limit, 100)), sources=sources)
            live = {"attempted": False, "upserted": 0, "errors": []}
            if not intel and live_on_miss:
                live["attempted"] = True
                for source_name in sources or available_sources(include_optional=False):
                    try:
                        adapter = adapter_for(source_name)
                        result = adapter.fetch_since({"limit": 200})
                        if result.error:
                            live["errors"].append(f"{source_name}: {result.error}")
                            continue
                        filtered = service.filter_records_by_term(result.records, query)
                        counts = service.upsert_records(filtered, commit=False)
                        live["upserted"] += int(counts.get("upserted", 0) or 0)
                    except Exception as exc:  # noqa: BLE001
                        live["errors"].append(f"{source_name}: {exc}")
                db.commit()
                intel = service.search(query, limit=max(1, min(limit, 100)), sources=sources)
            return {"query": query, "limit": limit, "sources": sources or [], "intel": intel, "live": live}

    @mcp.tool()
    def get_cve_intel(cve_id: str) -> dict[str, Any]:
        """Return local intel records for a CVE ID."""
        with SessionLocal() as db:
            normalized = normalize_cve_id(cve_id)
            return {"cve_id": normalized, "intel": VulnIntelService(db).for_cve(normalized)}

    @mcp.tool()
    def recent_intel(days: int = 7, limit: int = 25) -> dict[str, Any]:
        """Return recent prioritized vulnerability intel from the local cache."""
        with SessionLocal() as db:
            return {"days": days, "limit": limit, "intel": VulnIntelService(db).recent(days=max(1, min(days, 120)), limit=max(1, min(limit, 100)))}

    @mcp.tool()
    def list_intel_sources(include_optional: bool = True) -> dict[str, Any]:
        """List configured vulnerability intel source adapters."""
        return {"sources": available_sources(include_optional=include_optional)}

    @mcp.tool()
    def update_intel_source(source: str = "cisa_kev", dry_run: bool = True) -> dict[str, Any]:
        """Fetch one intel source. Defaults to dry-run to avoid surprise writes."""
        adapter = adapter_for(source)
        result = adapter.fetch_since({})
        payload: dict[str, Any] = {"source": result.source, "fetched": len(result.records), "cursor": result.cursor, "error": result.error, "dry_run": dry_run}
        if dry_run or result.error:
            return payload
        with SessionLocal() as db:
            payload["db"] = VulnIntelService(db).upsert_records(result.records)
        return payload

    @mcp.resource("cve://{cve_id}")
    def cve_resource(cve_id: str) -> dict[str, Any]:
        with SessionLocal() as db:
            normalized = normalize_cve_id(cve_id)
            return {"cve_id": normalized, "intel": VulnIntelService(db).for_cve(normalized)}

    @mcp.resource("cve-intel://recent/{days}")
    def recent_resource(days: str) -> dict[str, Any]:
        with SessionLocal() as db:
            return {"days": int(days), "intel": VulnIntelService(db).recent(days=int(days), limit=25)}

    @mcp.resource("cve-intel://sources")
    def sources_resource() -> dict[str, Any]:
        return {"sources": available_sources(include_optional=True)}

    @mcp.prompt()
    def prioritize_service_cves(service: str, version: str = "", target_context: str = "") -> str:
        return (
            "Prioritize locally known CVEs for this authorized target context. "
            "Rank by KEV, exploit availability, scanner template availability, EPSS, CVSS, and fit to observed service.\n"
            f"Service: {service}\nVersion: {version}\nContext: {target_context}\n"
        )

    @mcp.prompt()
    def cve_validation_plan(cve_id: str, target_context: str = "") -> str:
        return (
            "Create a low-noise validation plan for the CVE in an authorized lab or assessment. "
            "Do not provide destructive steps; focus on evidence, safe checks, expected signals, and rollback.\n"
            f"CVE: {normalize_cve_id(cve_id)}\nContext: {target_context}\n"
        )

    return mcp


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the CVE MCP server")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8788)
    args = parser.parse_args()
    mcp = create_cve_mcp()
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="streamable-http")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
