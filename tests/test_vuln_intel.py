import os
import tempfile
from pathlib import Path

TEST_DB_PATH = Path(os.getenv("SECOPS_TEST_DB", str(Path(tempfile.gettempdir()) / f"secops_test_{os.getpid()}.db")))
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
os.environ["SECOPS_DATABASE_URL"] = f"sqlite+pysqlite:///{TEST_DB_PATH}"

from secops.routers.cve import get_cve_intel, list_intel_sources, search_cve_intel
from secops.db import Base, SessionLocal, engine
from secops.models import VulnerabilityIntelReference
from secops.services.cve_search import CVESearchService
from secops.services.vuln_intel import IntelRecord, VulnIntelService, extract_cve_ids
from secops.services.intel_sources.base import SourceUpdateResult


def reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_extract_cve_ids_normalizes_and_dedupes() -> None:
    assert extract_cve_ids("foo cve-2024-12345", ["CVE-2024-12345", "CVE-2025-99999"]) == ["CVE-2024-12345", "CVE-2025-99999"]


def test_vuln_intel_upsert_and_lookup_by_cve() -> None:
    reset_db()
    with SessionLocal() as db:
        service = VulnIntelService(db)
        counts = service.upsert_records(
            [
                IntelRecord(
                    source="cisa_kev",
                    external_id="CVE-2024-12345",
                    title="Known exploited test vector",
                    cve_ids=["cve-2024-12345"],
                    kev=True,
                    confidence=0.95,
                )
            ]
        )
        assert counts["upserted"] == 1
        intel = service.for_cve("CVE-2024-12345")
        assert intel[0]["source"] == "cisa_kev"
        assert intel[0]["kev"] is True
        assert intel[0]["priority_score"] > 50


def test_cve_result_enrichment_uses_sidecar_priority() -> None:
    reset_db()
    with SessionLocal() as db:
        service = VulnIntelService(db)
        service.upsert_records(
            [
                IntelRecord(
                    source="nuclei_templates",
                    external_id="http-cves-2024-12345",
                    title="Template coverage",
                    cve_ids=["CVE-2024-12345"],
                    scanner_template_available=True,
                    confidence=0.7,
                )
            ]
        )
        results = service.enrich_results([{"id": "CVE-2024-12345", "cvss": 5.0}, {"id": "CVE-2024-0001", "cvss": 9.8}])
        assert results[0]["id"] == "CVE-2024-12345"
        assert results[0]["intel"][0]["scanner_template_available"] is True


def test_cve_intel_api_returns_seeded_records() -> None:
    reset_db()
    with SessionLocal() as db:
        VulnIntelService(db).upsert_records(
            [
                IntelRecord(
                    source="exploitdb",
                    external_id="999999",
                    title="PoC metadata",
                    cve_ids=["CVE-2024-54321"],
                    exploit_available=True,
                    confidence=0.75,
                )
            ]
        )
    with SessionLocal() as db:
        payload = get_cve_intel(cve_id="CVE-2024-54321", db=db)
    assert payload["cve_id"] == "CVE-2024-54321"
    assert payload["intel"][0]["source"] == "exploitdb"
    assert payload["intel"][0]["exploit_available"] is True


def test_upsert_duplicate_external_id_in_batch_does_not_duplicate_references() -> None:
    reset_db()
    with SessionLocal() as db:
        service = VulnIntelService(db)
        counts = service.upsert_records(
            [
                IntelRecord(
                    source="exploitdb",
                    external_id="46615",
                    title="PoC A",
                    url="https://www.exploit-db.com/exploits/46615",
                    cve_ids=["CVE-2019-8385"],
                    aliases=["CVE-2019-8385"],
                    exploit_available=True,
                ),
                IntelRecord(
                    source="exploitdb",
                    external_id="46615",
                    title="PoC A duplicate row",
                    url="https://www.exploit-db.com/exploits/46615",
                    cve_ids=["CVE-2019-8385"],
                    aliases=["CVE-2019-8385"],
                    exploit_available=True,
                ),
            ]
        )
        assert counts["upserted"] == 2
        refs = db.query(VulnerabilityIntelReference).all()
        assert len(refs) == 2
        assert sorted((ref.reference_type, ref.reference_value) for ref in refs) == [
            ("cve", "CVE-2019-8385"),
            ("url", "https://www.exploit-db.com/exploits/46615"),
        ]


def test_cve_intel_search_endpoint_searches_cached_sources() -> None:
    reset_db()
    with SessionLocal() as db:
        VulnIntelService(db).upsert_records(
            [
                IntelRecord(
                    source="github_advisories",
                    external_id="GHSA-test",
                    title="Apache Struts cached advisory",
                    summary="CVE-2024-77777 affects Apache Struts in a test fixture.",
                    cve_ids=["CVE-2024-77777"],
                    aliases=["GHSA-test"],
                    cvss=9.8,
                    confidence=0.85,
                )
            ]
        )
    with SessionLocal() as db:
        payload = search_cve_intel(q="struts", limit=10, source=None, db=db)
    assert payload["query"] == "struts"
    assert payload["intel"][0]["source"] == "github_advisories"
    assert payload["intel"][0]["cve_ids"] == ["CVE-2024-77777"]


def test_cve_intel_sources_endpoint_lists_defaults() -> None:
    reset_db()
    assert "cisa_kev" in list_intel_sources(include_optional=False)["sources"]


def test_cve_intel_search_live_on_miss_persists_cache() -> None:
    reset_db()

    class FakeAdapter:
        def fetch_since(self, cursor=None):  # noqa: ANN001
            return SourceUpdateResult(
                source="fake_feed",
                records=[
                    IntelRecord(
                        source="fake_feed",
                        external_id="FAKE-1",
                        title="Tomcat deserialization issue",
                        summary="CVE-2026-11111 remote issue in Apache Tomcat",
                        cve_ids=["CVE-2026-11111"],
                        confidence=0.8,
                    )
                ],
                cursor={"count": 1},
            )

    import secops.routers.cve as cve_router

    original_adapter_for = cve_router.adapter_for
    original_available_sources = cve_router.available_sources
    cve_router.adapter_for = lambda name: FakeAdapter()  # type: ignore[assignment]
    cve_router.available_sources = lambda include_optional=False: ["fake_feed"]  # type: ignore[assignment]
    try:
        with SessionLocal() as db:
            first = search_cve_intel(q="tomcat", limit=20, source=None, live_on_miss=True, live_limit=10, db=db)
        assert first["live"]["attempted"] is True
        assert first["live"]["fetched_records"] == 1
        assert first["intel"]
        assert first["intel"][0]["source"] == "fake_feed"

        with SessionLocal() as db:
            second = search_cve_intel(q="tomcat", limit=20, source=None, live_on_miss=False, live_limit=10, db=db)
        assert second["live"]["attempted"] is False
        assert second["intel"]
        assert second["intel"][0]["source"] == "fake_feed"
    finally:
        cve_router.adapter_for = original_adapter_for  # type: ignore[assignment]
        cve_router.available_sources = original_available_sources  # type: ignore[assignment]


def test_cve_search_service_live_fallback_uses_external_intel() -> None:
    reset_db()

    class FakeResponse:
        def raise_for_status(self):  # noqa: ANN201
            return self

        def json(self):  # noqa: ANN201
            return {"data": []}

    class FakeClient:
        def __enter__(self):  # noqa: ANN201
            return self

        def __exit__(self, exc_type, exc, tb):  # noqa: ANN001, ANN201
            return False

        def get(self, url):  # noqa: ANN001, ANN201
            return FakeResponse()

    class FakeAdapter:
        def fetch_since(self, cursor=None):  # noqa: ANN001
            return SourceUpdateResult(
                source="fake_feed",
                records=[
                    IntelRecord(
                        source="fake_feed",
                        external_id="FAKE-2",
                        title="Apache Struts RCE",
                        summary="CVE-2025-99999 exploit available",
                        cve_ids=["CVE-2025-99999"],
                        exploit_available=True,
                        cvss=9.8,
                        confidence=0.9,
                    )
                ],
                cursor={"count": 1},
            )

    import secops.services.cve_search as cve_service

    original_http_client = cve_service.httpx.Client
    original_adapter_for = cve_service.adapter_for
    original_available_sources = cve_service.available_sources
    cve_service.httpx.Client = lambda timeout=10.0: FakeClient()  # type: ignore[assignment]
    cve_service.adapter_for = lambda name: FakeAdapter()  # type: ignore[assignment]
    cve_service.available_sources = lambda include_optional=False: ["fake_feed"]  # type: ignore[assignment]
    try:
        payload = CVESearchService().search(vendor="apache", product="struts", live_on_miss=True, live_limit=10)
    finally:
        cve_service.httpx.Client = original_http_client  # type: ignore[assignment]
        cve_service.adapter_for = original_adapter_for  # type: ignore[assignment]
        cve_service.available_sources = original_available_sources  # type: ignore[assignment]

    assert payload["live"]["attempted"] is True
    assert payload["live"]["upserted"] == 1
    assert payload["results"]
    assert payload["results"][0]["id"] == "CVE-2025-99999"


def test_upsert_references_dedupes_url_for_multi_cve_record() -> None:
    reset_db()
    with SessionLocal() as db:
        service = VulnIntelService(db)
        service.upsert_records(
            [
                IntelRecord(
                    source="cisa_kev",
                    external_id="KEV-MULTI",
                    title="multi-cve advisory",
                    cve_ids=["CVE-2025-11111", "CVE-2025-22222"],
                    aliases=["CVE-2025-11111", "CVE-2025-22222"],
                    url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    confidence=0.9,
                )
            ]
        )
        refs = (
            db.query(VulnerabilityIntelReference)
            .filter(VulnerabilityIntelReference.reference_type == "url")
            .all()
        )
    assert len(refs) == 1
