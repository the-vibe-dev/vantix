from __future__ import annotations

from secops.services.intel_sources.epss import EpssAdapter


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self):  # noqa: ANN201
        return self

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def __enter__(self):  # noqa: ANN201
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: ANN001, ANN201
        return False

    def get(self, url: str, params: dict | None = None):  # noqa: ARG002, ANN201
        return _FakeResponse(self._payload)


def test_epss_adapter_handles_string_status(monkeypatch) -> None:  # noqa: ANN001
    payload = {
        "status": "2026-04-20",
        "data": [
            {
                "cve": "CVE-2026-11111",
                "date": "2026-04-20",
                "epss": "0.9",
                "percentile": "0.95",
            }
        ],
    }
    monkeypatch.setattr(
        "secops.services.intel_sources.epss.http_client",
        lambda: _FakeClient(payload),
    )
    result = EpssAdapter().fetch_since(None)
    assert result.error == ""
    assert result.cursor["date"] == "2026-04-20"
    assert len(result.records) == 1
    assert result.records[0].cve_ids == ["CVE-2026-11111"]


def test_epss_adapter_handles_dict_status(monkeypatch) -> None:  # noqa: ANN001
    payload = {
        "status": {"date": "2026-04-21"},
        "data": [],
    }
    monkeypatch.setattr(
        "secops.services.intel_sources.epss.http_client",
        lambda: _FakeClient(payload),
    )
    result = EpssAdapter().fetch_since(None)
    assert result.error == ""
    assert result.cursor["date"] == "2026-04-21"
    assert result.cursor["count"] == 0
