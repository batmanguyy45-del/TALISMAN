"""Tests for the scoped NVD CVE-feed client."""
from __future__ import annotations

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.intelligence import cve_feed


class _Response:
    status_code = 200

    def json(self):
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-1234",
                        "metrics": {},
                        "descriptions": [
                            {"lang": "en", "value": "Test description"}
                        ],
                        "published": "2099-01-01T00:00:00.000",
                    }
                }
            ]
        }


async def test_cve_lookup_uses_exact_nvd_scope_and_encoded_params(monkeypatch):
    observed = {}

    class Client:
        def __init__(self, **kwargs):
            observed["kwargs"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, **kwargs):
            observed["url"] = url
            observed["request_kwargs"] = kwargs
            return _Response()

    monkeypatch.setattr(cve_feed, "TalismanHTTPClient", Client)
    result = await cve_feed.lookup_cves("Spring Boot & Framework", "3.2.1")

    scope = observed["kwargs"]["scope"]
    assert isinstance(scope, ScopeEnforcer)
    assert scope.config.include == ["services.nvd.nist.gov"]
    assert scope.config.service_allowlist == []
    assert observed["kwargs"]["verify_ssl"] is True
    assert observed["kwargs"]["follow_redirects"] is False
    assert observed["url"] == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    assert observed["request_kwargs"]["params"] == {
        "keywordSearch": "Spring Boot & Framework 3.2.1",
        "resultsPerPage": 10,
    }
    assert result[0]["id"] == "CVE-2099-1234"


async def test_cve_lookup_respects_explicit_provider_scope(monkeypatch):
    observed = {}

    class Client:
        def __init__(self, **kwargs):
            observed["scope"] = kwargs["scope"]

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, **kwargs):
            return _Response()

    monkeypatch.setattr(cve_feed, "TalismanHTTPClient", Client)
    scope = ScopeEnforcer(
        ScopeConfig(
            include=["services.nvd.nist.gov"],
            service_allowlist=[],
        )
    )

    await cve_feed.lookup_cves("WordPress", scope=scope)

    assert observed["scope"] is scope
