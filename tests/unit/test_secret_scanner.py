"""Regression tests for secret redaction and conservative classifications."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.cloud import secrets


def _scope():
    return ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )


@pytest.mark.asyncio
async def test_known_secret_pattern_is_redacted_and_not_promoted():
    raw_key = "AKIA1234567890ABCDEF"
    records = await secrets._scan_content(
        f'const AWS_ACCESS_KEY_ID = "{raw_key}";',
        "fixture.js",
    )

    assert len(records) == 1
    record = records[0]
    assert record["type"] == "AWS Access Key ID"
    assert record["confidence"] == "candidate"
    assert record["value"] == "[REDACTED]"
    assert raw_key not in str(record)
    assert record["fingerprint"]
    assert record["requires_credential_validation"] is True


@pytest.mark.asyncio
async def test_placeholder_credentials_are_ignored():
    records = await secrets._scan_content(
        'const AWS_ACCESS_KEY_ID = "AKIA000000000EXAMPLE"; '
        'const API_KEY = "your_api_key_goes_here";',
        "fixture.js",
    )
    assert records == []


@pytest.mark.asyncio
async def test_arbitrary_uuid_is_not_reported_as_a_credential():
    records = await secrets._scan_content(
        "build_id=123e4567-e89b-12d3-a456-426614174000",
        "fixture.js",
    )
    assert records == []


@pytest.mark.asyncio
async def test_sensitive_path_http_200_without_secret_is_observation(monkeypatch):
    class Response:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text
            self.content = text.encode()
            self.headers = {}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            assert kwargs.get("scope") is not None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, **kwargs):
            if url.endswith("/.env.example"):
                return Response(200, "APP_ENV=demo\\nPUBLIC_URL=https://example.com")
            return Response(404, "")

    monkeypatch.setattr(secrets, "TalismanHTTPClient", FakeClient)
    session = type(
        "Session",
        (),
        {"add_finding": lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("secret heuristic must not create a confirmed finding")
        )},
    )()

    result = await secrets.run(
        target="https://example.com",
        scope=_scope(),
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 0
    assert any(
        item["path"] == "/.env.example"
        for item in result["observations"]
    )


@pytest.mark.asyncio
async def test_secret_scanner_requires_explicit_scope():
    result = await secrets.run(target="https://example.com")
    assert result["error"] == "scope_enforcer_required"
    assert result["secrets"] == []
    assert result["candidates"] == []
    assert result["count"] == 0
