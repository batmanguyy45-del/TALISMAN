"""Tests ensuring AWS checks never guess third-party resources."""
from __future__ import annotations

import pytest

from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.modules.cloud import aws


class _FakeClient:
    def __init__(self, *args, **kwargs):
        self.requests = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


@pytest.mark.asyncio
async def test_s3_checks_are_disabled_by_default():
    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    result = await aws.run(target="https://example.com", scope=scope)

    assert result["skipped"] is True
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_s3_scan_requires_explicit_bucket_names(monkeypatch):
    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    result = await aws.run(
        target="https://example.com",
        scope=scope,
        s3_enum=True,
    )

    assert result["skipped"] is True
    assert "explicit bucket names" in result["reason"]


@pytest.mark.asyncio
async def test_out_of_scope_bucket_is_skipped_without_network_probe(monkeypatch):
    scope = ScopeEnforcer(
        ScopeConfig(include=["example.com"], service_allowlist=[])
    )
    monkeypatch.setattr(aws, "TalismanHTTPClient", _FakeClient)

    async def unexpected_probe(*args, **kwargs):
        raise AssertionError("out-of-scope S3 bucket must not be probed")

    monkeypatch.setattr(aws, "_test_s3_bucket", unexpected_probe)
    result = await aws.run(
        target="https://example.com",
        scope=scope,
        s3_enum=True,
        s3_buckets=["third-party-bucket"],
    )

    assert result["s3_buckets"] == []
    assert result["skipped_buckets"] == ["third-party-bucket"]


@pytest.mark.asyncio
async def test_explicitly_scoped_bucket_can_be_checked(monkeypatch):
    scope = ScopeEnforcer(
        ScopeConfig(
            include=["example.com", "owned-bucket.s3.amazonaws.com"],
            service_allowlist=[],
        )
    )
    monkeypatch.setattr(aws, "TalismanHTTPClient", _FakeClient)

    async def fake_probe(name, client):
        return {
            "bucket": name,
            "url": f"https://{name}.s3.amazonaws.com/",
            "listable": True,
            "files": ["proof.txt"],
            "file_count": 1,
        }

    monkeypatch.setattr(aws, "_test_s3_bucket", fake_probe)
    result = await aws.run(
        target="https://example.com",
        scope=scope,
        s3_enum=True,
        s3_buckets=["owned-bucket"],
    )

    assert result["count"] == 1
    assert result["findings"][0]["bucket"] == "owned-bucket"
    assert result["skipped_buckets"] == []
