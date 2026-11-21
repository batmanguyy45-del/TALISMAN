"""Tests that AI report generation respects privacy mode."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from talisman.ai.engine import AIEngine


@pytest.mark.asyncio
async def test_anonymized_report_does_not_send_raw_description_or_evidence():
    engine = AIEngine(provider="anthropic", api_key="test-key", anonymize=True)
    engine._call = AsyncMock(return_value="draft")
    finding = {
        "id": "finding-123456789",
        "title": "Sensitive finding",
        "severity": "high",
        "vuln_type": "idor",
        "module": "idor",
        "confidence": "confirmed",
        "target": "https://app.example.test/private/user/123",
        "description": "PRIVATE_EMAIL=user@example.test",
        "evidence": "Authorization: Bearer SUPER_SECRET_TOKEN",
        "remediation": "Contact private@example.test",
    }

    result = await engine.write_report(finding)
    prompt = engine._call.await_args.args[1]

    assert result == "draft"
    assert "PRIVATE_EMAIL" not in prompt
    assert "user@example.test" not in prompt
    assert "SUPER_SECRET_TOKEN" not in prompt
    assert "private@example.test" not in prompt
    assert "[omitted in privacy mode]" in prompt


@pytest.mark.asyncio
async def test_non_anonymized_report_includes_evidence_only_when_explicitly_enabled():
    engine = AIEngine(provider="anthropic", api_key="test-key", anonymize=False)
    engine._call = AsyncMock(return_value="draft")
    finding = {
        "id": "finding-1",
        "title": "Test",
        "description": "controlled description",
        "evidence": "controlled evidence",
        "remediation": "controlled remediation",
    }

    await engine.write_report(finding)
    prompt = engine._call.await_args.args[1]
    assert "controlled description" in prompt
    assert "controlled evidence" in prompt
    assert "controlled remediation" in prompt
