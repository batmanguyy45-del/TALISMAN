"""Dashboard rendering regression tests."""
from __future__ import annotations

import pytest


pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")
from talisman.web import dashboard


class _FakeSession:
    async def open(self):
        return self

    async def close(self):
        return None

    async def summary(self):
        return {
            "targets_count": 1,
            "total_findings": 1,
            "severity_breakdown": {"critical": 1},
            "modules_run": 1,
        }

    async def get_findings(self, severity=None):
        return [
            {
                "severity": "critical<script>alert(1)</script>",
                "module": "<img src=x onerror=alert(2)>",
                "vuln_type": "xss",
                "target": "https://example.com/<svg onload=alert(3)>",
                "title": "<script>alert(4)</script>",
            }
        ]


class _FakeSessionManager:
    def list_sessions(self):
        return ["<script>alert(5)</script>"]

    def get(self, name):
        return _FakeSession()


@pytest.mark.asyncio
async def test_dashboard_escapes_untrusted_session_names(monkeypatch):
    monkeypatch.setattr(dashboard, "SessionManager", _FakeSessionManager)
    output = await dashboard._render_sessions()

    assert "<script>" not in output
    assert "&lt;script&gt;" in output


@pytest.mark.asyncio
async def test_findings_page_escapes_scanner_controlled_fields(monkeypatch):
    monkeypatch.setattr(dashboard, "SessionManager", _FakeSessionManager)
    output = await dashboard._render_findings()

    assert "<script>" not in output
    assert "<img src=x" not in output
    assert "<svg onload" not in output
    assert "badge-info" in output
