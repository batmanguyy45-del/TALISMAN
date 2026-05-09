"""Unit tests for session management."""
import asyncio
import pytest
import tempfile
from pathlib import Path
from talisman.engine.session import Session, SessionManager

@pytest.fixture
def tmp_session_dir(tmp_path):
    return tmp_path

@pytest.mark.asyncio
async def test_session_create_open(tmp_session_dir):
    sess = Session("test-session", tmp_session_dir)
    async with sess:
        assert sess.db_path.exists()

@pytest.mark.asyncio
async def test_add_and_get_finding(tmp_session_dir):
    sess = Session("test-session", tmp_session_dir)
    async with sess:
        fid = await sess.add_finding(
            target="https://example.com",
            module="xss",
            vuln_type="reflected_xss",
            severity="high",
            confidence="confirmed",
            title="Test XSS Finding",
            description="Test description",
        )
        assert fid is not None
        findings = await sess.get_findings()
        assert len(findings) == 1
        assert findings[0]["title"] == "Test XSS Finding"

@pytest.mark.asyncio
async def test_severity_filter(tmp_session_dir):
    sess = Session("test-session", tmp_session_dir)
    async with sess:
        await sess.add_finding("t", "m", "xss", "high", "confirmed", "High Finding")
        await sess.add_finding("t", "m", "sqli", "low", "confirmed", "Low Finding")
        highs = await sess.get_findings(severity=["high"])
        assert len(highs) == 1
        assert highs[0]["severity"] == "high"

@pytest.mark.asyncio
async def test_summary(tmp_session_dir):
    sess = Session("test-session", tmp_session_dir)
    async with sess:
        await sess.add_finding("t", "m", "xss", "critical", "confirmed", "Crit")
        await sess.add_finding("t", "m", "sqli", "high", "confirmed", "High")
        summary = await sess.summary()
        assert summary["total_findings"] == 2
        assert summary["findings"]["critical"] == 1
        assert summary["findings"]["high"] == 1

@pytest.mark.asyncio
async def test_module_run_tracking(tmp_session_dir):
    sess = Session("test-session", tmp_session_dir)
    async with sess:
        run_id = await sess.start_module_run("xss", "https://example.com")
        assert run_id is not None
        await sess.complete_module_run(run_id, status="success", summary="Found 2 issues")

@pytest.mark.asyncio
async def test_notes(tmp_session_dir):
    sess = Session("test-session", tmp_session_dir)
    async with sess:
        await sess.add_note("First login uses JWT HS256")
        notes = await sess.get_notes()
        assert len(notes) == 1
        assert "JWT" in notes[0]["note"]

def test_session_manager(tmp_session_dir):
    sm = SessionManager(tmp_session_dir)
    sm.create("bounty-q1")
    sm.create("bounty-q2")
    sessions = sm.list_sessions()
    assert "bounty-q1" in sessions
    assert "bounty-q2" in sessions
    assert sm.exists("bounty-q1")
    sm.delete("bounty-q1")
    assert not sm.exists("bounty-q1")
