"""Tests for report privacy, rendering safety and session-derived paths."""
from __future__ import annotations

import stat

import pytest

from talisman.output.report_engine import ReportEngine


def _engine(output_dir, severity="critical"):
    finding = {
        "title": "<script>alert('title')</script>",
        "target": "https://example.com/<img src=x onerror=alert(1)>",
        "module": "scanner.test",
        "vuln_type": "test",
        "severity": severity,
        "confidence": "confirmed",
        "description": "<img src=x onerror=alert(2)>",
        "request": "GET / HTTP/1.1\r\nHost: example.com",
        "evidence": "<svg onload=alert(3)>",
        "reproduction": "<script>alert(4)</script>",
        "remediation": "<b>remediation</b>",
        "cvss_score": "<script>alert(5)</script>",
        "cwe": "CWE-200",
    }
    return ReportEngine("private-session", [finding], [], output_dir)


def test_report_files_and_directory_are_private(tmp_path):
    output_dir = tmp_path / "reports"
    engine = _engine(output_dir)
    paths = engine.generate_all()

    assert stat.S_IMODE(output_dir.stat().st_mode) == 0o700
    for path in paths:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_html_and_markdown_escape_untrusted_finding_fields(tmp_path):
    engine = _engine(tmp_path / "reports", severity="critical<script>")
    html_path = engine.generate_html()
    markdown_path = engine.generate_markdown()

    html = html_path.read_text(encoding="utf-8")
    markdown = markdown_path.read_text(encoding="utf-8")

    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "<svg onload" not in html
    assert "alert(5)" not in html
    assert "<script>" not in markdown
    assert "<img src=x" not in markdown
    assert engine.findings[0]["severity"] == "info"


def test_report_rejects_path_traversal_session_name(tmp_path):
    with pytest.raises(ValueError, match="Invalid report session name"):
        ReportEngine("../outside", [], [], tmp_path / "reports")


def test_report_refuses_to_overwrite_symlink(tmp_path):
    output_dir = tmp_path / "reports"
    output_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("untouched", encoding="utf-8")
    report_path = output_dir / "private-session_report.json"

    try:
        report_path.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are not available on this platform")

    engine = _engine(output_dir)
    with pytest.raises(ValueError, match="symlink"):
        engine.generate_json()
    assert outside.read_text(encoding="utf-8") == "untouched"
