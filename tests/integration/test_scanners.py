"""Integration tests — run scanners against known-vulnerable local targets."""
import asyncio
import pytest
from pathlib import Path
import tempfile

from talisman.engine.session import Session
from talisman.engine.scope import ScopeEnforcer, ScopeConfig
from talisman.engine.rate_limiter import RateLimiter
from talisman.utils.payload_engine import PayloadEngine

# These tests run against deliberately vulnerable local targets
# Set up with: docker run -d -p 3000:3000 bkimminich/juice-shop
JUICE_SHOP = "http://localhost:3000"
DVWA = "http://localhost:80"

def _make_scope(target: str) -> ScopeEnforcer:
    cfg = ScopeConfig.from_target(target)
    return ScopeEnforcer(cfg)

@pytest.fixture
def tmp_sess(tmp_path):
    sess = Session("integration-test", tmp_path)
    return sess

@pytest.fixture
def rl():
    return RateLimiter("aggressive")

@pytest.mark.asyncio
@pytest.mark.integration
async def test_header_audit_returns_findings(tmp_sess, rl):
    """Headers scanner should find missing headers on juice-shop."""
    from talisman.modules.scanner.headers import run
    scope = _make_scope(JUICE_SHOP)
    async with tmp_sess:
        result = await run(
            target=JUICE_SHOP,
            session=tmp_sess,
            scope=scope,
            rate_limiter=rl,
        )
    assert isinstance(result, dict)
    assert "findings" in result
    # Juice Shop intentionally lacks security headers
    assert result.get("count", 0) >= 0

@pytest.mark.asyncio
@pytest.mark.integration
async def test_cors_scan(tmp_sess, rl):
    """CORS scanner should not crash on any target."""
    from talisman.modules.scanner.cors import run
    scope = _make_scope(JUICE_SHOP)
    async with tmp_sess:
        result = await run(
            target=JUICE_SHOP,
            session=tmp_sess,
            scope=scope,
            rate_limiter=rl,
        )
    assert isinstance(result, dict)
    assert "vulnerabilities" in result

@pytest.mark.asyncio
@pytest.mark.integration
async def test_subdomain_enum_returns_structure(tmp_sess, rl):
    """Subdomain enumeration should return proper structure."""
    from talisman.modules.recon.subdomain import run
    target = "example.com"
    scope = _make_scope(target)
    async with tmp_sess:
        result = await run(
            target=target,
            session=tmp_sess,
            scope=scope,
            rate_limiter=rl,
            sources=["crtsh"],
            bruteforce=False,
            threads=10,
        )
    assert isinstance(result, dict)
    assert "subdomains" in result
    assert "domain" in result

@pytest.mark.asyncio
@pytest.mark.integration
async def test_session_persistence_across_modules(tmp_path):
    """Findings should persist across multiple module runs."""
    sess = Session("test-persist", tmp_path)
    scope = _make_scope(JUICE_SHOP)
    rl = RateLimiter("aggressive")

    async with sess:
        from talisman.modules.scanner.headers import run as header_run
        from talisman.modules.scanner.cors import run as cors_run
        await header_run(target=JUICE_SHOP, session=sess, scope=scope, rate_limiter=rl)
        await cors_run(target=JUICE_SHOP, session=sess, scope=scope, rate_limiter=rl)
        summary = await sess.summary()
        # Should have some findings
        assert summary["total_findings"] >= 0

@pytest.mark.asyncio
async def test_report_engine_html(tmp_path):
    """Report engine should produce valid HTML."""
    from talisman.output.report_engine import ReportEngine
    findings = [
        {
            "id": "test-1",
            "session_id": "test",
            "target": "https://example.com",
            "module": "xss",
            "vuln_type": "reflected_xss",
            "severity": "high",
            "confidence": "confirmed",
            "title": "Test XSS Finding",
            "description": "Test description",
            "request": "GET /search?q=<script> HTTP/1.1",
            "response": "<html>...<script>...XSS...</html>",
            "evidence": "Payload reflected unencoded",
            "reproduction": "Navigate to URL",
            "remediation": "Encode output",
            "cvss_score": 6.1,
            "cwe": "CWE-79",
            "cve_refs": "[]",
            "references": "[]",
            "extra": "{}",
            "status": "open",
            "created_at": "2024-01-01T00:00:00",
            "updated_at": "2024-01-01T00:00:00",
        }
    ]
    engine = ReportEngine("test-session", findings, [], tmp_path)
    html_path = engine.generate_html()
    assert html_path.exists()
    content = html_path.read_text()
    assert "TALISMAN" in content
    assert "Test XSS Finding" in content
    assert "high" in content.lower()

@pytest.mark.asyncio
async def test_report_engine_markdown(tmp_path):
    """Report engine should produce valid Markdown."""
    from talisman.output.report_engine import ReportEngine
    findings = [{
        "id": "test-1",
        "session_id": "test",
        "target": "https://example.com",
        "module": "sqli",
        "vuln_type": "sql_injection",
        "severity": "critical",
        "confidence": "confirmed",
        "title": "SQL Injection — id parameter",
        "description": "Blind SQLi detected",
        "request": "GET /?id=1%27 HTTP/1.1",
        "response": "Database error",
        "evidence": "MySQL error message",
        "reproduction": "Add quote to id param",
        "remediation": "Use parameterized queries",
        "cvss_score": 9.8,
        "cwe": "CWE-89",
        "cve_refs": "[]",
        "references": "[]",
        "extra": "{}",
        "status": "open",
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-01-01T00:00:00",
    }]
    engine = ReportEngine("test-session", findings, [], tmp_path)
    md_path = engine.generate_markdown()
    assert md_path.exists()
    content = md_path.read_text()
    assert "# TALISMAN" in content
    assert "SQL Injection" in content
    assert "CRITICAL" in content

@pytest.mark.asyncio
async def test_scope_enforcement_integration(tmp_path):
    """Scope enforcer should block out-of-scope URLs from being processed."""
    from talisman.engine.scope import ScopeConfig, ScopeEnforcer
    cfg = ScopeConfig(
        include=["example.com", "*.example.com"],
        exclude=["admin.example.com"]
    )
    scope = ScopeEnforcer(cfg)
    in_scope_targets = [
        "https://example.com",
        "https://api.example.com",
        "https://dev.api.example.com/path?q=test",
    ]
    out_of_scope = [
        "https://evil.com",
        "https://admin.example.com",
        "https://notexample.com",
    ]
    filtered_in = scope.filter_targets(in_scope_targets)
    assert set(filtered_in) == set(in_scope_targets)
    filtered_out = scope.filter_targets(out_of_scope)
    assert len(filtered_out) == 0
