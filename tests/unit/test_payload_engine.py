"""Unit tests for payload engine."""
import pytest
from talisman.utils.payload_engine import PayloadEngine, XSS_PAYLOADS, SQLI_PAYLOADS

def test_xss_basic():
    engine = PayloadEngine()
    payloads = engine.get_xss(context="html")
    assert len(payloads) > 5
    assert any("<script>" in p for p in payloads)

def test_xss_waf_bypass():
    engine = PayloadEngine()
    payloads = engine.get_xss(waf_bypass=True)
    assert len(payloads) > 10
    assert any("ontoggle" in p for p in payloads)

def test_sqli_techniques():
    engine = PayloadEngine()
    error = engine.get_sqli(technique="error")
    time_b = engine.get_sqli(technique="time")
    assert len(error) > 0
    assert any("SLEEP" in p or "WAITFOR" in p for p in time_b)

def test_ssrf_with_oast():
    engine = PayloadEngine(oast_domain="test.oast.pro")
    payloads = engine.get_ssrf(include_oast=True)
    assert any("test.oast.pro" in p for p in payloads)

def test_lfi_payloads():
    engine = PayloadEngine()
    payloads = engine.get_lfi(bypass=True)
    assert any("etc/passwd" in p for p in payloads)
    assert any("%252f" in p for p in payloads)

def test_cmdi_linux():
    engine = PayloadEngine()
    payloads = engine.get_cmdi(os_target="linux")
    assert any("id" in p for p in payloads)

def test_mutate_url_encode():
    engine = PayloadEngine()
    result = engine.mutate("<script>alert(1)</script>", ["url_encode"])
    assert any("%3C" in r or "%3c" in r for r in result)

def test_unique_marker():
    engine = PayloadEngine()
    m1 = engine.generate_unique_marker()
    m2 = engine.generate_unique_marker()
    assert m1 != m2
    assert m1.startswith("TALIS")
    assert len(m1) == 13
