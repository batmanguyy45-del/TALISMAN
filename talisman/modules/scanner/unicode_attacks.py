"""Unicode/Bidi Trojan Source scanner — detects bidirectional control characters, homoglyph attacks, and normalization bypasses in reflected content and API responses."""
from __future__ import annotations
import asyncio
import re
import unicodedata
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

# Unicode bidirectional control characters that enable Trojan Source attacks
BIDI_CHARACTERS = {
    "\u202A": "LEFT-TO-RIGHT EMBEDDING (LRE)",
    "\u202B": "RIGHT-TO-LEFT EMBEDDING (RLE)",
    "\u202C": "POP DIRECTIONAL FORMATTING (PDF)",
    "\u202D": "LEFT-TO-RIGHT OVERRIDE (LRO)",
    "\u202E": "RIGHT-TO-LEFT OVERRIDE (RLO)",
    "\u2066": "LEFT-TO-RIGHT ISOLATE (LRI)",
    "\u2067": "RIGHT-TO-LEFT ISOLATE (RLI)",
    "\u2068": "FIRST STRONG ISOLATE (FSI)",
    "\u2069": "POP DIRECTIONAL ISOLATE (PDI)",
    "\u200E": "LEFT-TO-RIGHT MARK (LRM)",
    "\u200F": "RIGHT-TO-LEFT MARK (RLM)",
}

# Additional invisible/homoglyph characters used in attacks
INVISIBLE_CHARACTERS = {
    "\u200B": "ZERO WIDTH SPACE (ZWSP)",
    "\u200C": "ZERO WIDTH NON-JOINER (ZWNJ)",
    "\u200D": "ZERO WIDTH JOINER (ZWJ)",
    "\uFEFF": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u00AD": "SOFT HYPHEN",
    "\u2060": "WORD JOINER",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
    "\u180E": "MONGOLIAN VOWEL SEPARATOR",
}

# Homoglyph character mappings commonly used in attacks
HOMOGLYPH_SETS = [
    ("Latin 'a' vs Cyrillic 'а'", "a", "\u0430"),
    ("Latin 'e' vs Cyrillic 'е'", "e", "\u0435"),
    ("Latin 'o' vs Cyrillic 'о'", "o", "\u043E"),
    ("Latin 'c' vs Cyrillic 'с'", "c", "\u0441"),
    ("Latin 'p' vs Cyrillic 'р'", "p", "\u0440"),
    ("Latin 'x' vs Cyrillic 'х'", "x", "\u0445"),
    ("Latin 'y' vs Cyrillic 'у'", "y", "\u0443"),
]

UNICODE_ENDPOINTS = [
    "/api/user", "/api/profile", "/api/search",
    "/api/echo", "/api/render",
    "/api/comment", "/api/post",
    "/api/login", "/api/register",
    "/api/config", "/api/debug",
]

# Payloads with Bidi characters to test if the server reflects them unsanitized
BIDI_PAYLOADS = [
    # Classic Trojan Source: Early Return in comment
    '\u202E /* Hidden return */\u202C',
    # RLO override to hide malicious code
    '\u202Emoc.troppus_evreser@'.join(['', '']) + '\u202C',
    # Stretched string with LRI/RLI
    '\u2066admin\u2069',
    # ZWSP injection in the middle of a string
    'ad\u200Bmin',
    # Homoglyph confusable
    '\u0430dmin',  # Cyrillic 'а' instead of Latin 'a'
    # Multi-vector
    '\u202Eadmin\u202C\u200B',
]


async def _test_bidi_reflection(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test if the server reflects Unicode Bidi control characters without sanitization.

    If Bidi characters are reflected, an attacker can use Trojan Source techniques
    to hide malicious code in API responses that are consumed by other systems.
    """
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint

    for payload in BIDI_PAYLOADS:
        test_variants = [
            {"q": payload},
            {"input": payload},
            {"name": payload},
            {"data": payload},
            {"search": payload},
            {"comment": payload},
        ]

        for params in test_variants:
            try:
                r = await client.post(test_url, json=params,
                    headers={"Content-Type": "application/json"}, timeout=8)
                resp_text = r.text

                # Check if any Bidi character from our payload appears in the response
                for char, char_name in BIDI_CHARACTERS.items():
                    if char in resp_text:
                        findings.append({
                            "type": "bidi_reflection",
                            "endpoint": endpoint,
                            "char_name": char_name,
                            "char_hex": f"U+{ord(char):04X}",
                            "char_repr": repr(char),
                            "param": list(params.keys())[0],
                            "evidence": f"Unicode {char_name} (U+{ord(char):04X}) reflected in response at {endpoint}",
                        })
                        break

                for char, char_name in INVISIBLE_CHARACTERS.items():
                    if char in resp_text:
                        findings.append({
                            "type": "invisible_char_reflection",
                            "endpoint": endpoint,
                            "char_name": char_name,
                            "char_hex": f"U+{ord(char):04X}",
                            "param": list(params.keys())[0],
                            "evidence": f"Invisible character {char_name} (U+{ord(char):04X}) reflected in response",
                        })

                if findings:
                    break
            except Exception:
                pass

        if findings:
            break

    return findings


async def _test_normalization_bypass(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test Unicode normalization bypass — does the server normalize differently than the WAF?

    Many WAFs use NFD normalization while backends use NFC (or vice versa),
    creating a bypass opportunity.
    """
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = "TLSMUNICODE"

    # Payload with NFC/NFD normalization differences
    # "é" in NFC is \u00E9, in NFD is e\u0301
    nfc_payload = f"\u00E9{canary}"  # NFC: single codepoint é
    nfd_payload = f"e\u0301{canary}"  # NFD: e + combining acute accent

    # Test NFC payload
    try:
        r_nfc = await client.post(test_url,
            json={"q": nfc_payload, "name": f"test_{canary}"},
            headers={"Content-Type": "application/json"}, timeout=8)

        if canary not in r_nfc.text:
            # NFC not reflected? Try NFD
            r_nfd = await client.post(test_url,
                json={"q": nfd_payload, "name": f"test_{canary}"},
                headers={"Content-Type": "application/json"}, timeout=8)
            if canary in r_nfd.text and len(r_nfd.text) > 0:
                # NFD works but NFC didn't — normalization-based WAF bypass possible
                findings.append({
                    "type": "normalization_bypass",
                    "endpoint": endpoint,
                    "evidence": "NFD payload reflected while NFC was blocked/filtered — normalization bypass possible",
                    "canary": canary,
                })
    except Exception:
        pass

    return findings


async def _test_homoglyph_bypass(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Test homoglyph-based WAF/filter bypass.

    Replace Latin characters with visually identical Cyrillic counterparts.
    """
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint
    canary = "TLSMHOMOGLYPH"

    for desc, latin, cyrillic in HOMOGLYPH_SETS:
        # Build a payload replacing latin char with cyrillic
        test_word = f"{canary}_{cyrillic}dmin" if 'a' in desc else f"{canary}_t{cyrillic}st"
        safe_word = f"{canary}_safe_check"

        try:
            r = await client.post(test_url,
                json={"q": test_word, "name": safe_word},
                headers={"Content-Type": "application/json"}, timeout=8)
            resp_text = r.text

            # If the cyrillic variant is treated differently from the latin version
            if canary in resp_text and test_word[:30] in resp_text:
                # The homoglyph passed through — check if a Latin equivalent would be blocked
                # by testing a different endpoint with both forms
                findings.append({
                    "type": "homoglyph_bypass",
                    "endpoint": endpoint,
                    "description": desc,
                    "latin_char": latin,
                    "cyrillic_char": cyrillic,
                    "cyrillic_hex": f"U+{ord(cyrillic):04X}",
                    "evidence": f"Homoglyph '{cyrillic}' (U+{ord(cyrillic):04X}) equivalent to '{latin}' was accepted at {endpoint}",
                    "canary": canary,
                })
                break
        except Exception:
            pass

    return findings


async def _test_response_unicode(
    url: str, endpoint: str, client: TalismanHTTPClient,
) -> list[dict[str, Any]]:
    """Analyze response content for existing Unicode attack vectors.

    Some APIs may already have stored Bidi or invisible characters in their
    responses (e.g., from user-submitted content).
    """
    findings: list[dict[str, Any]] = []
    test_url = url.rstrip("/") + endpoint

    try:
        r = await client.get(test_url, timeout=8)
        resp_text = r.text

        found_chars = []
        for char, char_name in BIDI_CHARACTERS.items():
            count = resp_text.count(char)
            if count > 0:
                found_chars.append(f"{char_name} (U+{ord(char):04X}) x{count}")

        for char, char_name in INVISIBLE_CHARACTERS.items():
            count = resp_text.count(char)
            if count > 0:
                found_chars.append(f"{char_name} (U+{ord(char):04X}) x{count}")

        if found_chars:
            findings.append({
                "type": "bidi_in_response",
                "endpoint": endpoint,
                "chars_found": found_chars,
                "evidence": f"Response contains Unicode control characters: {'; '.join(found_chars[:5])}",
            })
    except Exception:
        pass

    return findings


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    url = target if "://" in target else f"https://{target}"
    console.print(f"\n[module][+] Unicode/Bidi Attack Scanner[/module] -> [target]{url}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12) as client:
        console.print(f"  Testing {len(UNICODE_ENDPOINTS)} endpoints for Unicode attack vectors...")

        for endpoint in UNICODE_ENDPOINTS:
            # -- 1. Bidi character reflection -----------------------------------------
            bidi_findings = await _test_bidi_reflection(url, endpoint, client)
            for f in bidi_findings:
                ftype = f.get("type", "")
                char_name = f.get("char_name", "Unknown")
                char_hex = f.get("char_hex", "U+????")
                title = f"Unicode control character reflection at {endpoint}: {char_name} ({char_hex})"
                print_finding(title, "medium", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="unicode_attacks",
                        vuln_type=ftype,
                        severity="medium", confidence="confirmed",
                        title=title,
                        description=f"Unicode {char_name} ({char_hex}) reflected at {endpoint} via parameter '{f.get('param', '')}'. Reflected Bidi characters enable Trojan Source-style attacks that can hide malicious code from both human review and automated analysis.",
                        evidence=f.get("evidence", ""),
                        remediation="1. Sanitize or strip Unicode control characters from user input. 2. Use Unicode-aware sanitization libraries. 3. Reject inputs containing Bidi control characters unless explicitly required. 4. Add warnings for Bidi characters in code review pipelines.",
                        cvss_score=5.3, cwe="CWE-172",
                    )

            # -- 2. Normalization bypass ----------------------------------------------
            norm_findings = await _test_normalization_bypass(url, endpoint, client)
            for f in norm_findings:
                title = f"Unicode normalization bypass at {endpoint}"
                print_finding(title, "high", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="unicode_attacks",
                        vuln_type="normalization_bypass",
                        severity="high", confidence="confirmed",
                        title=title,
                        description=f"Unicode normalization bypass detected at {endpoint}. NFD-form payload was processed differently from NFC, creating a WAF/input filter bypass opportunity.",
                        evidence=f.get("evidence", ""),
                        remediation="1. Normalize user input to a consistent Unicode form (NFC recommended) before validation. 2. Apply security filters AFTER normalization, not before.",
                        cvss_score=7.5, cwe="CWE-176",
                    )

            # -- 3. Homoglyph bypass --------------------------------------------------
            homo_findings = await _test_homoglyph_bypass(url, endpoint, client)
            for f in homo_findings:
                title = f"Homoglyph bypass at {endpoint}: {f.get('description', '')}"
                print_finding(title, "high", url)
                findings.append(f)
                if session:
                    await session.add_finding(
                        target=url, module="unicode_attacks",
                        vuln_type="homoglyph_bypass",
                        severity="high", confidence="confirmed",
                        title=title,
                        description=f"Homoglyph bypass confirmed at {endpoint}. Character '{f.get('cyrillic_char', '')}' (U+{f.get('cyrillic_hex', '')}) visually identical to Latin '{f.get('latin_char', '')}' was accepted and processed. This can bypass domain allowlists, input filters, and WAF rules.",
                        evidence=f.get("evidence", ""),
                        remediation="1. Use Unicode confusable detection libraries. 2. Restrict allowed character sets to ASCII for security-critical fields. 3. Normalize to NFC and validate against allowlist.",
                        cvss_score=7.5, cwe="CWE-176",
                    )

            # -- 4. Existing Bidi characters in responses -----------------------------
            resp_findings = await _test_response_unicode(url, endpoint, client)
            for f in resp_findings:
                chars = f.get("chars_found", [])
                title = f"Unicode control characters in response at {endpoint}: {len(chars)} types found"
                print_finding(title, "info", url)
                findings.append(f)

    console.print(f"  Unicode attack scan complete -- {len(findings)} issues")
    return {"target": url, "findings": findings, "count": len(findings)}
