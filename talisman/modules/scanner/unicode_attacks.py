"""Unicode/Bidi Trojan Source scanner — detects bidirectional control characters, homoglyph attacks, and normalization bypasses in reflected content and API responses."""
from __future__ import annotations
import asyncio
import re
import unicodedata
from typing import Any
from talisman.engine.scope import ScopeViolationError
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
    """Report Unicode observations and keep active filter tests as candidates."""
    url = target if "://" in target else f"https://{target}"
    if scope is None:
        return {
            "target": url, "findings": [], "candidates": [], "observations": [],
            "count": 0, "candidate_count": 0, "observation_count": 0,
            "error": "scope_enforcer_required",
        }
    scope.assert_in_scope(url)

    allow_post_probes = False
    try:
        scope.assert_destructive_allowed(url, "POST")
        allow_post_probes = True
    except ScopeViolationError:
        pass

    console.print(
        f"\n[module][+] Unicode Security Posture Scanner[/module] -> [target]{url}[/target]"
    )
    observations: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=12, scope=scope) as client:
        for endpoint in UNICODE_ENDPOINTS:
            # Existing response content is passive posture data. Its presence
            # does not, by itself, prove exploitability.
            for observation in await _test_response_unicode(url, endpoint, client):
                observations.append({
                    **observation,
                    "classification": "security_posture_observation",
                    "impact": "Requires a consumer/context analysis before assigning severity.",
                })

            if not allow_post_probes:
                continue

            active_results = (
                await _test_bidi_reflection(url, endpoint, client)
                + await _test_normalization_bypass(url, endpoint, client)
                + await _test_homoglyph_bypass(url, endpoint, client)
            )
            for item in active_results:
                candidates.append({
                    **item,
                    "confidence": "candidate",
                    "requires_security_decision_validation": True,
                    "verification_required": (
                        "Show that the application or a downstream security "
                        "decision treats the Unicode form differently in a way "
                        "that bypasses a concrete control. Reflection or acceptance "
                        "of a Unicode character alone is not a bypass."
                    ),
                })

    skipped_vectors = []
    if not allow_post_probes:
        skipped_vectors.append(
            "Active POST reflection, normalization, and homoglyph tests were "
            "skipped because destructive-probe permission was not granted."
        )

    console.print(
        f"  Unicode assessment complete -- {len(observations)} observations, "
        f"{len(candidates)} candidates"
    )
    return {
        "target": url,
        "findings": [],
        "candidates": candidates,
        "observations": observations,
        "count": 0,
        "candidate_count": len(candidates),
        "observation_count": len(observations),
        "post_probes_enabled": allow_post_probes,
        "skipped_vectors": skipped_vectors,
    }
