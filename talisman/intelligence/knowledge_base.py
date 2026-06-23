"""Internal knowledge base — technique -> payload -> remediation mappings."""
from __future__ import annotations
from typing import Any

TECHNIQUE_KNOWLEDGE: dict[str, dict[str, Any]] = {
 "reflected_xss": {
  "description": "Reflected XSS occurs when user input is immediately included in server response without sanitization.",
  "contexts": ["html_body", "html_attribute", "javascript", "url", "css"],
  "impact": "Account takeover, credential theft, defacement, malware distribution",
  "owasp": "A03:2021 – Injection",
  "cwe": "CWE-79",
  "references": [
   "https://owasp.org/www-community/attacks/xss/",
   "https://portswigger.net/web-security/cross-site-scripting",
  ],
  "remediation": [
   "HTML-encode all user output in HTML context",
   "JS-encode output in JavaScript context",
   "Implement a strict Content-Security-Policy",
   "Use framework-native templating with auto-escaping",
  ],
 },
 "sql_injection": {
  "description": "SQL injection allows attackers to interfere with database queries.",
  "techniques": ["error_based", "boolean_blind", "time_based", "union", "oob"],
  "impact": "Data exfiltration, authentication bypass, data modification, RCE (xp_cmdshell/UDF)",
  "owasp": "A03:2021 – Injection",
  "cwe": "CWE-89",
  "remediation": [
   "Use parameterized queries / prepared statements",
   "Apply stored procedures with proper parameterization",
   "Validate and allowlist input",
   "Apply least-privilege database accounts",
  ],
 },
 "ssrf": {
  "description": "SSRF allows attackers to induce the server to make requests to unintended locations.",
  "impact": "Internal network access, cloud metadata credential theft, pivoting, port scanning",
  "owasp": "A10:2021 – Server-Side Request Forgery",
  "cwe": "CWE-918",
  "remediation": [
   "Validate and allowlist destination URLs",
   "Block requests to RFC 1918 addresses and metadata endpoints",
   "Disable unused URL schemes (file://, gopher://, dict://)",
   "Use a dedicated HTTP client that parses responses strictly",
  ],
 },
}

def get_technique_info(vuln_type: str) -> dict[str, Any]:
 return TECHNIQUE_KNOWLEDGE.get(vuln_type.lower(), {})
