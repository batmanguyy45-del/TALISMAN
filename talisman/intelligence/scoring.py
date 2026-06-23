"""CVSS 3.1 scoring and severity classification."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

SEVERITY_THRESHOLDS = {
 "critical": 9.0,
 "high":  7.0,
 "medium": 4.0,
 "low":  0.1,
 "info":  0.0,
}

VULN_TYPE_BASE_SCORES: dict[str, float] = {
 "command_injection":  10.0,
 "rce":     10.0,
 "sql_injection":   9.8,
 "xxe":      9.1,
 "ssrf":     9.8,
 "ssti":     10.0,
 "reflected_xss":   6.1,
 "stored_xss":    8.8,
 "dom_xss":     6.1,
 "idor":     7.5,
 "open_redirect":   6.1,
 "path_traversal":   7.5,
 "lfi":      7.5,
 "cors_misconfiguration": 8.1,
 "csrf":     8.8,
 "jwt_weak_secret":   9.8,
 "jwt_alg_none":   9.8,
 "subdomain_takeover":  9.3,
 "s3_misconfiguration":  7.5,
 "default_credentials":  9.8,
 "actuator_exposed":  9.1,
 "k8s_api_exposed":  10.0,
 "etcd_exposed":   10.0,
 "database_exposed":  9.8,
 "secret_exposure":   8.6,
 "missing_security_header": 5.3,
 "csp_misconfiguration": 6.1,
 "information_disclosure": 5.3,
 "smb_signing_disabled": 8.1,
 "kerberoasting":   8.8,
 "asrep_roasting":   7.5,
 "gpp_credentials":   9.8,
 "http_request_smuggling": 9.8,
 "cache_poisoning":   8.1,
 "prototype_pollution":  8.1,
}

def score_from_vuln_type(vuln_type: str) -> float:
 return VULN_TYPE_BASE_SCORES.get(vuln_type.lower(), 5.0)

def severity_from_score(score: float) -> str:
 if score >= 9.0:
  return "critical"
 if score >= 7.0:
  return "high"
 if score >= 4.0:
  return "medium"
 if score > 0:
  return "low"
 return "info"

def calculate_cvss(
 av: str = "N", # Attack Vector: N(etwork)/A(djacent)/L(ocal)/P(hysical)
 ac: str = "L", # Attack Complexity: L(ow)/H(igh)
 pr: str = "N", # Privileges Required: N(one)/L(ow)/H(igh)
 ui: str = "N", # User Interaction: N(one)/R(equired)
 s: str = "U", # Scope: U(nchanged)/C(hanged)
 c: str = "H", # Confidentiality: N(one)/L(ow)/H(igh)
 i: str = "H", # Integrity: N(one)/L(ow)/H(igh)
 a: str = "H", # Availability: N(one)/L(ow)/H(igh)
) -> float:
 """Simplified CVSS 3.1 score calculation."""
 av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
 ac_map = {"L": 0.77, "H": 0.44}
 pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}
 pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.50}
 ui_map = {"N": 0.85, "R": 0.62}
 imp_map = {"N": 0.0, "L": 0.22, "H": 0.56}
 scope_changed = s == "C"
 pr_map = pr_map_c if scope_changed else pr_map_u
 av_v = av_map.get(av, 0.85)
 ac_v = ac_map.get(ac, 0.77)
 pr_v = pr_map.get(pr, 0.85)
 ui_v = ui_map.get(ui, 0.85)
 c_v = imp_map.get(c, 0.56)
 i_v = imp_map.get(i, 0.56)
 a_v = imp_map.get(a, 0.56)
 isc_base = 1 - (1 - c_v) * (1 - i_v) * (1 - a_v)
 if scope_changed:
  isc = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
 else:
  isc = 6.42 * isc_base
 ess = av_v * ac_v * pr_v * ui_v
 if isc <= 0:
  return 0.0
 if scope_changed:
  base = min(1.08 * (isc + ess), 10.0)
 else:
  base = min(isc + ess, 10.0)
 return round(base, 1)
