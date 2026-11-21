"""Credential-redaction tests for evidence and serialized report values."""
from talisman.utils.redaction import (
    redact_sensitive_text,
    redact_sensitive_value,
)


def test_redacts_auth_headers_cookies_and_query_parameters():
    raw = (
        "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz1234567890\\n"
        "Cookie: sessionid=secret-cookie; csrftoken=secret-csrf\\n"
        "GET /reset?token=reset-secret&next=/home"
    )
    redacted = redact_sensitive_text(raw)

    assert "ghp_abcdefghijklmnopqrstuvwxyz1234567890" not in redacted
    assert "secret-cookie" not in redacted
    assert "secret-csrf" not in redacted
    assert "reset-secret" not in redacted
    assert "next=/home" in redacted


def test_redacts_known_tokens_and_private_key_material():
    stripe_key = "sk_" + "live_" + "1234567890abcdefghijklmnopqrstuv"
    raw = (
        "AWS=AKIA1234567890ABCDEF "
        f"Stripe={stripe_key} "
        "-----BEGIN PRIVATE KEY-----\\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\n"
        "-----END PRIVATE KEY-----"
    )
    redacted = redact_sensitive_text(raw)

    assert "AKIA1234567890ABCDEF" not in redacted
    assert stripe_key not in redacted
    assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" not in redacted
    assert "[PRIVATE KEY REDACTED]" in redacted


def test_redacts_database_url_passwords():
    raw = "postgresql://reader:verysecretpassword@db.example.test:5432/app"
    redacted = redact_sensitive_text(raw)
    assert "verysecretpassword" not in redacted
    assert "reader:[REDACTED]@" in redacted


def test_recursively_redacts_nested_evidence():
    raw = {
        "request": "Authorization: Bearer my-secret-token",
        "nested": [{"query": "/api?access_token=top-secret"}],
    }
    safe = redact_sensitive_value(raw)
    assert "my-secret-token" not in str(safe)
    assert "top-secret" not in str(safe)


def test_bounds_redaction_input_size():
    safe = redact_sensitive_text("x" * 100, max_chars=10)
    assert len(safe) < 100
    assert "[TRUNCATED" in safe
