"""Credential-redaction tests for evidence and serialized report values."""
from talisman.utils.redaction import (
    redact_sensitive_text,
    redact_sensitive_value,
)


def test_redacts_auth_headers_cookies_and_query_parameters():
    raw = (
        "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz1234567890\n"
        "Cookie: sessionid=secret-cookie; csrftoken=secret-csrf\n"
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
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
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


def test_redacts_sensitive_mapping_keys_even_for_opaque_values():
    raw = {
        "access_token": "opaque-access-token",
        "nested": {
            "client-secret": "opaque-client-secret",
            "api_key": "opaque-api-key",
            "safe_label": "keep-this-label",
        },
        "headers": [{"Authorization": "opaque-auth-value"}],
    }

    safe = redact_sensitive_value(raw)

    assert safe["access_token"] == "[REDACTED]"
    assert safe["nested"]["client-secret"] == "[REDACTED]"
    assert safe["nested"]["api_key"] == "[REDACTED]"
    assert safe["headers"][0]["Authorization"] == "[REDACTED]"
    assert safe["nested"]["safe_label"] == "keep-this-label"


def test_redacts_quoted_json_secrets_with_spaces_and_signed_url_params():
    raw = (
        '{"password": "opaque password with spaces", '
        '"refresh_token": "opaque-refresh-token"} '
        "https://example.com/callback?X-Amz-Signature=opaque-signed-secret"
    )

    safe = redact_sensitive_text(raw)

    assert "opaque password with spaces" not in safe
    assert "opaque-refresh-token" not in safe
    assert "opaque-signed-secret" not in safe
    assert "[REDACTED]" in safe


def test_redacts_prefixed_secret_field_names():
    structured = redact_sensitive_value({
        "db_password": "opaque-db-password",
        "aws_secret_access_key": "opaque-aws-secret",
        "oauth_access_token": "opaque-oauth-token",
        "safe_password_policy": "minimum 14 characters",
    })
    serialized = redact_sensitive_text(
        '{"db_password": "opaque-json-db-password", '
        '"aws_secret_access_key": "opaque-json-aws-secret"}'
    )

    assert structured["db_password"] == "[REDACTED]"
    assert structured["aws_secret_access_key"] == "[REDACTED]"
    assert structured["oauth_access_token"] == "[REDACTED]"
    assert structured["safe_password_policy"] == "minimum 14 characters"
    assert "opaque-json-db-password" not in serialized
    assert "opaque-json-aws-secret" not in serialized
