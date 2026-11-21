"""Tests for alert webhook destination validation."""
from talisman.engine.monitor import _valid_webhook_url


def test_discord_and_slack_webhooks_are_allowed():
    assert _valid_webhook_url(
        "https://discord.com/api/webhooks/123456/secret-token"
    )
    assert _valid_webhook_url(
        "https://hooks.slack.com/services/T000/B000/secret"
    )


def test_non_https_or_untrusted_webhook_destinations_are_rejected():
    assert not _valid_webhook_url(
        "http://discord.com/api/webhooks/123456/token"
    )
    assert not _valid_webhook_url(
        "https://discord.com.attacker.test/api/webhooks/123456/token"
    )
    assert not _valid_webhook_url(
        "https://discord.com@127.0.0.1/api/webhooks/123456/token"
    )
    assert not _valid_webhook_url(
        "https://discord.com:8443/api/webhooks/123456/token"
    )


def test_webhook_urls_with_query_fragment_or_line_breaks_are_rejected():
    assert not _valid_webhook_url(
        "https://discord.com/api/webhooks/123456/token?next=https://127.0.0.1"
    )
    assert not _valid_webhook_url(
        "https://hooks.slack.com/services/T000/B000/secret#fragment"
    )
    assert not _valid_webhook_url(
        "https://discord.com/api/webhooks/123456/token\r\nHost: localhost"
    )
