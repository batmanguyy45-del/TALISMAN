"""Regression tests for redaction in terminal and file log output."""
from __future__ import annotations

import logging
import sys
from io import StringIO

from rich.console import Console

from talisman.utils import logger as logger_module


def test_redaction_filter_sanitizes_interpolated_and_structured_log_messages():
    redaction_filter = logger_module.SensitiveDataRedactionFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request url=%s headers=%s",
        args=(
            "https://user:password123@example.com/?access_token=opaque-token",
            {"Authorization": "Bearer opaque-bearer-token"},
        ),
        exc_info=None,
    )

    assert redaction_filter.filter(record) is True

    rendered = record.getMessage()
    for secret in ("password123", "opaque-token", "opaque-bearer-token"):
        assert secret not in rendered
    assert "[REDACTED]" in rendered


def test_setup_logging_redacts_terminal_and_file_handlers(tmp_path, monkeypatch):
    terminal_output = StringIO()
    monkeypatch.setattr(
        logger_module,
        "console",
        Console(file=terminal_output, force_terminal=False, no_color=True, highlight=False),
    )
    log_path = tmp_path / "talisman.log"

    logger_module.setup_logging(level="INFO", log_file=log_path)
    handlers = list(logging.getLogger().handlers)

    assert len(handlers) == 2
    assert all(
        any(
            isinstance(item, logger_module.SensitiveDataRedactionFilter)
            for item in handler.filters
        )
        for handler in handlers
    )

    secret_url = "https://user:pass123@example.com/?api_key=opaque-api-key"
    logging.getLogger("talisman.test.redaction").warning("request_url=%s", secret_url)

    for handler in handlers:
        handler.flush()

    terminal_text = terminal_output.getvalue()
    file_text = log_path.read_text(encoding="utf-8")
    for rendered in (terminal_text, file_text):
        assert "pass123" not in rendered
        assert "opaque-api-key" not in rendered
        assert "[REDACTED]" in rendered


def test_redaction_filter_sanitizes_exception_details():
    redaction_filter = logger_module.SensitiveDataRedactionFilter()
    try:
        raise RuntimeError(
            "failed request https://example.com/?access_token=opaque-exception-token"
        )
    except RuntimeError:
        exception_info = sys.exc_info()

    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="request failed",
        args=(),
        exc_info=exception_info,
    )

    assert redaction_filter.filter(record) is True
    rendered = record.getMessage()
    assert "opaque-exception-token" not in rendered
    assert "RuntimeError" in rendered
    assert "access_token=[REDACTED]" in rendered
