"""Regression tests for CLI scope-file loading."""
from __future__ import annotations

import pytest

from talisman.cli import _load_scope_config


def test_explicit_missing_scope_file_fails_closed(tmp_path):
    missing_scope = tmp_path / "missing-scope.yaml"

    with pytest.raises(FileNotFoundError, match="Scope file does not exist"):
        _load_scope_config("example.com", missing_scope)


def test_explicit_scope_directory_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="not a regular file"):
        _load_scope_config("example.com", tmp_path)


def test_scope_file_is_used_when_explicitly_supplied(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "include:\n  - api.example.com\n"
        "exclude:\n  - api.example.com/admin/*\n",
        encoding="utf-8",
    )

    config = _load_scope_config("example.com", scope_file)

    assert config.include == ["api.example.com"]
    assert config.exclude == ["api.example.com/admin/*"]


def test_no_scope_file_uses_exact_target_scope():
    config = _load_scope_config("https://example.com", None)

    assert config.include == ["example.com"]
