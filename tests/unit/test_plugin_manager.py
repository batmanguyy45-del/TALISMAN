"""Unit tests for the plugin manager system."""
from __future__ import annotations
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest


class TestDiscoverPlugins:
    def test_no_dir(self):
        from talisman.engine.plugin_manager import discover_plugins

        with (
            patch("pathlib.Path.exists", return_value=False),
            patch("pathlib.Path.mkdir"),
        ):
            plugins = discover_plugins()
        assert isinstance(plugins, dict)

    def test_empty_dir(self, tmp_path):
        from talisman.engine.plugin_manager import discover_plugins

        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        with patch("talisman.engine.plugin_manager.PLUGIN_DIRS", [plugin_dir]):
            plugins = discover_plugins()
        assert isinstance(plugins, dict)
        assert len(plugins) == 0

    def test_with_manifest(self, tmp_path):
        from talisman.engine.plugin_manager import discover_plugins

        plugin_dir = tmp_path / "test_plugin"
        plugin_dir.mkdir()
        manifest = plugin_dir / "plugin.yaml"
        manifest.write_text(
            "name: test-plugin\n"
            "version: 1.0.0\n"
            "entrypoint: test_module.TestPlugin\n"
            "type: scanner\n"
            "author: test\n"
            "description: A test plugin\n"
        )

        with patch("talisman.engine.plugin_manager.PLUGIN_DIRS", [tmp_path]):
            plugins = discover_plugins()
        assert "test-plugin" in plugins
        info = plugins["test-plugin"]
        assert info["version"] == "1.0.0"
        assert info["entrypoint"] == "test_module.TestPlugin"
        assert info["type"] == "scanner"
        assert info["module_alias"] == "plugin.test-plugin"


class TestRegistryFunctions:
    def test_register_plugins_to_registry(self):
        from talisman.engine.plugin_manager import (
            register_plugins_to_registry,
            _plugin_registry,
        )

        _plugin_registry.clear()
        registry = {"scanner.xss": "talisman.modules.scanner.xss"}

        with patch("talisman.engine.plugin_manager.discover_plugins", return_value={}):
            updated = register_plugins_to_registry(registry)
        assert "scanner.xss" in updated
        assert updated["scanner.xss"] == "talisman.modules.scanner.xss"

    def test_list_plugins_empty(self):
        from talisman.engine.plugin_manager import list_plugins

        with patch("talisman.engine.plugin_manager.discover_plugins", return_value={}):
            result = list_plugins()
        assert isinstance(result, list)
        assert len(result) == 0


class TestPluginExecution:
    @pytest.mark.asyncio
    async def test_run_plugin_not_found(self):
        from talisman.engine.plugin_manager import run_plugin

        result = await run_plugin("plugin.nonexistent", target="http://test.com")
        assert "error" in result
        assert "not found" in result["error"]

    def test_load_plugin_invalid_entrypoint(self):
        from talisman.engine.plugin_manager import load_plugin

        info = {"entrypoint": ""}
        result = load_plugin(info)
        assert result is None

    def test_load_plugin_bad_module(self):
        from talisman.engine.plugin_manager import load_plugin

        info = {"entrypoint": "nonexistent_module.ClassName", "directory": "/tmp"}
        result = load_plugin(info)
        assert result is None
