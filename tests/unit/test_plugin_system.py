"""End-to-end tests for the plugin system — discovery, loading, registration, and execution."""
from __future__ import annotations
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

COMMUNITY_PLUGIN_DIR = Path("talisman/plugins/community/example_scanner")


@pytest.mark.asyncio
async def test_example_plugin_manifest_exists():
    manifest = COMMUNITY_PLUGIN_DIR / "plugin.yaml"
    assert manifest.exists(), f"Manifest not found at {manifest}"
    import yaml
    with open(manifest) as f:
        data = yaml.safe_load(f)
    assert data["name"] == "example-scanner"
    assert data["entrypoint"] == "scanner.ExampleScannerPlugin"
    assert data["module_alias"] == "scanner.example"


@pytest.mark.asyncio
async def test_example_plugin_module_imports():
    sys.path.insert(0, str(COMMUNITY_PLUGIN_DIR))
    try:
        from scanner import ExampleScannerPlugin
        instance = ExampleScannerPlugin()
        assert instance.name == "example-scanner"
        assert hasattr(instance, "check")
        assert hasattr(instance, "run")
    finally:
        if str(COMMUNITY_PLUGIN_DIR) in sys.path:
            sys.path.remove(str(COMMUNITY_PLUGIN_DIR))


@pytest.mark.asyncio
async def test_plugin_base_run_method(tmp_path):
    from talisman.plugins.base import ScannerPlugin
    sys.path.insert(0, str(COMMUNITY_PLUGIN_DIR))
    try:
        from scanner import ExampleScannerPlugin
        instance = ExampleScannerPlugin()
        session = MagicMock()
        session.add_finding = AsyncMock()

        with patch("talisman.utils.http_client.TalismanHTTPClient") as mock_cls:
            mock_instance = MagicMock()
            mock_cls.return_value.__aenter__.return_value = mock_instance

            resp = MagicMock()
            resp.headers = {"X-Content-Type-Options": ""}
            mock_instance.get = AsyncMock(return_value=resp)

            result = await instance.run(target="http://test.com", session=session)
            assert isinstance(result, dict)
            assert "findings" in result
            assert result["count"] > 0
            session.add_finding.assert_called_once()
    finally:
        if str(COMMUNITY_PLUGIN_DIR) in sys.path:
            sys.path.remove(str(COMMUNITY_PLUGIN_DIR))


@pytest.mark.asyncio
async def test_plugin_base_run_no_finding_when_header_present(tmp_path):
    from talisman.plugins.base import ScannerPlugin
    sys.path.insert(0, str(COMMUNITY_PLUGIN_DIR))
    try:
        from scanner import ExampleScannerPlugin
        instance = ExampleScannerPlugin()

        with patch("talisman.utils.http_client.TalismanHTTPClient") as mock_cls:
            mock_instance = MagicMock()
            mock_cls.return_value.__aenter__.return_value = mock_instance

            resp = MagicMock()
            resp.headers = {"X-Content-Type-Options": "nosniff"}
            mock_instance.get = AsyncMock(return_value=resp)

            result = await instance.run(target="http://test.com")
            assert isinstance(result, dict)
            assert result["count"] == 0
    finally:
        if str(COMMUNITY_PLUGIN_DIR) in sys.path:
            sys.path.remove(str(COMMUNITY_PLUGIN_DIR))


@pytest.mark.asyncio
async def test_discover_discovers_example_plugin():
    from talisman.engine.plugin_manager import discover_plugins

    plugins = discover_plugins()
    assert "example-scanner" in plugins, (
        f"example-scanner not found in {list(plugins.keys())}. "
        f"Expected in PLUGIN_DIRS community path."
    )
    info = plugins["example-scanner"]
    assert info["entrypoint"] == "scanner.ExampleScannerPlugin"
    assert info["module_alias"] == "scanner.example"


@pytest.mark.asyncio
async def test_resolve_and_run_plugin():
    from talisman.engine.plugin_manager import (
        resolve_plugin,
        _plugin_registry,
        register_plugins_to_registry,
    )

    _plugin_registry.clear()
    registry = register_plugins_to_registry({})
    assert "scanner.example" in registry or "plugin.example-scanner" in registry

    alias = "scanner.example" if "scanner.example" in registry else "plugin.example-scanner"
    fn = resolve_plugin(alias)
    assert fn is not None, f"Could not resolve plugin with alias {alias}"
    assert callable(fn)
