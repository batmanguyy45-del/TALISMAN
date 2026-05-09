"""Dynamic plugin loader with manifest validation."""
from __future__ import annotations
import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

PLUGINS_DIR = Path.home() / ".talisman" / "plugins"


def load_plugin_from_dir(plugin_dir: Path) -> Any | None:
    """Load a plugin from a directory containing plugin.yaml + Python module."""
    from talisman.plugins.base import PluginManifest
    manifest_loader = PluginManifest(plugin_dir)
    manifest = manifest_loader.load()
    if not manifest:
        log.warning("plugin_no_manifest", dir=str(plugin_dir))
        return None
    entrypoint = manifest.get("entrypoint", "")
    if not entrypoint:
        return None
    parts = entrypoint.rsplit(".", 1)
    if len(parts) != 2:
        return None
    module_name, class_name = parts
    # Add plugin dir to sys.path temporarily
    if str(plugin_dir) not in sys.path:
        sys.path.insert(0, str(plugin_dir))
    try:
        mod = importlib.import_module(module_name)
        cls = getattr(mod, class_name)
        return cls()
    except Exception as e:
        log.error("plugin_load_error", plugin=str(plugin_dir), error=str(e))
        return None
    finally:
        if str(plugin_dir) in sys.path:
            sys.path.remove(str(plugin_dir))


def list_installed_plugins() -> list[dict[str, Any]]:
    """List all installed plugins in the user plugins directory."""
    plugins: list[dict[str, Any]] = []
    if not PLUGINS_DIR.exists():
        return plugins
    for plugin_dir in PLUGINS_DIR.iterdir():
        if plugin_dir.is_dir():
            from talisman.plugins.base import PluginManifest
            manifest = PluginManifest(plugin_dir).load()
            if manifest:
                plugins.append({
                    "name": manifest.get("name", plugin_dir.name),
                    "version": manifest.get("version", "unknown"),
                    "type": manifest.get("type", "scanner"),
                    "description": manifest.get("description", ""),
                    "author": manifest.get("author", ""),
                    "dir": str(plugin_dir),
                })
    return plugins


def install_plugin(source: str) -> bool:
    """Install a plugin from a directory path or GitHub URL."""
    import shutil
    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    source_path = Path(source)
    if source_path.exists() and source_path.is_dir():
        dest = PLUGINS_DIR / source_path.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(source_path, dest)
        console.print(f"  [success]✓ Plugin installed: {source_path.name}[/success]")
        return True
    console.print(f"  [error]Plugin source not found: {source}[/error]")
    return False
