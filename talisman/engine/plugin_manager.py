"""Plugin manager — discovers, registers, and bridges external plugins into the module registry."""
from __future__ import annotations
import asyncio
import importlib
import inspect
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

PLUGIN_DIRS = [
    Path.home() / ".talisman" / "plugins",
    Path(__file__).parent.parent / "plugins" / "community",
]

_plugin_registry: dict[str, dict[str, Any]] = {}


def discover_plugins() -> dict[str, dict[str, Any]]:
    """Scan plugin directories and discover all installed plugins."""
    plugins: dict[str, dict[str, Any]] = {}

    for plugin_dir in PLUGIN_DIRS:
        if not plugin_dir.exists():
            plugin_dir.mkdir(parents=True, exist_ok=True)
            continue

        for item in plugin_dir.iterdir():
            if not item.is_dir():
                continue

            manifest_path = item / "plugin.yaml"
            if not manifest_path.exists():
                continue

            try:
                import yaml
                with open(manifest_path) as f:
                    manifest = yaml.safe_load(f) or {}
            except Exception:
                continue

            plugin_name = manifest.get("name", item.name)
            entrypoint = manifest.get("entrypoint", "")
            plugin_type = manifest.get("type", "scanner")

            if not entrypoint:
                continue

            plugins[plugin_name] = {
                "name": plugin_name,
                "version": manifest.get("version", "1.0.0"),
                "author": manifest.get("author", "unknown"),
                "description": manifest.get("description", ""),
                "type": plugin_type,
                "entrypoint": entrypoint,
                "directory": str(item),
                "module_alias": manifest.get("module_alias", f"plugin.{plugin_name}"),
                "tags": manifest.get("tags", []),
                "destructive": manifest.get("destructive", False),
                "requires_auth": manifest.get("requires_auth", False),
            }

    return plugins


def load_plugin(plugin_info: dict[str, Any]) -> Callable | None:
    """Load a plugin's run() function by importing its entrypoint module."""
    entrypoint = plugin_info.get("entrypoint", "")
    if not entrypoint:
        return None

    # entrypoint format: "module_path.ClassName" or "module_path"
    parts = entrypoint.rsplit(".", 1)
    if len(parts) < 1:
        return None

    module_path = parts[0]
    class_name = parts[1] if len(parts) == 2 else None

    plugin_dir = plugin_info.get("directory", "")
    if plugin_dir and plugin_dir not in sys.path:
        sys.path.insert(0, plugin_dir)

    try:
        mod = importlib.import_module(module_path)

        if class_name:
            cls = getattr(mod, class_name)
            instance = cls()
            # Check if it has a run method
            if hasattr(instance, "run") and callable(instance.run):
                return instance.run
            # Check if it's an async generator (ScannerPlugin interface)
            if hasattr(instance, "check") and callable(instance.check):
                return instance.run  # ScannerPlugin base class provides run()
        else:
            # Module-level run function
            if hasattr(mod, "run") and callable(mod.run):
                return mod.run

    except (ImportError, AttributeError) as e:
        log.warning("plugin_load_failed", plugin=plugin_info.get("name"), error=str(e))
    except Exception as e:
        log.error("plugin_load_error", plugin=plugin_info.get("name"), error=str(e))
    finally:
        if plugin_dir and plugin_dir in sys.path:
            sys.path.remove(plugin_dir)

    return None


def register_plugins_to_registry(module_registry_map: dict[str, str]) -> dict[str, str]:
    """Discover plugins and add them to the module registry map.

    Returns an updated copy of the registry map with plugin entries added.
    """
    updated = dict(module_registry_map)
    plugins = discover_plugins()

    for plugin_name, info in plugins.items():
        alias = info.get("module_alias", f"plugin.{plugin_name}")
        fn = load_plugin(info)
        if fn:
            _plugin_registry[alias] = {"info": info, "run": fn}
            updated[alias] = f"__plugin__:{alias}"
            log.info("plugin_registered", name=plugin_name, alias=alias)

    return updated


def resolve_plugin(alias: str) -> Callable | None:
    """Resolve a plugin from the internal plugin registry."""
    entry = _plugin_registry.get(alias)
    if entry:
        return entry.get("run")
    return None


def list_plugins() -> list[dict[str, Any]]:
    """List all discovered and registered plugins."""
    plugins = discover_plugins()
    result = []
    for name, info in plugins.items():
        alias = info.get("module_alias", f"plugin.{name}")
        result.append({
            "name": name,
            "version": info["version"],
            "author": info["author"],
            "description": info["description"],
            "type": info["type"],
            "alias": alias,
            "registered": alias in _plugin_registry,
        })
    return result


async def run_plugin(alias: str, target: str, **kwargs: Any) -> dict[str, Any]:
    """Execute a plugin by its module alias."""
    fn = resolve_plugin(alias)
    if fn is None:
        return {"error": f"Plugin '{alias}' not found or not loaded"}
    try:
        if inspect.iscoroutinefunction(fn):
            return await fn(target=target, **kwargs)
        return fn(target=target, **kwargs)
    except Exception as e:
        log.error("plugin_execution_error", plugin=alias, error=str(e))
        return {"error": str(e)}


PLUGIN_REGISTRY_URL = "https://raw.githubusercontent.com/batmanguyy45-del/TALISMAN-plugins/main/registry.json"


async def search_registry(query: str = "") -> list[dict[str, Any]]:
    """Search the community plugin registry for available plugins."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(PLUGIN_REGISTRY_URL)
            if r.status_code != 200:
                return []
            registry = r.json()
            if not isinstance(registry, list):
                return []
            if query:
                q = query.lower()
                return [p for p in registry if q in p.get("name", "").lower()
                        or q in p.get("description", "").lower()
                        or q in p.get("tags", "").lower()]
            return registry
    except Exception:
        return []


def install_plugin(plugin_name: str, repo_url: str | None = None) -> dict[str, Any]:
    """Install a plugin from a Git repository or a local path."""
    target_dir = Path.home() / ".talisman" / "plugins" / plugin_name
    if target_dir.exists():
        return {"success": False, "error": f"Plugin '{plugin_name}' already installed at {target_dir}"}

    try:
        if repo_url:
            subprocess.run(
                ["git", "clone", repo_url, str(target_dir)],
                capture_output=True, text=True, check=True, timeout=60,
            )
        else:
            url = f"https://github.com/batmanguyy45-del/TALISMAN-plugins.git"
            clone_dir = Path(tempfile.mkdtemp())
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(clone_dir)],
                capture_output=True, text=True, check=True, timeout=60,
            )
            plugin_src = clone_dir / plugin_name
            if not plugin_src.exists():
                shutil.rmtree(clone_dir)
                return {"success": False, "error": f"Plugin '{plugin_name}' not found in registry"}
            shutil.copytree(plugin_src, target_dir)
            shutil.rmtree(clone_dir)

        # Verify the plugin manifest
        manifest_path = target_dir / "plugin.yaml"
        if not manifest_path.exists():
            shutil.rmtree(target_dir)
            return {"success": False, "error": "Installed plugin missing plugin.yaml"}

        import yaml
        with open(manifest_path) as f:
            manifest = yaml.safe_load(f) or {}

        return {
            "success": True,
            "name": manifest.get("name", plugin_name),
            "version": manifest.get("version", "1.0.0"),
            "author": manifest.get("author", "unknown"),
            "path": str(target_dir),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Git clone timed out"}
    except subprocess.CalledProcessError as e:
        return {"success": False, "error": f"Git clone failed: {e.stderr[:200]}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def uninstall_plugin(plugin_name: str) -> dict[str, Any]:
    """Remove an installed plugin."""
    target_dir = Path.home() / ".talisman" / "plugins" / plugin_name
    if not target_dir.exists():
        return {"success": False, "error": f"Plugin '{plugin_name}' not found"}
    try:
        shutil.rmtree(target_dir)
        return {"success": True, "name": plugin_name}
    except Exception as e:
        return {"success": False, "error": str(e)}
