"""Plugin manager — discovers, registers, and bridges external plugins into the module registry."""
from __future__ import annotations

import importlib
import inspect
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from talisman.utils.logger import get_logger

log = get_logger(__name__)

PLUGIN_DIRS = [
    Path.home() / ".talisman" / "plugins",
    Path(__file__).parent.parent / "plugins" / "community",
]

_plugin_registry: dict[str, dict[str, Any]] = {}
_PLUGIN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MODULE_PATH_RE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")
_ALIAS_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_PLUGIN_OPT_IN = "TALISMAN_ENABLE_UNTRUSTED_PLUGINS"


def _validate_plugin_name(name: str) -> str:
    if not isinstance(name, str) or not _PLUGIN_NAME_RE.fullmatch(name):
        raise ValueError("Invalid plugin name; use 1-64 letters, digits, dots, underscores or hyphens")
    if name in {".", ".."}:
        raise ValueError("Invalid plugin name")
    return name


def _validate_repo_url(repo_url: str) -> str:
    parsed = urlsplit(repo_url)
    segments = [segment for segment in parsed.path.split("/") if segment]
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or len(segments) != 2
        or any(not _PLUGIN_NAME_RE.fullmatch(segment.removesuffix(".git")) for segment in segments)
    ):
        raise ValueError("Plugin repositories must be HTTPS GitHub URLs in owner/repository form")
    return repo_url


def _validated_manifest(manifest: Any, fallback_name: str) -> dict[str, Any] | None:
    if not isinstance(manifest, dict):
        return None
    name = manifest.get("name", fallback_name)
    entrypoint = manifest.get("entrypoint")
    plugin_type = manifest.get("type", "scanner")
    alias = manifest.get("module_alias", f"plugin.{name}")
    if not isinstance(name, str) or not _PLUGIN_NAME_RE.fullmatch(name):
        return None
    if not isinstance(entrypoint, str) or not _MODULE_PATH_RE.fullmatch(entrypoint):
        return None
    if plugin_type not in {"scanner", "recon"}:
        return None
    if not isinstance(alias, str) or not _ALIAS_RE.fullmatch(alias):
        return None
    tags = manifest.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        return None
    for flag in ("destructive", "requires_auth"):
        if flag in manifest and not isinstance(manifest[flag], bool):
            return None
    return {
        "name": name,
        "version": str(manifest.get("version", "1.0.0"))[:64],
        "author": str(manifest.get("author", "unknown"))[:128],
        "description": str(manifest.get("description", ""))[:1000],
        "type": plugin_type,
        "entrypoint": entrypoint,
        "module_alias": alias,
        "tags": tags[:32],
        "destructive": manifest.get("destructive", False),
        "requires_auth": manifest.get("requires_auth", False),
    }


def _untrusted_plugins_enabled() -> bool:
    return os.environ.get(_PLUGIN_OPT_IN, "").strip().lower() in {"1", "true", "yes"}

def _contains_symlinks(root: Path) -> bool:
    """Reject plugin trees containing file or directory symlinks."""
    for current, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            if (Path(current) / name).is_symlink():
                return True
    return False




def discover_plugins() -> dict[str, dict[str, Any]]:
    """Discover manifests without importing or executing plugin code."""
    plugins: dict[str, dict[str, Any]] = {}

    for configured_root in PLUGIN_DIRS:
        root = configured_root.expanduser()
        if not root.exists():
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.is_symlink() or not root.is_dir():
            continue
        resolved_root = root.resolve()

        for item in root.iterdir():
            if item.is_symlink() or not item.is_dir():
                continue
            manifest_path = item / "plugin.yaml"
            if manifest_path.is_symlink() or not manifest_path.is_file():
                continue

            try:
                import yaml

                with manifest_path.open(encoding="utf-8") as handle:
                    raw_manifest = yaml.safe_load(handle)
                manifest = _validated_manifest(raw_manifest, item.name)
            except Exception as exc:
                log.warning(
                    "plugin_manifest_rejected",
                    path=str(manifest_path),
                    error=type(exc).__name__,
                )
                continue

            if manifest is None:
                log.warning("plugin_manifest_rejected", path=str(manifest_path))
                continue

            resolved_item = item.resolve()
            if not resolved_item.is_relative_to(resolved_root):
                continue

            plugins[manifest["name"]] = {
                **manifest,
                "directory": str(resolved_item),
            }

    return plugins


def load_plugin(plugin_info: dict[str, Any]) -> Callable | None:
    """Load a reviewed plugin only after explicit trust opt-in."""
    if not _untrusted_plugins_enabled():
        return None

    manifest = _validated_manifest(plugin_info, str(plugin_info.get("name", "")))
    if manifest is None:
        return None

    configured_dir = plugin_info.get("directory")
    if not isinstance(configured_dir, str) or not configured_dir:
        return None

    try:
        plugin_dir = Path(configured_dir).resolve(strict=True)
        allowed_roots = [
            root.expanduser().resolve(strict=True)
            for root in PLUGIN_DIRS
            if root.expanduser().exists() and not root.expanduser().is_symlink()
        ]
    except OSError:
        return None

    if not plugin_dir.is_dir() or not any(
        plugin_dir != root and plugin_dir.is_relative_to(root)
        for root in allowed_roots
    ):
        log.warning("plugin_directory_rejected", plugin=manifest["name"])
        return None

    entrypoint = manifest["entrypoint"]
    parts = entrypoint.split(".")
    if len(parts) < 2:
        return None
    module_path = ".".join(parts[:-1])
    class_name = parts[-1]
    if not _MODULE_PATH_RE.fullmatch(module_path) or not class_name.isidentifier():
        return None

    plugin_path = str(plugin_dir)
    if plugin_path in sys.path:
        sys.path.remove(plugin_path)
    sys.path.insert(0, plugin_path)
    try:
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name, None)
        if cls is None or not callable(cls):
            return None
        instance = cls()
        run_method = getattr(instance, "run", None)
        if callable(run_method):
            return run_method
        log.warning("plugin_entrypoint_missing_run", plugin=manifest["name"])
    except Exception as exc:
        log.warning(
            "plugin_load_failed",
            plugin=manifest["name"],
            error=type(exc).__name__,
        )
    finally:
        if plugin_path in sys.path:
            sys.path.remove(plugin_path)

    return None


def register_plugins_to_registry(module_registry_map: dict[str, str]) -> dict[str, str]:
    """Discover plugins and add them to the module registry map.

    Returns an updated copy of the registry map with plugin entries added.
    """
    updated = dict(module_registry_map)
    if not _untrusted_plugins_enabled():
        log.warning(
            "plugin_autoload_disabled",
            message=(
                "Community plugins are untrusted code. Set "
                "TALISMAN_ENABLE_UNTRUSTED_PLUGINS=1 only after reviewing "
                "installed plugins."
            ),
        )
        return updated

    plugins = discover_plugins()

    for plugin_name, info in plugins.items():
        alias = info.get("module_alias", f"plugin.{plugin_name}")
        if alias in updated and not alias.startswith("plugin."):
            log.warning("plugin_alias_conflict", name=plugin_name, alias=alias)
            continue
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
    """Install a plugin from the trusted registry or an HTTPS GitHub repository."""
    try:
        plugin_name = _validate_plugin_name(plugin_name)
        source_url = _validate_repo_url(
            repo_url or "https://github.com/batmanguyy45-del/TALISMAN-plugins"
        )
        root = Path.home() / ".talisman" / "plugins"
        if root.is_symlink():
            return {"success": False, "error": "Plugin directory must not be a symbolic link"}
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root = root.resolve()
        target_dir = root / plugin_name
        if target_dir.exists() or target_dir.is_symlink():
            return {
                "success": False,
                "error": f"Plugin '{plugin_name}' already exists",
            }

        with tempfile.TemporaryDirectory(prefix="talisman-plugin-") as temp_dir:
            clone_dir = Path(temp_dir) / "repository"
            git_environment = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(Path.home()),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ALLOW_PROTOCOL": "https",
                "GIT_LFS_SKIP_SMUDGE": "1",
            }
            subprocess.run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "http.followRedirects=false",
                    "-c",
                    "credential.helper=",
                    "clone",
                    "--depth",
                    "1",
                    "--single-branch",
                    "--",
                    source_url,
                    str(clone_dir),
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=60,
                env=git_environment,
            )

            plugin_src = clone_dir if repo_url else clone_dir / plugin_name
            if plugin_src.is_symlink() or not plugin_src.is_dir():
                return {
                    "success": False,
                    "error": f"Plugin '{plugin_name}' not found in repository",
                }

            if _contains_symlinks(plugin_src):
                return {"success": False, "error": "Plugin tree contains symlinks"}

            manifest_path = plugin_src / "plugin.yaml"
            if manifest_path.is_symlink() or not manifest_path.is_file():
                return {"success": False, "error": "Plugin is missing plugin.yaml"}

            import yaml

            with manifest_path.open(encoding="utf-8") as handle:
                raw_manifest = yaml.safe_load(handle)
            manifest = _validated_manifest(raw_manifest, plugin_name)
            if manifest is None or manifest["name"] != plugin_name:
                return {"success": False, "error": "Plugin manifest failed validation"}

            shutil.copytree(plugin_src, target_dir, symlinks=False)
            os.chmod(target_dir, 0o700)

        return {
            "success": True,
            "name": manifest["name"],
            "version": manifest["version"],
            "author": manifest["author"],
            "path": str(target_dir),
            "requires_review": True,
            "execution_enabled": False,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Git clone timed out"}
    except subprocess.CalledProcessError as exc:
        return {
            "success": False,
            "error": f"Git clone failed: {str(exc.stderr or '')[:200]}",
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def uninstall_plugin(plugin_name: str) -> dict[str, Any]:
    """Remove an installed plugin directory without following symlinks."""
    try:
        plugin_name = _validate_plugin_name(plugin_name)
        root = Path.home() / ".talisman" / "plugins"
        if root.is_symlink():
            return {"success": False, "error": "Plugin directory must not be a symbolic link"}
        target_dir = root / plugin_name
        if target_dir.is_symlink():
            return {"success": False, "error": "Plugin directory must not be a symbolic link"}
        if not target_dir.exists():
            return {"success": False, "error": f"Plugin '{plugin_name}' not found"}
        resolved_root = root.resolve(strict=True)
        resolved_target = target_dir.resolve(strict=True)
        if resolved_target.parent != resolved_root:
            return {"success": False, "error": "Plugin path escaped the plugin directory"}
        shutil.rmtree(resolved_target)
        _plugin_registry.pop(f"plugin.{plugin_name}", None)
        return {"success": True, "name": plugin_name}
    except Exception as exc:
        return {"success": False, "error": str(exc)}
