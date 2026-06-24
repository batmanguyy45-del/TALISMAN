"""Chain orchestrator — reads YAML workflow chains and executes them as a DAG."""
from __future__ import annotations
import asyncio
import importlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
import yaml
from talisman.engine.session import Session
from talisman.engine.scope import ScopeEnforcer, ScopeConfig
from talisman.engine.rate_limiter import RateLimiter, RATE_PROFILES
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)
CHAINS_DIR = Path(__file__).parent.parent.parent / "chains"

@dataclass
class ChainStep:
 id: str
 module: str
 args: dict[str, Any] = field(default_factory=dict)
 depends_on: list[str] = field(default_factory=list)
 parallel: bool = False
 condition: str | None = None
 output_key: str | None = None
 on_error: str = "stop" # stop | continue | warn

@dataclass
class Chain:
 name: str
 description: str
 steps: list[ChainStep]
 rate_profile: str = "normal"
 variables: dict[str, Any] = field(default_factory=dict)
 version: str = "1.0"
 tags: list[str] = field(default_factory=list)

 @classmethod
 def from_yaml(cls, path: Path) -> "Chain":
  with open(path) as f:
   data = yaml.safe_load(f)
  steps = []
  for s in data.get("steps", []):
   if isinstance(s, str):
    steps.append(ChainStep(id=s, module=s))
   elif isinstance(s, dict):
    steps.append(ChainStep(
     id=s.get("id", s.get("module", "unknown")),
     module=s.get("module", s.get("id", "")),
     args=s.get("args", {}),
     depends_on=s.get("depends_on", []),
     parallel=s.get("parallel", False),
     condition=s.get("condition"),
     output_key=s.get("output", {}).get("key") if isinstance(s.get("output"), dict) else None,
     on_error=s.get("on_error", "stop"),
    ))
  return cls(
   name=data.get("name", path.stem),
   description=data.get("description", ""),
   steps=steps,
   rate_profile=data.get("rate_profile", "normal"),
   variables=data.get("variables", {}),
   version=data.get("version", "1.0"),
   tags=data.get("tags", []),
  )

class ModuleRegistry:
 """Resolves module path strings to async callable functions."""
 MODULE_MAP: dict[str, str] = {
   "recon.subdomain":   "talisman.modules.recon.subdomain",
   "recon.dns":    "talisman.modules.recon.dns",
   "recon.ports":    "talisman.modules.recon.port_scanner",
   "recon.crawl":    "talisman.modules.recon.web_crawler",
   "recon.tech":    "talisman.modules.recon.tech_detect",
   "recon.osint":    "talisman.modules.recon.osint",
   "recon.whois":    "talisman.modules.recon.whois_asn",
   "scanner.xss":    "talisman.modules.scanner.xss",
   "scanner.sqli":    "talisman.modules.scanner.sqli",
   "scanner.ssrf":    "talisman.modules.scanner.ssrf",
   "scanner.xxe":    "talisman.modules.scanner.xxe",
   "scanner.ssti":    "talisman.modules.scanner.ssti",
   "scanner.lfi":    "talisman.modules.scanner.lfi_rfi",
   "scanner.cmdi":    "talisman.modules.scanner.cmdi",
   "scanner.headers":   "talisman.modules.scanner.headers",
   "scanner.cors":    "talisman.modules.scanner.cors",
   "scanner.auth":    "talisman.modules.scanner.auth",
   "scanner.idor":    "talisman.modules.scanner.idor",
   "scanner.smuggling":  "talisman.modules.scanner.smuggling",
   "scanner.smuggle":   "talisman.modules.scanner.smuggling",
   "scanner.cache":    "talisman.modules.scanner.cache_poison",
   "scanner.cache_poison": "talisman.modules.scanner.cache_poison",
   "scanner.redirect":   "talisman.modules.scanner.open_redirect",
   "scanner.open_redirect": "talisman.modules.scanner.open_redirect",
   "scanner.proto":    "talisman.modules.scanner.prototype",
   "scanner.prototype":   "talisman.modules.scanner.prototype",
   "scanner.nosqli":    "talisman.modules.scanner.nosqli",
   "scanner.deserialize":  "talisman.modules.scanner.deserialization",
   "scanner.websocket":   "talisman.modules.scanner.websocket",
   "scanner.crlf":    "talisman.modules.scanner.crlf",
   "scanner.nuclei":    "talisman.modules.scanner.nuclei_runner",
   "scanner.bizlogic":    "talisman.modules.scanner.business_logic",
   "scanner.business_logic": "talisman.modules.scanner.business_logic",
   "scanner.race":    "talisman.modules.scanner.race_condition",
   "scanner.race_condition": "talisman.modules.scanner.race_condition",
   "scanner.log4shell":   "talisman.modules.scanner.log4shell",
   "scanner.mfa":    "talisman.modules.scanner.mfa_bypass",
   "scanner.mfa_bypass":  "talisman.modules.scanner.mfa_bypass",
   "waf.detector":    "talisman.modules.waf.detector",
   "waf.bypass":    "talisman.modules.waf.bypass_engine",
   "waf.origin":    "talisman.modules.waf.vendors.cloudflare",
   "api.swagger":    "talisman.modules.api.swagger_audit",
   "api.graphql":    "talisman.modules.api.graphql",
   "api.jwt":     "talisman.modules.api.jwt",
   "api.oauth":    "talisman.modules.api.oauth",
   "cloud.aws":    "talisman.modules.cloud.aws",
   "cloud.gcp":    "talisman.modules.cloud.gcp",
   "cloud.azure":    "talisman.modules.cloud.azure",
   "cloud.secrets":   "talisman.modules.cloud.secrets",
   "misconfig.server":   "talisman.modules.misconfiguration.server_misconfig",
   "misconfig.spring":   "talisman.modules.misconfiguration.spring_misconfig",
   "misconfig.kubernetes":  "talisman.modules.misconfiguration.kubernetes_misconfig",
   "misconfig.database":  "talisman.modules.misconfiguration.database_exposure",
   "misconfig.nginx":   "talisman.modules.misconfiguration.nginx_misconfig",
   "network.takeover":   "talisman.modules.network.takeover",
   "network.ssl":    "talisman.modules.network.ssl_tls",
   "cms.wordpress":   "talisman.modules.cms.wordpress.core",
   "cms.wordpress.plugins": "talisman.modules.cms.wordpress.plugins",
   "cms.wordpress.xmlrpc":  "talisman.modules.cms.wordpress.xmlrpc",
   "ad.recon":     "talisman.modules.activedirectory.ad_recon",
   "ad.kerberos":    "talisman.modules.activedirectory.kerberos",
   "ad.smb":     "talisman.modules.activedirectory.smb_audit",
  }

 @classmethod
 def resolve(cls, module_path: str) -> Callable:
  mapped = cls.MODULE_MAP.get(module_path)
  if mapped is None:
   mapped = "talisman.modules." + module_path
  # First attempt: import the full module path directly and get its run function
  try:
   mod = importlib.import_module(mapped)
   return getattr(mod, "run", None)
  except (ImportError, AttributeError):
   pass
  # Fallback: import parent package and look for module name as attribute
  parts = mapped.rsplit(".", 1)
  if len(parts) == 2:
   mod_path, fn_name = parts
  else:
   mod_path, fn_name = parts[0], "run"
  try:
   mod = importlib.import_module(mod_path)
   return getattr(mod, fn_name, getattr(mod, "run", None))
  except (ImportError, AttributeError) as e:
   log.warning("module_not_found", module=module_path, error=str(e))
   return None


class ChainOrchestrator:
 def __init__(
  self,
  session: Session,
  scope: ScopeEnforcer,
  rate_profile: str = "normal",
  proxy: str | None = None,
  dry_run: bool = False,
  notify_fn: Callable | None = None,
 ):
  self.session = session
  self.scope = scope
  self.rate_limiter = RateLimiter(rate_profile)
  self.proxy = proxy
  self.dry_run = dry_run
  self.notify_fn = notify_fn
  self._step_outputs: dict[str, Any] = {}

 @staticmethod
 def load_chain(name: str) -> Chain:
  candidates = [
   CHAINS_DIR / f"{name}.yaml",
   CHAINS_DIR / f"{name}.yml",
   Path(name) if Path(name).exists() else None,
  ]
  for path in candidates:
   if path and path.exists():
    return Chain.from_yaml(path)
  raise FileNotFoundError(f"Chain '{name}' not found in {CHAINS_DIR}")

 @staticmethod
 def list_chains() -> list[dict[str, str]]:
  chains = []
  if CHAINS_DIR.exists():
   for path in sorted(CHAINS_DIR.glob("*.yaml")):
    try:
     c = Chain.from_yaml(path)
     chains.append({"name": c.name, "description": c.description, "tags": ",".join(c.tags)})
    except Exception:
     chains.append({"name": path.stem, "description": "Parse error", "tags": ""})
  return chains

 def _resolve_template(self, value: Any, context: dict[str, Any]) -> Any:
  if isinstance(value, str):
   for k, v in context.items():
    value = value.replace(f"{{{{ {k} }}}}", str(v))
    value = value.replace(f"{{{{{k}}}}}", str(v))
   return value
  if isinstance(value, dict):
   return {k: self._resolve_template(v, context) for k, v in value.items()}
  if isinstance(value, list):
   return [self._resolve_template(i, context) for i in value]
  return value

 async def _execute_step(
  self, step: ChainStep, target: str, context: dict[str, Any]
 ) -> Any:
  resolved_args = self._resolve_template(step.args, context)
  log.info("chain_step_start", step=step.id, module=step.module, target=target)
  if self.dry_run:
   console.print(f" [dim][DRY RUN] Would run: {step.module} on {target}[/dim]")
   return {}
  fn = ModuleRegistry.resolve(step.module)
  if fn is None:
   log.warning("module_unavailable", step=step.id, module=step.module)
   return {}
  run_id = await self.session.start_module_run(step.module, target)
  start = time.monotonic()
  try:
   result = await fn(
    target=target,
    session=self.session,
    scope=self.scope,
    rate_limiter=self.rate_limiter,
    proxy=self.proxy,
    **resolved_args,
   )
   elapsed = time.monotonic() - start
   await self.session.complete_module_run(
    run_id, status="success",
    summary=f"Completed in {elapsed:.1f}s"
   )
   log.info("chain_step_done", step=step.id, elapsed=f"{elapsed:.1f}s")
   return result or {}
  except Exception as e:
   elapsed = time.monotonic() - start
   log.error("chain_step_error", step=step.id, error=str(e))
   await self.session.complete_module_run(run_id, status="error", error=str(e))
   if step.on_error == "stop":
    raise
   return {}

 async def run(self, chain: Chain, target: str) -> dict[str, Any]:
  console.print(f"\n[chain]> Chain: {chain.name}[/chain] on [target]{target}[/target]\n")
  context: dict[str, Any] = {
   "target": target,
   "session": self.session.name,
   **chain.variables,
  }
  completed: set[str] = set()
  self._step_outputs = {}
  pending = list(chain.steps)
  start_time = time.monotonic()
  while pending:
   ready = [
    s for s in pending
    if all(dep in completed for dep in s.depends_on)
   ]
   if not ready:
    log.error("chain_deadlock", pending=[s.id for s in pending])
    break
   parallel_steps = [s for s in ready if s.parallel]
   sequential_steps = [s for s in ready if not s.parallel]
   if parallel_steps:
    tasks = [
     self._execute_step(s, target, {**context, "steps": self._step_outputs})
     for s in parallel_steps
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for step, result in zip(parallel_steps, results):
     if isinstance(result, Exception):
      log.error("parallel_step_failed", step=step.id, error=str(result))
      if step.on_error == "stop":
       raise result
     else:
      if step.output_key:
       self._step_outputs[step.output_key] = result
      self._step_outputs[step.id] = result
     completed.add(step.id)
     pending.remove(step)
   for step in sequential_steps:
    ctx = {**context, "steps": self._step_outputs}
    result = await self._execute_step(step, target, ctx)
    if step.output_key:
     self._step_outputs[step.output_key] = result
    self._step_outputs[step.id] = result
    completed.add(step.id)
    pending.remove(step)
  elapsed = time.monotonic() - start_time
  summary = await self.session.summary()
  console.print(f"\n[success][+] Chain '{chain.name}' complete in {elapsed:.1f}s[/success]")
  console.print(f" Findings: {summary['findings']}")
  if self.notify_fn:
   await self.notify_fn(f"Chain {chain.name} complete on {target}: {summary['findings']}")
  return self._step_outputs
