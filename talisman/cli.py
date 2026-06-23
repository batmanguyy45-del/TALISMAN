"""
TALISMAN CLI — Advanced Bug Bounty & Security Research Platform
Author: MR MARCUS TAYK | Version: 1.0.0
"""
from __future__ import annotations
import asyncio, json, sys
from pathlib import Path
from typing import Optional
import typer
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from talisman import __version__
from talisman.utils.logger import setup_logging, console, print_banner
from talisman.engine.session import SessionManager
from talisman.engine.scope import ScopeEnforcer, ScopeConfig
from talisman.engine.rate_limiter import RateLimiter, RATE_PROFILES
from talisman.engine.orchestrator import ChainOrchestrator

app = typer.Typer(
 name="talisman",
 help=(
  "[T] TALISMAN — Advanced Bug Bounty & Security Research Platform\n\n"
  "[bold]Author:[/bold] MR MARCUS TAYK | [bold]Version:[/bold] 1.0.0\n\n"
  "[bold yellow]AUTHORIZED USE ONLY[/bold yellow] — Use only on systems you own or have written permission to test.\n\n"
  "[bold]Quick Start:[/bold]\n"
  " talisman init           # First-time setup\n"
  " talisman autopilot -t example.com -s my-session  # Full automated scan\n"
  " talisman recon subdomain -t example.com -s bounty  # Subdomain enum\n"
  " talisman scan all -t https://example.com -s bounty # All vuln scanners\n"
  " talisman chain run full_recon -t example.com -s b  # YAML chain\n"
  " talisman report generate my-session --format html  # HTML report\n"
  " talisman session findings my-session --severity high # View findings"
 ),
 rich_markup_mode="rich",
 no_args_is_help=True,
 context_settings={"help_option_names": ["--help", "-h"]},
)

recon_app  = typer.Typer(help="Reconnaissance — subdomain, DNS, crawl, OSINT, tech, ports", no_args_is_help=True)
scan_app  = typer.Typer(help="Vulnerability scanners — XSS, SQLi, SSRF, CMDi, SSTI, LFI, XXE, +more", no_args_is_help=True)
fuzz_app  = typer.Typer(help="Fuzzing — path/directory brute force, parameter discovery", no_args_is_help=True)
api_app  = typer.Typer(help="API security — GraphQL, JWT, OAuth 2.0, Swagger/OpenAPI", no_args_is_help=True)
cloud_app  = typer.Typer(help="Cloud security — AWS S3, CloudFront, secrets, GCP, Azure", no_args_is_help=True)
misconfig_app = typer.Typer(help="Misconfiguration — Spring Boot, Kubernetes, databases, Nginx/Apache/IIS", no_args_is_help=True)
waf_app  = typer.Typer(help="WAF — fingerprint 12 vendors, Cloudflare origin finder, bypass payloads", no_args_is_help=True)
chain_app  = typer.Typer(help="Chain orchestrator — YAML workflows: full_recon, web_vuln_scan, wordpress_full, +more", no_args_is_help=True)
session_app = typer.Typer(help="Session management — list, findings, summary, notes, delete", no_args_is_help=True)
report_app = typer.Typer(help="Reports — HTML (dark theme), Markdown (HackerOne/Bugcrowd), JSON", no_args_is_help=True)
cms_app  = typer.Typer(help="CMS — WordPress deep audit (version, plugins, users, XML-RPC, REST API)", no_args_is_help=True)
ad_app  = typer.Typer(help="Active Directory — LDAP enum, Kerberoasting, SMB, password spray, AD CS", no_args_is_help=True)
intel_app  = typer.Typer(help="Intelligence — CVE lookup, CVSS scoring, knowledge base", no_args_is_help=True)

for _name, _sub in [
 ("recon", recon_app), ("scan", scan_app), ("fuzz", fuzz_app),
 ("api", api_app), ("cloud", cloud_app), ("misconfig", misconfig_app),
 ("waf", waf_app), ("chain", chain_app), ("session", session_app),
 ("report", report_app), ("cms", cms_app), ("ad", ad_app), ("intel", intel_app),
]:
 app.add_typer(_sub, name=_name)

def _run(coro):
 try:
  asyncio.run(coro)
 except KeyboardInterrupt:
  console.print("\n[yellow][!] Interrupted[/yellow]")
  sys.exit(0)

async def _session_scope(session_name, target, scope_file):
 sm = SessionManager()
 sess = sm.get(session_name)
 await sess.open()
 cfg = ScopeConfig.from_file(scope_file) if scope_file and scope_file.exists() else ScopeConfig.from_target(target)
 return sess, ScopeEnforcer(cfg)

PROFILE_HELP = (
 "Rate profile for scan speed/stealth:\n"
 " aggressive — 200 req/s, 50 concurrent (internal/dev)\n"
 " normal  — 50 req/s, 20 concurrent (standard bug bounty) [default]\n"
 " stealth — 10 req/s, 5 concurrent (WAF-protected/production)\n"
 " passive — 5 req/s, 2 concurrent (highly monitored)"
)

# ── init ──────────────────────────────────────────────────────────────────────
@app.command("init")
def cmd_init():
 """
 Initialize TALISMAN — create config directories and check external tools.

 \b
 Run once after installation: talisman init
 Creates: ~/.talisman/{sessions,wordlists,templates,plugins,reports}
 Checks for: subfinder, nuclei, httpx, ffuf, amass, nmap, masscan, feroxbuster
 """
 print_banner()
 import shutil
 home = Path.home() / ".talisman"
 for d in ["sessions", "wordlists", "templates", "plugins", "reports"]:
  (home / d).mkdir(parents=True, exist_ok=True)
 console.print(f"[bold green][+] Directories created:[/bold green] {home}")
 tools = [
  ("subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
  ("nuclei",  "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
  ("httpx",  "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
  ("ffuf",  "go install github.com/ffuf/ffuf/v2@latest"),
  ("amass",  "go install github.com/owasp-amass/amass/v4/...@latest"),
  ("nmap",  "sudo apt install nmap"),
  ("masscan",  "sudo apt install masscan"),
  ("feroxbuster", "cargo install feroxbuster"),
 ]
 t = Table(title="External Tools", style="cyan", border_style="dim")
 t.add_column("Tool"); t.add_column("Status"); t.add_column("Install Command", style="dim")
 for tool, cmd in tools:
  path = shutil.which(tool)
  t.add_row(tool, f"[green][+] {path}[/green]" if path else "[yellow][-] Not found (optional)[/yellow]", "" if path else cmd)
 console.print(t)
 console.print("\n[bold green][+] TALISMAN ready![/bold green] Run: [cyan]talisman --help[/cyan]")
 console.print("[dim]Author: MR MARCUS TAYK | TALISMAN v1.0.0[/dim]")

@app.command("version")
def cmd_version():
 """Show version and author info."""
 console.print(Panel(
  f"[bold cyan]TALISMAN[/bold cyan] v{__version__}\n"
  f"[dim]Threat Analysis, Lateral Intelligence & Security Management[/dim]\n"
  f"[bold]Author:[/bold] MR MARCUS TAYK\n"
  f"[bold]License:[/bold] MIT | Authorized testing only",
  title="[T] TALISMAN", border_style="cyan",
 ))

# ── autopilot ──────────────────────────────────────────────────────────────────
@app.command("autopilot")
def cmd_autopilot(
 target: str = typer.Option(..., "-t", "--target",
  help="Target URL, domain, or IP.\n\nExamples: example.com | https://app.example.com | 192.168.1.1"),
 session_name: str = typer.Option("default", "-s", "--session",
  help="Session name for storing findings.\n\nExample: -s bounty-q1"),
 profile: str = typer.Option("normal", "-p", "--profile", help=PROFILE_HELP),
 proxy: Optional[str] = typer.Option(None, "--proxy",
  help="Proxy URL.\n\nExamples: http://127.0.0.1:8080 (Burp) | socks5://127.0.0.1:9050"),
 scope_file: Optional[Path] = typer.Option(None, "--scope",
  help="Scope YAML file.\n\nExample: --scope ./scope.yaml"),
 oast: Optional[str] = typer.Option(None, "--oast",
  help="OAST domain for OOB detection (SSRF, XXE, CMDi, Log4Shell).\n\nExample: --oast oastify.com"),
 report: bool = typer.Option(True, "--report/--no-report",
  help="Auto-generate HTML+Markdown+JSON report on completion."),
 wp_scan: bool = typer.Option(True, "--wordpress/--no-wordpress",
  help="Enable WordPress deep audit when WordPress is detected."),
 secrets: bool = typer.Option(True, "--secrets/--no-secrets",
  help="Enable secret scanning across JS/HTML/config files."),
 debug: bool = typer.Option(False, "--debug", help="Enable verbose debug logging."),
):
 """
 [AUTO] AUTOPILOT — Full automated security assessment in one command.

 \b
 Workflow:
  Phase 1 — Technology fingerprinting & WAF detection
  Phase 2 — Web crawling & JS endpoint extraction
  Phase 3 — OSINT (emails, S3 buckets, GitHub dorks)
  Phase 4 — All vulnerability scanners (XSS, SQLi, SSRF, CMDi, SSTI, LFI,
     CORS, headers, cache poisoning, IDOR, smuggling, auth, bizlogic)
  Phase 5 — WordPress deep audit (if WordPress detected)
  Phase 6 — Secret scanning (API keys, tokens, credentials)
  Phase 7 — Report generation (HTML + Markdown + JSON)

 \b
 Examples:
  # Standard bug bounty run
  talisman autopilot -t example.com -s bounty-q1

  # Stealth with Burp Suite + OAST
  talisman autopilot -t https://app.example.com -s test \\
  --proxy http://127.0.0.1:8080 --oast oastify.com --profile stealth

  # Aggressive internal scan
  talisman autopilot -t 192.168.1.0/24 -s internal --profile aggressive

  # Scoped scan with scope file
  talisman autopilot -t example.com -s bounty \\
  --scope ./scope.yaml --profile normal

  # Skip report generation
  talisman autopilot -t example.com -s quick --no-report

 \b
 Rate Profiles:
  aggressive 200 req/s 50 concurrent (internal/dev targets)
  normal  50 req/s 20 concurrent (standard bug bounty) [DEFAULT]
  stealth  10 req/s 5 concurrent (WAF-protected/production)
  passive  5 req/s 2 concurrent (highly monitored)
 """
 setup_logging("DEBUG" if debug else "INFO")
 print_banner()
 if profile not in RATE_PROFILES:
  console.print(f"[red]Invalid profile '{profile}'. Choose: {', '.join(RATE_PROFILES.keys())}[/red]")
  raise typer.Exit(1)
 console.print(Panel(
  f"[bold cyan]Target:[/bold cyan] {target}\n"
  f"[bold cyan]Session:[/bold cyan] {session_name}\n"
  f"[bold cyan]Profile:[/bold cyan] {profile} "
  f"[bold cyan]Proxy:[/bold cyan] {proxy or 'none'} "
  f"[bold cyan]OAST:[/bold cyan] {oast or 'none'}",
  title="[AUTO] TALISMAN AUTOPILOT — MR MARCUS TAYK", border_style="cyan",
 ))
 async def _run_async():
  sess, scope = await _session_scope(session_name, target, scope_file)
  rl = RateLimiter(profile)
  common = dict(session=sess, scope=scope, rate_limiter=rl, proxy=proxy, oast_domain=oast)
  import importlib
  async with sess:
   scanners = [
    ("tech_detect",  "talisman.modules.recon.tech_detect"),
    ("web_crawler",  "talisman.modules.recon.web_crawler"),
    ("osint",   "talisman.modules.recon.osint"),
    ("headers",   "talisman.modules.scanner.headers"),
    ("cors",   "talisman.modules.scanner.cors"),
    ("xss",    "talisman.modules.scanner.xss"),
    ("sqli",   "talisman.modules.scanner.sqli"),
    ("ssrf",   "talisman.modules.scanner.ssrf"),
    ("cmdi",   "talisman.modules.scanner.cmdi"),
    ("ssti",   "talisman.modules.scanner.ssti"),
    ("lfi",    "talisman.modules.scanner.lfi_rfi"),
    ("open_redirect", "talisman.modules.scanner.open_redirect"),
    ("cache_poison", "talisman.modules.scanner.cache_poison"),
    ("idor",   "talisman.modules.scanner.idor"),
    ("prototype",  "talisman.modules.scanner.prototype"),
    ("smuggling",  "talisman.modules.scanner.smuggling"),
    ("auth",   "talisman.modules.scanner.auth"),
    ("business_logic", "talisman.modules.scanner.business_logic"),
    ("server_misconfig","talisman.modules.misconfiguration.server_misconfig"),
   ]
   if oast:
    scanners += [
     ("xxe",  "talisman.modules.scanner.xxe"),
     ("log4shell", "talisman.modules.scanner.log4shell"),
    ]
   tech_result = {}
   for name, mod_path in scanners:
    try:
     mod = importlib.import_module(mod_path)
     r = await mod.run(target=target, **common)
     if name == "tech_detect" and isinstance(r, dict):
      tech_result = r
    except Exception as e:
     console.print(f" [dim]{name}: {e}[/dim]")
   # WordPress
   if wp_scan and any("WordPress" in t for t in tech_result.get("technologies", [])):
    console.print("\n[bold cyan]━━ WordPress Deep Audit[/bold cyan]")
    for mod_path in [
     "talisman.modules.cms.wordpress.core",
     "talisman.modules.cms.wordpress.users",
     "talisman.modules.cms.wordpress.plugins",
     "talisman.modules.cms.wordpress.xmlrpc",
    ]:
     try:
      mod = importlib.import_module(mod_path)
      await mod.run(target=target, **common)
     except Exception as e:
      console.print(f" [dim]{mod_path.split('.')[-1]}: {e}[/dim]")
   # Secrets
   if secrets:
    try:
     mod = importlib.import_module("talisman.modules.cloud.secrets")
     await mod.run(target=target, **common)
    except Exception as e:
     console.print(f" [dim]secrets: {e}[/dim]")
   summary = await sess.summary()
   f = summary["findings"]
   console.print(Panel(
    f"[bold red]Critical:[/bold red] {f.get('critical',0)} "
    f"[bold orange3]High:[/bold orange3] {f.get('high',0)} "
    f"[bold yellow]Medium:[/bold yellow] {f.get('medium',0)} "
    f"[bold blue]Low:[/bold blue] {f.get('low',0)}\n"
    f"[bold]Total:[/bold] {summary['total_findings']}",
    title="[OK] Autopilot Complete", border_style="green",
   ))
   if report:
    try:
     from talisman.output.report_engine import ReportEngine
     findings = await sess.get_findings()
     targets = await sess.get_targets()
     engine = ReportEngine(session_name, findings, targets, Path("./reports"))
     outputs = engine.generate_all(["html", "markdown", "json"])
     for o in outputs:
      console.print(f" [green][+][/green] {o}")
    except Exception as e:
     console.print(f" [dim]Report: {e}[/dim]")
 _run(_run_async())

@app.command("takeover")
def cmd_takeover(
 target: str = typer.Option(..., "-t", "--target", help="Target domain or subdomain"),
 session_name: str = typer.Option("default", "-s", "--session", help="Session name"),
 proxy: Optional[str] = typer.Option(None, "--proxy", help="Proxy URL"),
 subdomains_file: Optional[str] = typer.Option(None, "--subdomains",
  help="File with subdomains to check in bulk (one per line)"),
):
 """
 Subdomain takeover — 40+ service signatures (GitHub Pages, Heroku, Netlify, Vercel, +more).

 \b
 Examples:
  talisman takeover -t sub.example.com -s bounty
  talisman takeover -t example.com --subdomains ./subs.txt -s bounty
 """
 print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  subs = [target]
  if subdomains_file:
   try:
    with open(subdomains_file) as f:
     subs = [l.strip() for l in f if l.strip()]
    console.print(f" Loaded {len(subs)} subdomains")
   except Exception as e:
    console.print(f" [red]{e}[/red]")
  from talisman.modules.network.takeover import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy, subdomains=subs)
 _run(_r())

# ── RECON ─────────────────────────────────────────────────────────────────────
@recon_app.command("subdomain")
def recon_subdomain(
 target: str = typer.Option(..., "-t", "--target", help="Target domain (e.g. example.com)"),
 session_name: str = typer.Option("default", "-s", "--session", help="Session name"),
 profile: str = typer.Option("normal", "-p", "--profile", help=PROFILE_HELP),
 proxy: Optional[str] = typer.Option(None, "--proxy", help="Proxy URL"),
 scope_file: Optional[Path] = typer.Option(None, "--scope", help="Scope YAML file"),
 sources: str = typer.Option("crtsh,hackertarget,wayback,permutation", "--sources",
  help="Passive sources: crtsh,hackertarget,wayback,permutation"),
 bruteforce: bool = typer.Option(False, "--bruteforce/--no-bruteforce", help="Active DNS brute force"),
 wordlist: Optional[str] = typer.Option(None, "--wordlist", help="Wordlist for brute force"),
 threads: int = typer.Option(50, "--threads", help="DNS resolution threads"),
 alive_only: bool = typer.Option(True, "--alive-only/--all", help="Only show live subdomains"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Subdomain enumeration — passive (crt.sh, HackerTarget, Wayback) + active brute force.

 \b
 Examples:
  talisman recon subdomain -t example.com -s bounty
  talisman recon subdomain -t example.com --bruteforce \\
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
  talisman recon subdomain -t example.com --sources crtsh,wayback --threads 100
 """
 setup_logging("DEBUG" if debug else "INFO")
 print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, scope_file)
  from talisman.modules.recon.subdomain import run
  async with sess:
   r = await run(target=target, session=sess, scope=scope,
       rate_limiter=RateLimiter(profile), proxy=proxy,
       sources=sources.split(","), bruteforce=bruteforce,
       wordlist=wordlist, threads=threads, alive_only=alive_only)
   console.print(f"\n[green][+] {r.get('live_count',0)} live subdomains[/green]")
 _run(_r())

@recon_app.command("dns")
def recon_dns(
 target: str = typer.Option(..., "-t", "--target", help="Target domain"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 zone_transfer: bool = typer.Option(True, "--zone-transfer/--no-zone-transfer"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Deep DNS analysis — records, zone transfer, SPF/DMARC/DKIM, takeover indicators.

 \b
 Examples:
  talisman recon dns -t example.com -s bounty
  talisman recon dns -t example.com --zone-transfer
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.recon.dns import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy, zone_transfer=zone_transfer)
 _run(_r())

@recon_app.command("tech")
def recon_tech(
 target: str = typer.Option(..., "-t", "--target", help="Target URL"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Technology fingerprinting — 35+ tech stacks + 12 WAF vendors.

 \b
 Detects: WordPress, Laravel, Django, Spring Boot, React, Angular, Nginx, Apache,
 Cloudflare, Akamai, AWS WAF, Imperva, F5, Sucuri, Wordfence, ModSecurity, +more

 \b
 Examples:
  talisman recon tech -t https://example.com -s bounty
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.recon.tech_detect import run
  async with sess:
   r = await run(target=target, session=sess, scope=scope, proxy=proxy)
   if r.get("technologies"):
    console.print(f" Tech: {', '.join(r['technologies'])}")
   if r.get("waf"):
    console.print(f" WAF: [yellow]{r['waf']}[/yellow]")
 _run(_r())

@recon_app.command("crawl")
def recon_crawl(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 depth: int = typer.Option(3, "--depth", help="Crawl depth (default 3)"),
 js_parse: bool = typer.Option(True, "--js-parse/--no-js"),
 max_pages: int = typer.Option(200, "--max-pages"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Web crawler — links, forms, JS endpoint extraction, comment analysis.

 \b
 Examples:
  talisman recon crawl -t https://example.com -s bounty
  talisman recon crawl -t https://example.com --depth 5 --max-pages 500
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.recon.web_crawler import run
  async with sess:
   r = await run(target=target, session=sess, scope=scope, proxy=proxy,
       depth=depth, js_parse=js_parse, max_pages=max_pages)
   console.print(f" Pages: {r.get('pages_visited',0)} | Forms: {len(r.get('forms',[]))} | JS endpoints: {len(r.get('js_endpoints',[]))}")
 _run(_r())

@recon_app.command("osint")
def recon_osint(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 github_token: Optional[str] = typer.Option(None, "--github-token", envvar="GITHUB_TOKEN"),
 checks: str = typer.Option("emails,s3_buckets,github_dorks", "--checks"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 OSINT — email harvesting, S3 bucket discovery, GitHub secret dorks.

 \b
 Examples:
  talisman recon osint -t example.com -s bounty
  talisman recon osint -t example.com --github-token ghp_xxxx --checks github_dorks
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.recon.osint import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy,
      checks=checks.split(","), github_token=github_token)
 _run(_r())

@recon_app.command("ports")
def recon_ports(
 target: str = typer.Option(..., "-t", "--target", help="Target IP or hostname"),
 session_name: str = typer.Option("default", "-s", "--session"),
 ports: str = typer.Option("common", "--ports", help="Ports: common | 1-65535 | 80,443,8080"),
 threads: int = typer.Option(100, "--threads"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Port scanner — common ports including all database, K8s, and service ports.

 \b
 Examples:
  talisman recon ports -t 192.168.1.1 -s internal
  talisman recon ports -t target.com --ports 1-10000 --threads 200
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.recon.port_scanner import run
  async with sess:
   r = await run(target=target, session=sess, scope=scope, ports=ports, threads=threads)
   console.print(f" Open ports: {r.get('open_ports',[])}")
 _run(_r())

@recon_app.command("all")
def recon_all(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 profile: str = typer.Option("normal", "-p", "--profile", help=PROFILE_HELP),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 scope_file: Optional[Path] = typer.Option(None, "--scope"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Run ALL recon modules: subdomain -> DNS -> tech -> crawl -> OSINT -> ports.

 \b
 Examples:
  talisman recon all -t example.com -s bounty-q1
  talisman recon all -t example.com --profile stealth -s bounty
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, scope_file)
  rl = RateLimiter(profile)
  common = dict(session=sess, scope=scope, rate_limiter=rl, proxy=proxy)
  import importlib
  async with sess:
   for mp in ["talisman.modules.recon.subdomain","talisman.modules.recon.dns",
      "talisman.modules.recon.tech_detect","talisman.modules.recon.web_crawler",
      "talisman.modules.recon.osint","talisman.modules.recon.port_scanner"]:
    try:
     await importlib.import_module(mp).run(target=target, **common)
    except Exception as e:
     console.print(f" [dim]{mp.split('.')[-1]}: {e}[/dim]")
   s = await sess.summary()
   console.print(f"\n[green][+] Full recon — {s['total_findings']} findings[/green]")
 _run(_r())

# ── SCAN ──────────────────────────────────────────────────────────────────────
def _mkscan(name, mod_path, doc):
 @scan_app.command(name)
 def _cmd(
  target: str = typer.Option(..., "-t", "--target"),
  session_name: str = typer.Option("default", "-s", "--session"),
  profile: str = typer.Option("normal", "-p", "--profile", help=PROFILE_HELP),
  proxy: Optional[str] = typer.Option(None, "--proxy"),
  oast: Optional[str] = typer.Option(None, "--oast", help="OAST domain for OOB detection"),
  waf_bypass: bool = typer.Option(False, "--waf-bypass", help="Enable WAF evasion"),
  debug: bool = typer.Option(False, "--debug"),
 ):
  setup_logging("DEBUG" if debug else "INFO"); print_banner()
  async def _r():
   sess, scope = await _session_scope(session_name, target, None)
   import importlib
   mod = importlib.import_module(mod_path)
   async with sess:
    r = await mod.run(target=target, session=sess, scope=scope,
         rate_limiter=RateLimiter(profile), proxy=proxy,
         oast_domain=oast, waf_bypass=waf_bypass)
    c = r.get("count",0) if isinstance(r,dict) else 0
    console.print(f"\n[{'red' if c else 'green'}][+] {c} findings[/{'red' if c else 'green'}]")
    if c: console.print(f" View: [cyan]talisman session findings {session_name}[/cyan]")
  _run(_r())
 _cmd.__doc__ = doc

_mkscan("xss","talisman.modules.scanner.xss",
 "Cross-Site Scripting — reflected, DOM, context-aware payloads, WAF bypass variants.\n\n\\b\nExamples:\n talisman scan xss -t 'https://example.com/search?q=FUZZ'\n talisman scan xss -t https://example.com --waf-bypass")
_mkscan("sqli","talisman.modules.scanner.sqli",
 "SQL Injection — error-based, boolean blind, time-based. Detects MySQL/MSSQL/PostgreSQL/Oracle.\n\n\\b\nExamples:\n talisman scan sqli -t 'https://example.com/item?id=1'\n talisman scan sqli -t https://example.com --waf-bypass --oast oastify.com")
_mkscan("ssrf","talisman.modules.scanner.ssrf",
 "SSRF — cloud metadata, internal IPs, protocol handlers (file://, gopher://, dict://).\n\n\\b\nExamples:\n talisman scan ssrf -t https://example.com --oast oastify.com\n talisman scan ssrf -t 'https://example.com/fetch?url=FUZZ'")
_mkscan("cmdi","talisman.modules.scanner.cmdi",
 "Command Injection — Linux/Windows, time-based blind, OOB via OAST, WAF bypass.\n\n\\b\nExamples:\n talisman scan cmdi -t 'https://example.com/ping?host=FUZZ' --oast oastify.com\n talisman scan cmdi -t https://example.com --waf-bypass")
_mkscan("ssti","talisman.modules.scanner.ssti",
 "SSTI — Jinja2, Twig, Freemarker, Velocity. Math eval detection + RCE payloads.\n\n\\b\nExamples:\n talisman scan ssti -t 'https://example.com/greet?name=FUZZ'\n talisman scan ssti -t https://example.com --proxy http://127.0.0.1:8080")
_mkscan("lfi","talisman.modules.scanner.lfi_rfi",
 "LFI/Path Traversal — Unix/Windows traversal + PHP wrapper exploitation.\n\n\\b\nExamples:\n talisman scan lfi -t 'https://example.com/page?file=FUZZ'\n talisman scan lfi -t https://example.com --waf-bypass")
_mkscan("xxe","talisman.modules.scanner.xxe",
 "XXE — classic file read, XInclude, OOB via OAST, SSRF. Tests XML endpoints.\n\n\\b\nExamples:\n talisman scan xxe -t https://example.com/upload --oast oastify.com\n talisman scan xxe -t https://example.com/api/xml")
_mkscan("cors","talisman.modules.scanner.cors",
 "CORS — wildcard reflection, null origin, subdomain/prefix/suffix bypass.\n\n\\b\nExamples:\n talisman scan cors -t https://example.com -s bounty\n talisman scan cors -t https://api.example.com")
_mkscan("headers","talisman.modules.scanner.headers",
 "Security headers — HSTS, CSP, X-Frame-Options, Referrer-Policy. CSP weakness analysis.\n\n\\b\nExamples:\n talisman scan headers -t https://example.com\n talisman scan headers -t https://example.com -s bounty")
_mkscan("cache","talisman.modules.scanner.cache_poison",
 "Cache poisoning — X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL injection.\n\n\\b\nExamples:\n talisman scan cache -t https://example.com\n talisman scan cache -t https://cdn.example.com -s bounty")
_mkscan("idor","talisman.modules.scanner.idor",
 "IDOR/BOLA — numeric and UUID ID enumeration, adjacent ID testing.\n\n\\b\nExamples:\n talisman scan idor -t 'https://example.com/api/users/123'\n talisman scan idor -t https://example.com/api -s bounty")
_mkscan("smuggle","talisman.modules.scanner.smuggling",
 "HTTP Request Smuggling — CL.TE, TE.CL, TE.TE via raw TCP timing analysis.\n\n\\b\nExamples:\n talisman scan smuggle -t https://example.com\n talisman scan smuggle -t https://example.com --proxy http://127.0.0.1:8080")
_mkscan("redirect","talisman.modules.scanner.open_redirect",
 "Open redirect — 24 common parameter names tested with bypass variants.\n\n\\b\nExamples:\n talisman scan redirect -t 'https://example.com/login?next=FUZZ'\n talisman scan redirect -t https://example.com -s bounty")
_mkscan("proto","talisman.modules.scanner.prototype",
 "Prototype pollution — __proto__ and constructor.prototype in params and JSON body.\n\n\\b\nExamples:\n talisman scan proto -t https://example.com/api\n talisman scan proto -t 'https://example.com/merge'")
_mkscan("auth","talisman.modules.scanner.auth",
 "Auth bypass — 20+ default creds, CSRF token check, auto login form detection.\n\n\\b\nExamples:\n talisman scan auth -t https://example.com\n talisman scan auth -t https://admin.example.com --proxy http://127.0.0.1:8080")
_mkscan("log4shell","talisman.modules.scanner.log4shell",
 "Log4Shell CVE-2021-44228 — JNDI in 20 headers + URL params. Requires --oast.\n\n\\b\nExamples:\n talisman scan log4shell -t https://example.com --oast oastify.com\n talisman scan log4shell -t https://api.example.com --oast interactsh.com")
_mkscan("race","talisman.modules.scanner.race_condition",
 "Race condition — parallel request flood, TOCTOU detection on rate-limited actions.\n\n\\b\nExamples:\n talisman scan race -t https://example.com/redeem-coupon\n talisman scan race -t https://example.com/transfer -s bounty")
_mkscan("mfa","talisman.modules.scanner.mfa_bypass",
 "MFA/2FA bypass — step skip, code brute rate limit, response manipulation.\n\n\\b\nExamples:\n talisman scan mfa -t https://example.com\n talisman scan mfa -t https://app.example.com --proxy http://127.0.0.1:8080")
_mkscan("bizlogic","talisman.modules.scanner.business_logic",
 "Business logic — negative values, mass assignment, workflow step bypass.\n\n\\b\nExamples:\n talisman scan bizlogic -t https://example.com/checkout\n talisman scan bizlogic -t https://shop.example.com -s bounty")

@scan_app.command("all")
def scan_all(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 profile: str = typer.Option("normal", "-p", "--profile", help=PROFILE_HELP),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 oast: Optional[str] = typer.Option(None, "--oast"),
 waf_bypass: bool = typer.Option(False, "--waf-bypass"),
 exclude: str = typer.Option("", "--exclude", help="Modules to skip (comma-separated, e.g. smuggle,race)"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Run ALL vulnerability scanners against target.

 \b
 Scanners: headers, cors, xss, sqli, ssrf, cmdi, ssti, lfi, redirect,
 cache, idor, proto, smuggle, auth, misconfig, bizlogic, mfa, race
 If --oast provided: also xxe, log4shell

 \b
 Examples:
  talisman scan all -t https://example.com -s bounty
  talisman scan all -t https://example.com --waf-bypass --oast oastify.com
  talisman scan all -t https://example.com --exclude smuggle,race -p stealth
  talisman scan all -t https://example.com --proxy http://127.0.0.1:8080
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 skip = set(exclude.split(",")) if exclude else set()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  rl = RateLimiter(profile)
  common = dict(session=sess, scope=scope, rate_limiter=rl, proxy=proxy,
      oast_domain=oast, waf_bypass=waf_bypass)
  scanners = [
   ("headers","talisman.modules.scanner.headers"),
   ("cors","talisman.modules.scanner.cors"),
   ("xss","talisman.modules.scanner.xss"),
   ("sqli","talisman.modules.scanner.sqli"),
   ("ssrf","talisman.modules.scanner.ssrf"),
   ("cmdi","talisman.modules.scanner.cmdi"),
   ("ssti","talisman.modules.scanner.ssti"),
   ("lfi","talisman.modules.scanner.lfi_rfi"),
   ("redirect","talisman.modules.scanner.open_redirect"),
   ("cache","talisman.modules.scanner.cache_poison"),
   ("idor","talisman.modules.scanner.idor"),
   ("proto","talisman.modules.scanner.prototype"),
   ("smuggle","talisman.modules.scanner.smuggling"),
   ("auth","talisman.modules.scanner.auth"),
   ("misconfig","talisman.modules.misconfiguration.server_misconfig"),
   ("bizlogic","talisman.modules.scanner.business_logic"),
   ("mfa","talisman.modules.scanner.mfa_bypass"),
   ("race","talisman.modules.scanner.race_condition"),
  ]
  if oast:
   scanners += [("xxe","talisman.modules.scanner.xxe"),("log4shell","talisman.modules.scanner.log4shell")]
  import importlib
  async with sess:
   for name, mp in scanners:
    if name in skip:
     console.print(f" [dim]skip: {name}[/dim]"); continue
    try:
     await importlib.import_module(mp).run(target=target, **common)
    except Exception as e:
     console.print(f" [dim]{name}: {e}[/dim]")
   s = await sess.summary()
   console.print(Panel(
    f"[red]Critical: {s['findings'].get('critical',0)}[/red] "
    f"[orange3]High: {s['findings'].get('high',0)}[/orange3] "
    f"[yellow]Medium: {s['findings'].get('medium',0)}[/yellow] "
    f"[blue]Low: {s['findings'].get('low',0)}[/blue]\n"
    f"Total: {s['total_findings']}",
    title=f"[OK] All Scans Complete — {session_name}", border_style="green"))
   console.print(f" Report: [cyan]talisman report generate {session_name}[/cyan]")
 _run(_r())

# ── WAF ───────────────────────────────────────────────────────────────────────
@waf_app.command("detect")
def waf_detect(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Detect WAF vendor using multi-layer fingerprinting (12 vendors).

 \b
 Detects: Cloudflare, Akamai, AWS WAF, Imperva, F5 BIG-IP, Sucuri,
 Barracuda, FortiWeb, Wordfence, ModSecurity, Azure Front Door, StackPath

 \b
 Examples:
  talisman waf detect -t https://example.com
  talisman waf detect -t https://example.com -s bounty
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.waf.detector import run
  async with sess:
   r = await run(target=target, session=sess, scope=scope, proxy=proxy)
   if r.get("waf"):
    console.print(f"\n WAF: [yellow]{r['waf']}[/yellow] ({r.get('confidence',0)}% confidence)")
    console.print(f" Next: [cyan]talisman waf bypass -t {target} --waf {r['waf']}[/cyan]")
 _run(_r())

@waf_app.command("origin")
def waf_origin(
 target: str = typer.Option(..., "-t", "--target", help="Domain behind CDN/WAF"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 shodan_key: Optional[str] = typer.Option(None, "--shodan-key", envvar="SHODAN_API_KEY"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Find real origin IP behind Cloudflare/CDN — bypass WAF entirely.

 \b
 Methods: crt.sh CT logs, MX correlation, Shodan, favicon hash, subdomain enum

 \b
 Examples:
  talisman waf origin -t example.com
  talisman waf origin -t example.com --shodan-key YOUR_KEY
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 from talisman.modules.waf.vendors.cloudflare import find_origin
 _run(find_origin(target=target, proxy=proxy, shodan_key=shodan_key))

@waf_app.command("bypass")
def waf_bypass(
 target: str = typer.Option(..., "-t", "--target"),
 waf: str = typer.Option("auto", "--waf", help="WAF vendor: auto, Cloudflare, Akamai, ModSecurity, AWS WAF"),
 vuln_type: str = typer.Option("xss", "--type", help="Vuln type: xss, sqli, lfi, cmdi"),
 param: str = typer.Option("q", "--param", help="URL parameter to test"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Generate and score vendor-specific WAF bypass payloads.

 \b
 Examples:
  talisman waf bypass -t https://example.com --waf Cloudflare --type xss
  talisman waf bypass -t https://example.com --waf Akamai --type sqli --param id
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 from talisman.modules.waf.bypass_engine import run
 _run(run(target=target, waf=waf, vuln_type=vuln_type, proxy=proxy, param=param))

# ── FUZZ ──────────────────────────────────────────────────────────────────────
@fuzz_app.command("paths")
def fuzz_paths(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 profile: str = typer.Option("normal", "-p", "--profile", help=PROFILE_HELP),
 wordlist: Optional[str] = typer.Option(None, "--wordlist"),
 threads: int = typer.Option(30, "--threads"),
 extensions: str = typer.Option("php,asp,aspx,jsp,bak,txt,json,sql,log,xml,zip", "--extensions"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Directory/file brute force — 150+ built-in paths + custom wordlist.

 \b
 Covers: admin panels, API endpoints, config files, git/svn, backup files,
 debug pages, Java WEB-INF, .env files, phpinfo, server-status, actuator

 \b
 Examples:
  talisman fuzz paths -t https://example.com -s bounty
  talisman fuzz paths -t https://example.com \\
  --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \\
  --extensions php,bak,old,sql --threads 100
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.fuzzer.path_fuzz import run
  async with sess:
   r = await run(target=target, session=sess, scope=scope, proxy=proxy,
       wordlist=wordlist, threads=threads, extensions=extensions.split(","))
   console.print(f"\n Found {r.get('count',0)} accessible paths")
 _run(_r())

@fuzz_app.command("params")
def fuzz_params(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 wordlist: Optional[str] = typer.Option(None, "--wordlist"),
 methods: str = typer.Option("GET,POST", "--methods"),
 threads: int = typer.Option(20, "--threads"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Parameter discovery — find hidden params via response differential analysis.

 \b
 Examples:
  talisman fuzz params -t https://example.com/api/users -s bounty
  talisman fuzz params -t https://example.com --methods GET,POST,PUT
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.fuzzer.param_fuzz import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy,
      wordlist=wordlist, methods=methods, threads=threads)
 _run(_r())

# ── API ───────────────────────────────────────────────────────────────────────
@api_app.command("graphql")
def api_graphql(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 auth: Optional[str] = typer.Option(None, "--auth", help="Auth header (e.g. 'Bearer TOKEN')"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 GraphQL audit — introspection, injection, alias batching DoS, depth limits.

 \b
 Auto-discovers endpoint at /graphql, /gql, /graphiql, /api/graphql, /query

 \b
 Examples:
  talisman api graphql -t https://api.example.com -s bounty
  talisman api graphql -t https://example.com --auth 'Bearer eyJhb...'
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.api.graphql import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy, auth=auth)
 _run(_r())

@api_app.command("jwt")
def api_jwt(
 target: str = typer.Option(..., "-t", "--target"),
 token: str = typer.Option(..., "--token", help="JWT token string to analyze/attack"),
 session_name: str = typer.Option("default", "-s", "--session"),
 endpoint: Optional[str] = typer.Option(None, "--endpoint", help="Protected endpoint to test forged tokens"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 crack: bool = typer.Option(True, "--crack/--no-crack"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 JWT attacks — alg confusion, none attack, kid injection, secret brute force.

 \b
 Examples:
  talisman api jwt -t https://api.example.com --token eyJhbGci...
  talisman api jwt -t https://api.example.com --token eyJ... \\
  --endpoint https://api.example.com/admin/users
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.api.jwt import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy,
      token=token, endpoint=endpoint, crack_secret=crack)
 _run(_r())

@api_app.command("swagger")
def api_swagger(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 spec_url: Optional[str] = typer.Option(None, "--spec"),
 auth: Optional[str] = typer.Option(None, "--auth"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 OpenAPI/Swagger spec analysis — endpoint audit, unauth access, IDOR patterns.

 \b
 Auto-discovers spec at /swagger.json, /openapi.json, /api-docs, /v2/api-docs

 \b
 Examples:
  talisman api swagger -t https://api.example.com -s bounty
  talisman api swagger -t https://api.example.com --auth 'Bearer TOKEN'
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.api.swagger_audit import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy,
      spec_url=spec_url, auth_header=auth)
 _run(_r())

@api_app.command("oauth")
def api_oauth(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 client_id: Optional[str] = typer.Option(None, "--client-id"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 OAuth 2.0/OIDC audit — implicit flow, PKCE, redirect_uri bypass.

 \b
 Examples:
  talisman api oauth -t https://auth.example.com -s bounty
  talisman api oauth -t https://example.com --client-id myapp -s bounty
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.api.oauth import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy, client_id=client_id)
 _run(_r())

# ── CLOUD ─────────────────────────────────────────────────────────────────────
@cloud_app.command("aws")
def cloud_aws(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 s3_enum: bool = typer.Option(True, "--s3/--no-s3"),
 cloudfront_bypass: bool = typer.Option(True, "--cf-bypass/--no-cf"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 AWS audit — S3 bucket enum (20+ patterns), CloudFront origin bypass.

 \b
 Examples:
  talisman cloud aws -t example.com -s bounty
  talisman cloud aws -t example.com --s3 --cf-bypass -s bounty
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.cloud.aws import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy,
      s3_enum=s3_enum, cloudfront_bypass=cloudfront_bypass)
 _run(_r())

@cloud_app.command("secrets")
def cloud_secrets(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Secret scanning — 30+ patterns in JS files, HTML, config files, .env.

 \b
 Detects: AWS keys, GitHub PAT, Stripe keys, OpenAI, Slack tokens,
 database URLs, private keys, generic password/api_key/secret patterns

 \b
 Examples:
  talisman cloud secrets -t https://example.com -s bounty
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.cloud.secrets import run
  async with sess:
   r = await run(target=target, session=sess, scope=scope, proxy=proxy)
   console.print(f"\n Found {r.get('count',0)} secrets")
 _run(_r())

# ── MISCONFIG ─────────────────────────────────────────────────────────────────
@misconfig_app.command("spring")
def misconfig_spring(target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 debug: bool = typer.Option(False, "--debug")):
 """
 Spring Boot Actuator — 22 endpoint audit (env, heapdump, sessions, jolokia, shutdown).

 \b
 Examples:
  talisman misconfig spring -t https://api.example.com -s bounty
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.misconfiguration.spring_misconfig import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy)
 _run(_r())

@misconfig_app.command("kubernetes")
def misconfig_k8s(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 api_port: int = typer.Option(6443, "--api-port"),
 kubelet_port: int = typer.Option(10255, "--kubelet-port"),
 etcd_port: int = typer.Option(2379, "--etcd-port"),
 dashboard: bool = typer.Option(True, "--dashboard/--no-dashboard"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Kubernetes misconfig — unauthenticated API, kubelet, etcd, dashboard exposure.

 \b
 Examples:
  talisman misconfig kubernetes -t k8s.example.com -s bounty
  talisman misconfig kubernetes -t 10.0.0.1 --api-port 8080
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.misconfiguration.kubernetes_misconfig import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy,
      api_server_port=api_port, kubelet_port=kubelet_port,
      etcd_port=etcd_port, dashboard_check=dashboard)
 _run(_r())

@misconfig_app.command("database")
def misconfig_db(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 checks: str = typer.Option("mongodb,redis,elasticsearch,memcached,couchdb,influxdb,neo4j,mysql,postgres", "--checks"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Exposed database scanner — 15 DB types, unauthenticated access check.

 \b
 Examples:
  talisman misconfig database -t 192.168.1.1 -s internal
  talisman misconfig database -t target.com --checks mongodb,redis,elasticsearch
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.misconfiguration.database_exposure import run
  async with sess:
   await run(target=target, session=sess, scope=scope, checks=checks.split(","))
 _run(_r())

@misconfig_app.command("server")
def misconfig_server(target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 debug: bool = typer.Option(False, "--debug")):
 """
 Server misconfig — Nginx/Apache/IIS, CRLF, HTTP methods, 25+ sensitive files.

 \b
 Examples:
  talisman misconfig server -t https://example.com -s bounty
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.misconfiguration.server_misconfig import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy)
 _run(_r())

@misconfig_app.command("nginx")
def misconfig_nginx(target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 debug: bool = typer.Option(False, "--debug")):
 """Nginx-specific — alias traversal, off-by-slash, stub_status exposure."""
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.misconfiguration.nginx_misconfig import run
  async with sess:
   await run(target=target, session=sess, scope=scope, proxy=proxy)
 _run(_r())

# ── CMS ───────────────────────────────────────────────────────────────────────
@cms_app.command("wordpress")
def cms_wordpress(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 oast: Optional[str] = typer.Option(None, "--oast"),
 full: bool = typer.Option(False, "--full"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 WordPress deep audit — version, CVEs, plugins (15 vuln checks), users, XML-RPC.

 \b
 Examples:
  talisman cms wordpress -t https://wordpress-site.com -s bounty
  talisman cms wordpress -t https://wp-site.com --oast oastify.com --full
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  common = dict(session=sess, scope=scope, proxy=proxy, oast_domain=oast)
  async with sess:
   for mp in ["talisman.modules.cms.wordpress.core","talisman.modules.cms.wordpress.users",
      "talisman.modules.cms.wordpress.plugins","talisman.modules.cms.wordpress.xmlrpc"]:
    try:
     import importlib
     await importlib.import_module(mp).run(target=target, **common)
    except Exception as e:
     console.print(f" [dim]{mp.split('.')[-1]}: {e}[/dim]")
   s = await sess.summary()
   console.print(f"\n[green][+] WordPress audit — {s['total_findings']} findings[/green]")
 _run(_r())

# ── AD ────────────────────────────────────────────────────────────────────────
@ad_app.command("recon")
def ad_recon(
 target: str = typer.Option(..., "-t", "--target"),
 domain: str = typer.Option(..., "--domain", help="AD domain (e.g. corp.local)"),
 dc_ip: str = typer.Option(..., "--dc-ip", help="Domain Controller IP"),
 session_name: str = typer.Option("default", "-s", "--session"),
 username: Optional[str] = typer.Option(None, "--user"),
 password: Optional[str] = typer.Option(None, "--password"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 AD enumeration via LDAP — users, groups, Kerberoastable, AS-REP, admins.

 \b
 Requires: pip install ldap3

 \b
 Examples:
  talisman ad recon -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10
  talisman ad recon -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 \\
  --user jsmith --password Password1
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.activedirectory.ad_recon import run
  async with sess:
   await run(target=target, session=sess, scope=scope,
      domain=domain, dc_ip=dc_ip, username=username, password=password)
 _run(_r())

@ad_app.command("kerberos")
def ad_kerberos(
 target: str = typer.Option(..., "-t", "--target"),
 domain: str = typer.Option(..., "--domain"),
 dc_ip: str = typer.Option(..., "--dc-ip"),
 session_name: str = typer.Option("default", "-s", "--session"),
 username: Optional[str] = typer.Option(None, "--user"),
 password: Optional[str] = typer.Option(None, "--password"),
 users_file: Optional[str] = typer.Option(None, "--users"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Kerberoasting + AS-REP roasting — capture hashes for offline cracking.

 \b
 Requires: pip install impacket
 Crack: hashcat -m 13100 hashes.txt rockyou.txt (Kerberoast)
 Crack: hashcat -m 18200 hashes.txt rockyou.txt (AS-REP)

 \b
 Examples:
  talisman ad kerberos -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 \\
  --user jsmith --password Password1
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  users_list = None
  if users_file:
   try:
    with open(users_file) as f: users_list = [l.strip() for l in f if l.strip()]
   except Exception as e: console.print(f"[red]{e}[/red]")
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.activedirectory.kerberos import run
  async with sess:
   await run(target=target, session=sess, scope=scope,
      domain=domain, dc_ip=dc_ip, username=username, password=password,
      users_list=users_list)
 _run(_r())

@ad_app.command("smb")
def ad_smb(
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 username: str = typer.Option("", "--user"),
 password: str = typer.Option("", "--password"),
 domain: str = typer.Option("", "--domain"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 SMB audit — shares, signing check, null session, GPP credential decrypt (MS14-025).

 \b
 Requires: pip install impacket

 \b
 Examples:
  talisman ad smb -t 192.168.1.10 -s internal
  talisman ad smb -t 192.168.1.10 --user jsmith --password Password1 --domain CORP
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.activedirectory.smb_audit import run
  async with sess:
   await run(target=target, session=sess, scope=scope,
      username=username, password=password, domain=domain)
 _run(_r())

@ad_app.command("spray")
def ad_spray(
 target: str = typer.Option(..., "-t", "--target"),
 domain: str = typer.Option(..., "--domain"),
 dc_ip: str = typer.Option(..., "--dc-ip"),
 session_name: str = typer.Option("default", "-s", "--session"),
 users_file: str = typer.Option(..., "--users", help="File with usernames (one per line)"),
 passwords: Optional[str] = typer.Option(None, "--passwords", help="Comma-separated passwords"),
 lockout_threshold: int = typer.Option(3, "--lockout-threshold"),
 delay_minutes: int = typer.Option(30, "--delay-minutes"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 AD Password Spray — lockout-safe, smart password list, configurable delay.

 \b
 Examples:
  talisman ad spray -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 \\
  --users users.txt --passwords 'Password1,Welcome1!' -s internal
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.activedirectory.password_spray import run
  async with sess:
   await run(target=target, session=sess, scope=scope,
      domain=domain, dc_ip=dc_ip, users_file=users_file,
      passwords=passwords, lockout_threshold=lockout_threshold,
      delay_minutes=delay_minutes)
 _run(_r())

@ad_app.command("adcs")
def ad_cs_cmd(
 target: str = typer.Option(..., "-t", "--target"),
 domain: str = typer.Option(..., "--domain"),
 dc_ip: str = typer.Option(..., "--dc-ip"),
 session_name: str = typer.Option("default", "-s", "--session"),
 username: Optional[str] = typer.Option(None, "--user"),
 password: Optional[str] = typer.Option(None, "--password"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 AD Certificate Services — ESC1-ESC8 vulnerability detection.

 \b
 ESC1: SAN + Client Auth = forge admin certs
 ESC2: Any Purpose EKU
 ESC4: Template ACL misconfiguration
 ESC8: NTLM relay to ADCS HTTP endpoint -> DCSync

 \b
 Examples:
  talisman ad adcs -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 \\
  --user jsmith --password Password1 -s internal
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  sess, scope = await _session_scope(session_name, target, None)
  from talisman.modules.activedirectory.ad_cs import run
  async with sess:
   await run(target=target, session=sess, scope=scope,
      domain=domain, dc_ip=dc_ip, username=username, password=password)
 _run(_r())

# ── CHAIN ─────────────────────────────────────────────────────────────────────
@chain_app.command("run")
def chain_run(
 chain_name: str = typer.Argument(...,
  help="Chain name or YAML path.\n\nBuilt-in: full_recon, web_vuln_scan, wordpress_full, api_audit, cloud_breach, waf_bypass_probe, windows_ad"),
 target: str = typer.Option(..., "-t", "--target"),
 session_name: str = typer.Option("default", "-s", "--session"),
 profile: str = typer.Option("normal", "-p", "--profile", help=PROFILE_HELP),
 proxy: Optional[str] = typer.Option(None, "--proxy"),
 scope_file: Optional[Path] = typer.Option(None, "--scope"),
 oast: Optional[str] = typer.Option(None, "--oast"),
 dry_run: bool = typer.Option(False, "--dry-run", help="Preview steps without executing"),
 debug: bool = typer.Option(False, "--debug"),
):
 """
 Run a built-in or custom YAML workflow chain.

 \b
 Built-in chains:
  full_recon  — Complete recon: subdomain -> DNS -> tech -> crawl -> OSINT -> takeover
  web_vuln_scan — All web vulnerability scanners
  wordpress_full — Complete WordPress audit
  api_audit  — GraphQL + JWT + REST/Swagger audit
  cloud_breach  — AWS S3 + secrets + CloudFront bypass
  waf_bypass_probe — WAF fingerprint + origin finder + bypass generation
  windows_ad  — LDAP recon + Kerberoasting + SMB audit

 \b
 Examples:
  talisman chain run full_recon -t example.com -s bounty-q1
  talisman chain run web_vuln_scan -t https://example.com \\
  --profile stealth --proxy http://127.0.0.1:8080 -s bounty
  talisman chain run wordpress_full -t https://wp-site.com --oast oastify.com
  talisman chain run windows_ad -t 192.168.1.10 --profile stealth -s internal
  talisman chain run full_recon -t example.com --dry-run
 """
 setup_logging("DEBUG" if debug else "INFO"); print_banner()
 async def _r():
  try:
   chain = ChainOrchestrator.load_chain(chain_name)
  except FileNotFoundError:
   console.print(f"[red]Chain '{chain_name}' not found.[/red]")
   console.print(f" List chains: [cyan]talisman chain list[/cyan]")
   raise typer.Exit(1)
  sess, scope = await _session_scope(session_name, target, scope_file)
  orc = ChainOrchestrator(session=sess, scope=scope, rate_profile=profile,
         proxy=proxy, dry_run=dry_run)
  async with sess:
   await orc.run(chain, target)
   if not dry_run:
    s = await sess.summary()
    console.print(f" Findings: {s['findings']}")
    console.print(f" Report: [cyan]talisman report generate {session_name}[/cyan]")
 _run(_r())

@chain_app.command("list")
def chain_list():
 """List all available built-in and custom chains."""
 chains = ChainOrchestrator.list_chains()
 t = Table(title="[T] TALISMAN Chains", style="cyan", border_style="dim")
 t.add_column("Name", style="bold cyan"); t.add_column("Description"); t.add_column("Tags", style="dim")
 for c in chains:
  t.add_row(c["name"], c["description"], c["tags"])
 console.print(t)
 console.print(f"\n Run: [cyan]talisman chain run <name> -t <target> -s <session>[/cyan]")

@chain_app.command("show")
def chain_show(chain_name: str = typer.Argument(...)):
 """Show steps of a chain before running."""
 try:
  chain = ChainOrchestrator.load_chain(chain_name)
 except FileNotFoundError:
  console.print(f"[red]Chain '{chain_name}' not found[/red]"); raise typer.Exit(1)
 console.print(Panel(f"[bold]{chain.name}[/bold]\n{chain.description}\nProfile: {chain.rate_profile} | Steps: {len(chain.steps)}",
      border_style="cyan"))
 t = Table(style="dim", border_style="dim")
 t.add_column("#",width=3); t.add_column("Step"); t.add_column("Module"); t.add_column("Depends On"); t.add_column("∥")
 for i, s in enumerate(chain.steps, 1):
  t.add_row(str(i), s.id, s.module, ", ".join(s.depends_on) or "—", "[+]" if s.parallel else "")
 console.print(t)

# ── SESSION ───────────────────────────────────────────────────────────────────
@session_app.command("list")
def session_list():
 """List all saved sessions."""
 sm = SessionManager()
 sessions = sm.list_sessions()
 if not sessions:
  console.print("[dim]No sessions found. Run a scan first.[/dim]"); return
 t = Table(title="TALISMAN Sessions", style="cyan", border_style="dim")
 t.add_column("Session Name", style="bold")
 for s in sessions: t.add_row(s)
 console.print(t)

@session_app.command("findings")
def session_findings(
 session_name: str = typer.Argument(...),
 severity: str = typer.Option("", "--severity", help="Filter: critical,high,medium,low,info"),
 fmt: str = typer.Option("table", "--format", help="table | json"),
 limit: int = typer.Option(50, "--limit"),
):
 """
 View session findings.

 \b
 Examples:
  talisman session findings bounty-q1
  talisman session findings bounty-q1 --severity critical,high
  talisman session findings bounty-q1 --format json | jq '.[].title'
 """
 async def _r():
  sm = SessionManager()
  sess = sm.get(session_name)
  async with sess:
   findings = await sess.get_findings(severity=severity.split(",") if severity else None)
   findings = findings[:limit]
   if fmt == "json":
    console.print(json.dumps(findings, indent=2, default=str)); return
   COLORS = {"critical":"red","high":"orange3","medium":"yellow","low":"blue","info":"dim white"}
   t = Table(title=f"Findings: {session_name}", style="cyan", border_style="dim")
   t.add_column("Sev",width=10); t.add_column("Title",style="bold"); t.add_column("Target"); t.add_column("Module",width=15)
   for f in findings:
    sev = f.get("severity","info").lower()
    c = COLORS.get(sev,"white")
    t.add_row(f"[{c}]{sev.upper()}[/{c}]", f.get("title","")[:55], f.get("target","")[:35], f.get("module",""))
   console.print(t)
   s = await sess.summary()
   console.print(f" Total: {s['total_findings']} | "
       f"[red]Crit:{s['findings'].get('critical',0)}[/red] "
       f"[orange3]High:{s['findings'].get('high',0)}[/orange3] "
       f"[yellow]Med:{s['findings'].get('medium',0)}[/yellow]")
   console.print(f" Report: [cyan]talisman report generate {session_name}[/cyan]")
 _run(_r())

@session_app.command("summary")
def session_summary(session_name: str = typer.Argument(...)):
 """Show summary statistics for a session."""
 async def _r():
  sm = SessionManager()
  sess = sm.get(session_name)
  async with sess:
   s = await sess.summary()
  console.print(Panel(
   f"[bold]Session:[/bold] {s['session']} | [bold]Targets:[/bold] {s['targets']}\n\n"
   f"[red]Critical: {s['findings'].get('critical',0)}[/red] "
   f"[orange3]High: {s['findings'].get('high',0)}[/orange3] "
   f"[yellow]Medium: {s['findings'].get('medium',0)}[/yellow] "
   f"[blue]Low: {s['findings'].get('low',0)}[/blue]\n"
   f"[bold]Total: {s['total_findings']}[/bold]",
   title=f"[DATA] {session_name}", border_style="cyan"))
 _run(_r())

@session_app.command("note")
def session_note(session_name: str = typer.Argument(...), note: str = typer.Argument(...)):
 """Add a note to a session.\n\nExample: talisman session note bounty 'Login uses JWT HS256'"""
 async def _r():
  sm = SessionManager()
  sess = sm.get(session_name)
  async with sess:
   await sess.add_note(note)
   console.print(f"[green][+] Note added to '{session_name}'[/green]")
 _run(_r())

@session_app.command("delete")
def session_delete(session_name: str = typer.Argument(...),
 confirm: bool = typer.Option(False, "--confirm", help="Required to confirm deletion")):
 """Delete a session and all its findings."""
 if not confirm:
  console.print(f"[yellow]Add --confirm to delete '{session_name}'[/yellow]"); raise typer.Exit(1)
 SessionManager().delete(session_name)
 console.print(f"[green][+] Session '{session_name}' deleted[/green]")

# ── REPORT ────────────────────────────────────────────────────────────────────
@report_app.command("generate")
def report_generate(
 session_name: str = typer.Argument(...),
 fmt: str = typer.Option("html,markdown,json", "--format", help="Formats: html,markdown,json"),
 output_dir: Path = typer.Option(Path("./reports"), "--output"),
 severity: str = typer.Option("", "--severity", help="Filter: critical,high,medium,low"),
 open_html: bool = typer.Option(False, "--open", help="Open HTML in browser after generation"),
):
 """
 Generate professional reports — HTML (dark theme), Markdown (HackerOne-ready), JSON.

 \b
 Examples:
  talisman report generate bounty-q1
  talisman report generate bounty-q1 --format html --severity critical,high
  talisman report generate bounty-q1 --output ~/Desktop/reports/ --open
 """
 async def _r():
  sm = SessionManager()
  sess = sm.get(session_name)
  from talisman.output.report_engine import ReportEngine
  async with sess:
   sev_filter = severity.split(",") if severity else None
   findings = await sess.get_findings(severity=sev_filter)
   targets = await sess.get_targets()
  if not findings:
   console.print(f"[yellow]No findings in '{session_name}'[/yellow]"); return
  engine = ReportEngine(session_name, findings, targets, output_dir)
  outputs = engine.generate_all(fmt.split(","))
  console.print(f"\n[green][+] Reports in {output_dir}/[/green]")
  for o in outputs: console.print(f" -> {o}")
  if open_html:
   html_files = [o for o in outputs if str(o).endswith(".html")]
   if html_files:
    import webbrowser
    webbrowser.open(f"file://{html_files[0].resolve()}")
 _run(_r())

# ── INTEL ─────────────────────────────────────────────────────────────────────
@intel_app.command("cve")
def intel_cve(technology: str = typer.Argument(...),
 version: Optional[str] = typer.Option(None, "--version")):
 """
 CVE lookup via NVD API.

 \b
 Examples:
  talisman intel cve WordPress --version 6.3.1
  talisman intel cve "Spring Boot" --version 2.7.1
 """
 async def _r():
  from talisman.intelligence.cve_feed import lookup_cves
  cves = await lookup_cves(technology, version)
  if not cves:
   console.print(" No CVEs found"); return
  t = Table(title=f"CVEs: {technology}", style="cyan", border_style="dim")
  t.add_column("CVE ID",style="bold"); t.add_column("Sev",width=10); t.add_column("CVSS"); t.add_column("Description")
  COLORS = {"critical":"red","high":"orange3","medium":"yellow","low":"blue"}
  for cve in cves:
   sev = cve.get("severity","?").lower(); c = COLORS.get(sev,"white")
   t.add_row(cve.get("id",""), f"[{c}]{sev.upper()}[/{c}]",
      str(cve.get("cvss_score","")), cve.get("description","")[:60])
  console.print(t)
 _run(_r())

@intel_app.command("score")
def intel_score(vuln_type: str = typer.Argument(..., help="e.g. command_injection, reflected_xss, idor")):
 """CVSS score estimate for a vulnerability type.\n\nExample: talisman intel score command_injection"""
 from talisman.intelligence.scoring import score_from_vuln_type, severity_from_score
 score = score_from_vuln_type(vuln_type)
 sev = severity_from_score(score)
 COLORS = {"critical":"red","high":"orange3","medium":"yellow","low":"blue","info":"dim"}
 c = COLORS.get(sev,"white")
 console.print(Panel(f"Vuln: {vuln_type}\nCVSS: {score}\n[{c}]Severity: {sev.upper()}[/{c}]", border_style="cyan"))

if __name__ == "__main__":
 app()
