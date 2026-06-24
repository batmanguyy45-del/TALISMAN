"""Structured logging with Rich console output. Author: MR MARCUS TAYK"""
from __future__ import annotations
import logging
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
from rich.panel import Panel

TALISMAN_THEME = Theme({
 "info":    "cyan",
 "success":   "bold green",
 "warning":   "bold yellow",
 "error":   "bold red",
 "critical":   "bold red on white",
 "finding.critical": "bold red",
 "finding.high":  "red",
 "finding.medium": "yellow",
 "finding.low":  "blue",
 "finding.info":  "dim white",
 "module":   "bold magenta",
 "target":   "bold cyan",
 "chain":   "bold blue",
})

console = Console(theme=TALISMAN_THEME, stderr=False, highlight=False)
err_console = Console(theme=TALISMAN_THEME, stderr=True)

SEVERITY_COLORS = {
 "critical": "[bold red]",
 "high":  "[red]",
 "medium": "[yellow]",
 "low":  "[blue]",
 "info":  "[dim white]",
}

_logging_configured = False


def setup_logging(level: str = "INFO", log_file: Path | None = None) -> None:
 global _logging_configured
 log_level = getattr(logging, level.upper(), logging.INFO)

 handlers: list[logging.Handler] = [
  RichHandler(
   console=console,
   rich_tracebacks=True,
   markup=True,
   show_path=False,
   show_time=True,
   tracebacks_suppress=[],
  )
 ]
 if log_file:
  log_file.parent.mkdir(parents=True, exist_ok=True)
  fh = logging.FileHandler(log_file)
  fh.setFormatter(
   logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
  )
  handlers.append(fh)

 logging.basicConfig(level=log_level, handlers=handlers, force=True)

 # Configure structlog with a safe, version-agnostic setup
 try:
  import structlog
  structlog.configure(
   processors=[
    structlog.stdlib.filter_by_level,
    structlog.stdlib.add_logger_name,
    structlog.stdlib.add_log_level,
    structlog.stdlib.PositionalArgumentsFormatter(),
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
    structlog.dev.ConsoleRenderer(colors=False),
   ],
   wrapper_class=structlog.stdlib.BoundLogger,
   context_class=dict,
   logger_factory=structlog.stdlib.LoggerFactory(),
   cache_logger_on_first_use=True,
  )
 except Exception:
  pass # structlog not critical — stdlib logging is the fallback

 _logging_configured = True


def get_logger(name: str) -> Any:
 """Get a logger — structlog if available, else stdlib."""
 try:
  import structlog
  return structlog.get_logger(name)
 except ImportError:
  return logging.getLogger(name)


def print_finding(title: str, severity: str, target: str, description: str = "") -> None:
 color = SEVERITY_COLORS.get(severity.lower(), "[white]")
 badge = f"{color}[{severity.upper()}][/]"
 console.print(f" {badge} {title} — [target]{target}[/]")
 if description:
  console.print(f"   [dim]{description[:120]}[/]")


def print_banner() -> None:
 console.print("""
[bold cyan]
 ████████╗ █████╗ ██╗  ██╗███████╗███╗ ███╗ █████╗ ███╗ ██╗
 ╚══██╔══╝██╔══██╗██║  ██║██╔════╝████╗ ████║██╔══██╗████╗ ██║
 ██║ ███████║██║  ██║███████╗██╔████╔██║███████║██╔██╗ ██║
 ██║ ██╔══██║██║  ██║╚════██║██║╚██╔╝██║██╔══██║██║╚██╗██║
 ██║ ██║ ██║███████╗██║███████║██║ ╚═╝ ██║██║ ██║██║ ╚████║
 ╚═╝ ╚═╝ ╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝ ╚═╝╚═╝ ╚═══╝
[/bold cyan]
[dim] Threat Analysis, Lateral Intelligence & Security Management[/dim]
[dim] Advanced Bug Bounty & Professional Security Research Platform v1.0.0[/dim]
[bold yellow] Author: MR MARCUS TAYK | USE ONLY ON AUTHORIZED SYSTEMS[/bold yellow]
""")
