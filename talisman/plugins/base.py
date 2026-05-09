"""Plugin system base classes — extensible architecture for custom modules."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncGenerator

@dataclass
class Finding:
    title: str
    severity: str
    confidence: str
    vuln_type: str
    target: str
    description: str = ""
    request: str = ""
    response: str = ""
    evidence: str = ""
    reproduction: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe: str = ""
    references: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


class ScannerPlugin(ABC):
    """Base class for vulnerability scanner plugins."""
    name: str = "unnamed"
    version: str = "1.0.0"
    author: str = "unknown"
    description: str = ""
    vuln_class: str = "custom"
    tags: list[str] = field(default_factory=list)
    requires_auth: bool = False
    destructive: bool = False
    oast_required: bool = False

    @abstractmethod
    async def check(
        self,
        target: str,
        session_context: dict[str, Any],
        http_client: Any,
        config: dict[str, Any],
    ) -> AsyncGenerator[Finding, None]:
        """Yield findings as they are discovered."""
        yield  # type: ignore

    def on_tech_detected(self, tech: str) -> bool:
        """Return True if this plugin should auto-run when tech is detected."""
        return False

    async def run(
        self,
        target: str,
        session: Any = None,
        scope: Any = None,
        rate_limiter: Any = None,
        proxy: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Standard module interface."""
        from talisman.utils.http_client import TalismanHTTPClient
        findings: list[Finding] = []
        async with TalismanHTTPClient(proxy=proxy) as client:
            async for finding in self.check(target, {}, client, kwargs):
                findings.append(finding)
                if session:
                    await session.add_finding(
                        target=target,
                        module=self.name,
                        vuln_type=finding.vuln_type,
                        severity=finding.severity,
                        confidence=finding.confidence,
                        title=finding.title,
                        description=finding.description,
                        request=finding.request,
                        response=finding.response,
                        evidence=finding.evidence,
                        reproduction=finding.reproduction,
                        remediation=finding.remediation,
                        cvss_score=finding.cvss_score,
                        cwe=finding.cwe,
                        references=finding.references,
                        extra=finding.extra,
                    )
        return {"target": target, "findings": [f.__dict__ for f in findings], "count": len(findings)}


class ReconPlugin(ABC):
    """Base class for reconnaissance plugins."""
    name: str = "unnamed_recon"
    data_type: str = "subdomains"
    passive: bool = True

    @abstractmethod
    async def collect(self, target: str, config: dict[str, Any]) -> list[dict[str, Any]]:
        """Return list of discovered items."""
        pass


class WordlistPlugin(ABC):
    """Base class for custom wordlist plugins."""
    name: str = "unnamed_wordlist"
    wordlist_type: str = "paths"

    @abstractmethod
    def get_wordlist(self, context: dict[str, Any]) -> list[str]:
        """Return wordlist entries."""
        pass

    def get_wordlist_for_tech(self, tech: str) -> list[str]:
        return self.get_wordlist({})


class OutputPlugin(ABC):
    """Base class for custom output/report plugins."""
    name: str = "unnamed_output"
    format: str = "custom"

    @abstractmethod
    def render(self, session_data: dict[str, Any], findings: list[Finding]) -> str | bytes:
        """Render findings in this format."""
        pass

    def deliver(self, rendered: str | bytes, config: dict[str, Any]) -> bool:
        """Optionally deliver output to external system."""
        return True


class PluginManifest:
    """Plugin manifest loader."""
    def __init__(self, plugin_dir: Path):
        self.dir = plugin_dir

    def load(self) -> dict[str, Any]:
        manifest_path = self.dir / "plugin.yaml"
        if not manifest_path.exists():
            return {}
        import yaml
        with open(manifest_path) as f:
            return yaml.safe_load(f) or {}
