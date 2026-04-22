"""AI engine — multi-provider support for triage, planning, and report writing."""
from __future__ import annotations
import json
import os
from typing import Any
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

SYSTEM_TRIAGE = """You are a professional bug bounty security analyst.
Given a list of findings, you will:
1. Identify false positives and explain why
2. Cluster duplicate findings by root cause
3. Assign confidence scores (0-100)
4. Prioritize by exploitability and impact
Return a JSON object with: {triaged: [{id, confidence, is_fp, fp_reason, priority, notes}]}"""

SYSTEM_ATTACK_PLANNER = """You are an expert red team operator and bug bounty hunter.
Given reconnaissance data about a target, create a prioritized attack plan.
Focus on highest-impact, most realistic attack chains.
Return JSON: {attack_plan: [{priority, target, technique, chain, expected_impact, commands}]}"""

SYSTEM_REPORT_WRITER = """You are a professional security researcher writing bug bounty reports.
Write clear, professional reports that get triaged and paid.
Include: summary, impact, steps to reproduce, PoC, remediation.
Format for the specified platform (HackerOne/Bugcrowd/Intigriti)."""

SYSTEM_QA = """You are a security analyst with access to a session's findings and targets.
Answer questions about the assessment data accurately and concisely.
Cite specific findings by title when relevant."""


class AIEngine:
    def __init__(
        self,
        provider: str = "anthropic",
        model: str = "claude-sonnet-4-5-20251001",
        api_key: str | None = None,
        anonymize: bool = True,
    ):
        self.provider = provider
        self.model = model
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.anonymize = anonymize
        self._available = bool(self.api_key)

    def _anonymize_finding(self, finding: dict) -> dict:
        """Strip PII and sensitive data before sending to AI."""
        safe = {
            "id": finding.get("id", "")[:8],
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "vuln_type": finding.get("vuln_type", ""),
            "module": finding.get("module", ""),
            "confidence": finding.get("confidence", ""),
            "target_domain": finding.get("target", "").split("//")[-1].split("/")[0],
        }
        return safe

    async def _call_anthropic(self, system: str, prompt: str) -> str:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "max_tokens": 4096,
                        "system": system,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                if r.status_code == 200:
                    return r.json()["content"][0]["text"]
                return f"AI API error: {r.status_code}"
        except Exception as e:
            return f"AI error: {e}"

    async def _call_ollama(self, system: str, prompt: str) -> str:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=120) as client:
                r = await client.post(
                    "http://localhost:11434/api/generate",
                    json={
                        "model": self.model,
                        "prompt": f"{system}\n\n{prompt}",
                        "stream": False,
                    },
                )
                if r.status_code == 200:
                    return r.json().get("response", "")
                return f"Ollama error: {r.status_code}"
        except Exception as e:
            return f"Ollama error: {e}"

    async def _call(self, system: str, prompt: str) -> str:
        if not self._available and self.provider != "ollama":
            return "AI not configured — set ANTHROPIC_API_KEY or OPENAI_API_KEY"
        if self.provider == "anthropic":
            return await self._call_anthropic(system, prompt)
        if self.provider == "ollama":
            return await self._call_ollama(system, prompt)
        return "Provider not supported"

    async def triage_findings(self, findings: list[dict]) -> dict[str, Any]:
        """AI-powered finding triage — FP detection, dedup, prioritization."""
        console.print(f"  [dim]AI triage: {len(findings)} findings...[/dim]")
        safe_findings = [self._anonymize_finding(f) for f in findings] if self.anonymize else findings
        prompt = f"Triage these security findings:\n{json.dumps(safe_findings[:50], indent=2)}"
        response = await self._call(SYSTEM_TRIAGE, prompt)
        try:
            clean = response.strip()
            if "```" in clean:
                clean = clean.split("```json")[-1].split("```")[0]
            return json.loads(clean)
        except Exception:
            return {"raw_response": response, "triaged": []}

    async def plan_attack(self, recon_data: dict) -> dict[str, Any]:
        """Generate prioritized attack plan from recon data."""
        console.print("  [dim]AI attack planning...[/dim]")
        safe = {
            "technologies": recon_data.get("technologies", []),
            "subdomains_count": len(recon_data.get("subdomains", [])),
            "open_ports": recon_data.get("open_ports", []),
            "waf": recon_data.get("waf"),
            "endpoints_count": len(recon_data.get("endpoints", [])),
        }
        prompt = f"Create an attack plan for this target:\n{json.dumps(safe, indent=2)}"
        response = await self._call(SYSTEM_ATTACK_PLANNER, prompt)
        try:
            clean = response.strip()
            if "```" in clean:
                clean = clean.split("```json")[-1].split("```")[0]
            return json.loads(clean)
        except Exception:
            return {"raw_response": response, "attack_plan": []}

    async def write_report(
        self, finding: dict, platform: str = "hackerone"
    ) -> str:
        """Auto-generate professional bug report for a finding."""
        console.print(f"  [dim]AI report generation for: {finding.get('title','')[:50]}[/dim]")
        safe = self._anonymize_finding(finding) if self.anonymize else finding
        prompt = (
            f"Write a professional {platform} bug report for:\n"
            f"{json.dumps(safe, indent=2)}\n\n"
            f"Description: {finding.get('description','')}\n"
            f"Evidence: {finding.get('evidence','')[:200]}\n"
            f"Remediation: {finding.get('remediation','')}"
        )
        return await self._call(SYSTEM_REPORT_WRITER, prompt)

    async def ask(self, question: str, session_data: dict) -> str:
        """Q&A over session findings."""
        context = (
            f"Session: {session_data.get('session','')}\n"
            f"Targets: {session_data.get('targets', 0)}\n"
            f"Total findings: {session_data.get('total_findings', 0)}\n"
            f"Findings by severity: {session_data.get('findings', {})}\n"
        )
        prompt = f"Session data:\n{context}\n\nQuestion: {question}"
        return await self._call(SYSTEM_QA, prompt)
