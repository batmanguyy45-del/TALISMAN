"""AI engine — multi-provider support for triage, planning, and report writing."""
from __future__ import annotations
import json
import os
from typing import Any
from talisman.engine.scope import ScopeConfig, ScopeEnforcer
from talisman.utils.http_client import TalismanHTTPClient
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
  if api_key:
   self.api_key = api_key
  elif provider == "openai":
   self.api_key = os.getenv("OPENAI_API_KEY")
  elif provider == "anthropic":
   self.api_key = os.getenv("ANTHROPIC_API_KEY")
  else:
   self.api_key = None
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
   provider_scope = ScopeEnforcer(
    ScopeConfig(
     include=["api.anthropic.com"],
     exclude=[],
     service_allowlist=[],
     allow_state_changing_requests=True,
     avoid_writes=False,
    )
   )
   async with TalismanHTTPClient(
    scope=provider_scope,
    timeout=60,
    verify_ssl=True,
    follow_redirects=False,
   ) as client:
    response = await client.post(
     "https://api.anthropic.com/v1/messages",
     headers={
      "x-api-key": self.api_key or "",
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
    if response.status_code == 200:
     return response.json()["content"][0]["text"]
    return f"AI API error: {response.status_code}"
  except Exception as exc:
   log.warning("anthropic_request_failed", error=type(exc).__name__)
   return "AI provider request failed"

 async def _call_openai(self, system: str, prompt: str) -> str:
  try:
   provider_scope = ScopeEnforcer(
    ScopeConfig(
     include=["api.openai.com"],
     exclude=[],
     service_allowlist=[],
     allow_state_changing_requests=True,
     avoid_writes=False,
    )
   )
   async with TalismanHTTPClient(
    scope=provider_scope,
    timeout=60,
    verify_ssl=True,
    follow_redirects=False,
   ) as client:
    response = await client.post(
     "https://api.openai.com/v1/chat/completions",
     headers={"Authorization": f"Bearer {self.api_key or ''}"},
     json={
      "model": self.model,
      "messages": [
       {"role": "system", "content": system},
       {"role": "user", "content": prompt},
      ],
     },
    )
    if response.status_code == 200:
     return response.json()["choices"][0]["message"]["content"]
    return f"AI API error: {response.status_code}"
  except Exception as exc:
   log.warning("openai_request_failed", error=type(exc).__name__)
   return "AI provider request failed"

 async def _call_ollama(self, system: str, prompt: str) -> str:
  try:
   provider_scope = ScopeEnforcer(
    ScopeConfig(
     include=["localhost", "127.0.0.1", "::1"],
     exclude=[],
     service_allowlist=[],
     allow_state_changing_requests=True,
     avoid_writes=False,
    )
   )
   async with TalismanHTTPClient(
    scope=provider_scope,
    timeout=120,
    verify_ssl=True,
    follow_redirects=False,
   ) as client:
    response = await client.post(
     "http://localhost:11434/api/generate",
     json={
      "model": self.model,
      "prompt": f"{system}\\n\\n{prompt}",
      "stream": False,
     },
    )
    if response.status_code == 200:
     return response.json().get("response", "")
    return f"Ollama error: {response.status_code}"
  except Exception as exc:
   log.warning("ollama_request_failed", error=type(exc).__name__)
   return "Ollama request failed"

 async def _call(self, system: str, prompt: str) -> str:
  if not self._available and self.provider != "ollama":
   return "AI not configured — set ANTHROPIC_API_KEY or OPENAI_API_KEY"
  if self.provider == "anthropic":
   return await self._call_anthropic(system, prompt)
  if self.provider == "openai":
   return await self._call_openai(system, prompt)
  if self.provider == "ollama":
   return await self._call_ollama(system, prompt)
  return "Provider not supported"

 async def triage_findings(self, findings: list[dict]) -> dict[str, Any]:
  """AI-powered finding triage — FP detection, dedup, prioritization."""
  console.print(f" [dim]AI triage: {len(findings)} findings...[/dim]")
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
  console.print(" [dim]AI attack planning...[/dim]")
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
  console.print(f" [dim]AI report generation for: {finding.get('title','')[:50]}[/dim]")
  safe = self._anonymize_finding(finding) if self.anonymize else finding
  if self.anonymize:
   description = "[omitted in privacy mode]"
   evidence = "[omitted in privacy mode]"
   remediation = "[omitted in privacy mode]"
  else:
   description = finding.get("description", "")
   evidence = finding.get("evidence", "")[:200]
   remediation = finding.get("remediation", "")
  prompt = (
   f"Write a professional {platform} bug report for:\n"
   f"{json.dumps(safe, indent=2)}\n\n"
   f"Description: {description}\n"
   f"Evidence: {evidence}\n"
   f"Remediation: {remediation}"
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
