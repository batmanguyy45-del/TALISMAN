"""Report engine — generates HTML, Markdown, JSON reports from session findings."""
from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#2563eb",
    "info":     "#6b7280",
}
SEVERITY_BADGES = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}


class ReportEngine:
    def __init__(self, session_name: str, findings: list[dict[str, Any]],
                 targets: list[dict[str, Any]], output_dir: Path):
        self.session = session_name
        self.findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99))
        self.targets = targets
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_at = datetime.utcnow().isoformat() + "Z"

    def _severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def generate_json(self) -> Path:
        out = self.output_dir / f"{self.session}_report.json"
        report = {
            "session": self.session,
            "generated_at": self.generated_at,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self._severity_counts(),
                "targets": len(self.targets),
            },
            "targets": self.targets,
            "findings": self.findings,
        }
        out.write_text(json.dumps(report, indent=2, default=str))
        console.print(f"  [success]✓ JSON report: {out}[/success]")
        return out

    def generate_markdown(self) -> Path:
        out = self.output_dir / f"{self.session}_report.md"
        counts = self._severity_counts()
        lines: list[str] = [
            f"# TALISMAN Security Report — {self.session}",
            f"\n**Generated:** {self.generated_at}  ",
            f"**Total Findings:** {len(self.findings)}  ",
            "\n## Executive Summary\n",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev, cnt in counts.items():
            lines.append(f"| {SEVERITY_BADGES[sev]} {sev.capitalize()} | {cnt} |")
        lines.append(f"\n**Targets scanned:** {len(self.targets)}")
        lines.append("\n---\n")
        lines.append("## Findings\n")

        for i, f in enumerate(self.findings, 1):
            sev = f.get("severity", "info")
            lines.extend([
                f"### {i}. {f.get('title', 'Untitled')}",
                f"\n**Severity:** {SEVERITY_BADGES[sev]} {sev.upper()}  ",
                f"**Target:** `{f.get('target', 'N/A')}`  ",
                f"**Module:** {f.get('module', 'N/A')}  ",
                f"**Confidence:** {f.get('confidence', 'N/A')}  ",
            ])
            if f.get("cvss_score"):
                lines.append(f"**CVSS Score:** {f['cvss_score']}  ")
            if f.get("cwe"):
                lines.append(f"**CWE:** {f['cwe']}  ")
            lines.append(f"\n**Description:**  \n{f.get('description', 'N/A')}\n")
            if f.get("request"):
                lines.extend([
                    "**Request:**",
                    "```http",
                    f.get("request", ""),
                    "```",
                ])
            if f.get("evidence"):
                lines.extend([
                    "**Evidence:**",
                    "```",
                    str(f.get("evidence", ""))[:500],
                    "```",
                ])
            if f.get("reproduction"):
                lines.append(f"\n**Steps to Reproduce:**  \n{f.get('reproduction', '')}\n")
            if f.get("remediation"):
                lines.append(f"\n**Remediation:**  \n{f.get('remediation', '')}\n")
            lines.append("\n---\n")

        out.write_text("\n".join(lines))
        console.print(f"  [success]✓ Markdown report: {out}[/success]")
        return out

    def generate_html(self) -> Path:
        out = self.output_dir / f"{self.session}_report.html"
        counts = self._severity_counts()
        svg_bars = "".join(
            f'<div class="bar-item"><div class="bar" style="height:{min(cnt*8,120)}px;background:{SEVERITY_COLORS[s]}"></div>'
            f'<div class="bar-label">{s.upper()}<br><strong>{cnt}</strong></div></div>'
            for s, cnt in counts.items() if cnt > 0
        )
        findings_html = ""
        for i, f in enumerate(self.findings, 1):
            sev = f.get("severity", "info").lower()
            color = SEVERITY_COLORS.get(sev, "#6b7280")
            req_html = f"<pre class='code'>{self._esc(f.get('request',''))}</pre>" if f.get("request") else ""
            evidence_html = f"<pre class='code'>{self._esc(str(f.get('evidence',''))[:800])}</pre>" if f.get("evidence") else ""
            findings_html += f"""
<div class='finding' id='finding-{i}'>
  <div class='finding-header' style='border-left:4px solid {color}'>
    <span class='badge' style='background:{color}'>{sev.upper()}</span>
    <span class='finding-title'>{self._esc(f.get('title',''))}</span>
    <span class='finding-target'>{self._esc(f.get('target',''))}</span>
  </div>
  <div class='finding-body'>
    <table class='meta'>
      <tr><td>Module</td><td>{self._esc(f.get('module',''))}</td></tr>
      <tr><td>Confidence</td><td>{self._esc(f.get('confidence',''))}</td></tr>
      {'<tr><td>CVSS</td><td>' + str(f.get('cvss_score','')) + '</td></tr>' if f.get('cvss_score') else ''}
      {'<tr><td>CWE</td><td>' + self._esc(f.get('cwe','')) + '</td></tr>' if f.get('cwe') else ''}
    </table>
    <h4>Description</h4><p>{self._esc(f.get('description',''))}</p>
    {'<h4>HTTP Request</h4>' + req_html if req_html else ''}
    {'<h4>Evidence</h4>' + evidence_html if evidence_html else ''}
    {'<h4>Reproduction</h4><p>' + self._esc(f.get('reproduction','')) + '</p>' if f.get('reproduction') else ''}
    {'<h4>Remediation</h4><p>' + self._esc(f.get('remediation','')) + '</p>' if f.get('remediation') else ''}
  </div>
</div>"""

        html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>TALISMAN Report — {self._esc(self.session)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  .header {{ background: linear-gradient(135deg, #1e293b, #0f172a); border: 1px solid #334155; border-radius: 12px; padding: 32px; margin-bottom: 24px; }}
  .header h1 {{ font-size: 2rem; color: #38bdf8; margin-bottom: 8px; }}
  .header p {{ color: #94a3b8; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .stat {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-num {{ font-size: 2rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; }}
  .chart {{ display: flex; align-items: flex-end; gap: 8px; height: 140px; margin-bottom: 24px; background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; }}
  .bar-item {{ display: flex; flex-direction: column; align-items: center; gap: 4px; flex: 1; }}
  .bar {{ width: 100%; border-radius: 4px 4px 0 0; min-height: 4px; transition: height 0.3s; }}
  .bar-label {{ font-size: 0.7rem; color: #94a3b8; text-align: center; }}
  .finding {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 12px; padding: 16px; background: #0f172a; }}
  .badge {{ padding: 3px 10px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; color: #fff; }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .finding-target {{ font-size: 0.8rem; color: #64748b; font-family: monospace; }}
  .finding-body {{ padding: 16px; }}
  .meta {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 0.85rem; }}
  .meta td {{ padding: 6px 12px; border-bottom: 1px solid #334155; }}
  .meta td:first-child {{ color: #94a3b8; width: 120px; }}
  h4 {{ color: #38bdf8; margin: 16px 0 8px; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .code {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 12px; font-family: 'Fira Code', 'Courier New', monospace; font-size: 0.82rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
  p {{ color: #cbd5e1; line-height: 1.6; }}
  .footer {{ text-align: center; color: #475569; padding: 32px; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <h1>🗡️ TALISMAN Security Report</h1>
    <p>Session: <strong>{self._esc(self.session)}</strong> &nbsp;·&nbsp; Generated: {self.generated_at}</p>
    <p style='margin-top:8px'>Targets: {len(self.targets)} &nbsp;·&nbsp; Total findings: {len(self.findings)}</p>
  </div>
  <div class='summary'>
    {''.join(f"<div class='stat'><div class='stat-num' style='color:{SEVERITY_COLORS[s]}'>{c}</div><div class='stat-label'>{s}</div></div>" for s,c in counts.items())}
  </div>
  <div class='chart'>{svg_bars}</div>
  {findings_html}
  <div class='footer'>Generated by TALISMAN v1.0.0 — for authorized security testing only</div>
</div>
</body>
</html>"""
        out.write_text(html)
        console.print(f"  [success]✓ HTML report: {out}[/success]")
        return out

    @staticmethod
    def _esc(s: str) -> str:
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def generate_all(self, formats: list[str] | None = None) -> list[Path]:
        fmts = formats or ["json", "markdown", "html"]
        outputs: list[Path] = []
        console.print(f"\n[module]⚡ Generating Reports[/module] — {', '.join(fmts)}")
        if "json" in fmts:
            outputs.append(self.generate_json())
        if "markdown" in fmts:
            outputs.append(self.generate_markdown())
        if "html" in fmts:
            outputs.append(self.generate_html())
        return outputs
