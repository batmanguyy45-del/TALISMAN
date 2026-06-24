"""
TALISMAN Web Dashboard — local UI for viewing sessions, findings, and reports.
Run with:  python -m talisman.web.dashboard
"""
from __future__ import annotations
import webbrowser
from pathlib import Path
from typing import Any

try:
    import uvicorn
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse
except ImportError:
    print("Install web dependencies: pip install 'talisman[web]'")
    raise SystemExit(1)

from talisman.engine.session import SessionManager

app = FastAPI(title="TALISMAN Dashboard", version="1.0.0")

HTML_STYLES = """
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #0d1117; color: #c9d1d9; padding: 2rem; }
  h1 { color: #58a6ff; margin-bottom: 1rem; font-weight: 600; }
  h2 { color: #8b949e; margin: 1.5rem 0 0.5rem; font-size: 1.2rem;
       border-bottom: 1px solid #21262d; padding-bottom: 0.3rem; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
          padding: 1.2rem; margin-bottom: 1rem; }
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px,1fr)); gap: 1rem; }
  .stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; }
  .stat-value { font-size: 1.8rem; font-weight: 700; color: #58a6ff; }
  .stat-label { font-size: 0.8rem; color: #8b949e; text-transform: uppercase; }
  .sev-critical { color: #f85149; }
  .sev-high { color: #d29922; }
  .sev-medium { color: #58a6ff; }
  .sev-low { color: #3fb950; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
  th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid #21262d; font-size: 0.9rem; }
  th { color: #8b949e; font-weight: 600; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 10px;
           font-size: 0.75rem; font-weight: 600; }
  .badge-critical { background: #f8514920; color: #f85149; border: 1px solid #f8514960; }
  .badge-high { background: #d2992220; color: #d29922; border: 1px solid #d2992260; }
  .badge-medium { background: #58a6ff20; color: #58a6ff; border: 1px solid #58a6ff60; }
  .badge-low { background: #3fb95020; color: #3fb950; border: 1px solid #3fb95060; }
  .badge-info { background: #8b949e20; color: #8b949e; border: 1px solid #8b949e60; }
  .nav { margin-bottom: 1.5rem; }
  .nav a { margin-right: 1rem; color: #8b949e; }
  .nav a.active { color: #58a6ff; font-weight: 600; }
</style>
"""


def _render_sessions() -> str:
    sm = SessionManager()
    sessions = sm.list_sessions()
    total_findings = 0
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    session_rows = ""
    for sname in sessions:
        sess = sm.get(sname)
        import asyncio
        async def get_stats():
            await sess.open()
            s = await sess.summary()
            findings = await sess.get_findings()
            targets = await sess.get_targets()
            await sess.close()
            return s, findings, targets
        s, f, t = asyncio.run(get_stats())
        total_findings += s.get("total_findings", 0)
        for sev, cnt in s.get("severity_breakdown", {}).items():
            if sev in sev_counts:
                sev_counts[sev] += cnt
        sev_str = " ".join(
            f'<span class="sev-{sev}">{sev.upper()}: {s.get("severity_breakdown", {}).get(sev, 0)}</span>'
            for sev in ["critical", "high", "medium", "low"]
        )
        session_rows += f"""
        <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <div><strong><a href="#">{sname}</a></strong></div>
                <div style="font-size:0.85rem;color:#8b949e">{s.get("targets_count",0)} targets | {s.get("total_findings",0)} findings</div>
            </div>
            <div style="margin-top:0.5rem;font-size:0.85rem">{sev_str}</div>
            <div style="margin-top:0.3rem;font-size:0.8rem;color:#8b949e">{s.get("modules_run",0)} modules run</div>
        </div>
        """
    stats = "".join(
        f'<div class="stat"><div class="stat-value">{v}</div><div class="stat-label">{k.upper()}</div></div>'
        for k, v in [("sessions", len(sessions)), ("findings", total_findings)]
    )
    return f"""<!DOCTYPE html><html><head><title>TALISMAN Dashboard</title>{HTML_STYLES}</head><body>
<h1>TALISMAN</h1>
<div class="nav">
    <a href="#" class="active">Dashboard</a>
    <a href="#">Sessions</a>
    <a href="#">Findings</a>
    <a href="#">Reports</a>
</div>
<div class="stat-grid">{stats}</div>
<h2>Sessions</h2>
{session_rows if sessions else '<div class="card">No sessions yet. Run: talisman autopilot -t example.com -s my-session</div>'}
</body></html>"""


def _render_findings(severity: str | None = None) -> str:
    sm = SessionManager()
    sessions = sm.list_sessions()
    rows = ""
    for sname in sessions:
        sess = sm.get(sname)
        import asyncio
        async def get_f():
            await sess.open()
            filt = [severity] if severity else None
            findings = await sess.get_findings(severity=filt)
            await sess.close()
            return findings
        findings = asyncio.run(get_f())
        for f in findings:
            sev = f.get("severity", "info").lower()
            rows += f"""<tr>
<td><span class="badge badge-{sev}">{sev.upper()}</span></td>
<td>{f.get("module", "?")}</td>
<td>{f.get("vuln_type", "?")}</td>
<td>{f.get("target", "?")[:60]}</td>
<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{f.get("title", "")[:80]}</td>
</tr>"""
    return f"""<!DOCTYPE html><html><head><title>TALISMAN — Findings</title>{HTML_STYLES}</head><body>
<h1>Findings</h1>
<div class="nav">
    <a href="/">Dashboard</a>
    <a href="/findings" class="active">All Findings</a>
</div>
<table>
<thead><tr><th>Severity</th><th>Module</th><th>Type</th><th>Target</th><th>Title</th></tr></thead>
<tbody>{rows if rows else '<tr><td colspan="5" style="text-align:center;color:#8b949e">No findings</td></tr>'}</tbody>
</table>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return _render_sessions()


@app.get("/findings", response_class=HTMLResponse)
@app.get("/findings/{severity}", response_class=HTMLResponse)
async def findings(severity: str | None = None):
    return _render_findings(severity)


def main(port: int = 9191, open_browser: bool = True) -> None:
    print(f"[+] TALISMAN Dashboard: http://127.0.0.1:{port}")
    if open_browser:
        webbrowser.open(f"http://127.0.0.1:{port}")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
