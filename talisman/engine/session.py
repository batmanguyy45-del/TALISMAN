"""SQLite-backed session management. Every run is persistent and resumable."""
from __future__ import annotations
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
import aiosqlite
from talisman.utils.logger import get_logger

log = get_logger(__name__)
SESSIONS_DIR = Path.home() / ".talisman" / "sessions"

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    host TEXT NOT NULL,
    ip TEXT,
    port INTEGER,
    protocol TEXT,
    tech_stack TEXT,
    status TEXT DEFAULT 'active',
    waf_detected TEXT,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    target TEXT NOT NULL,
    module TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    request TEXT,
    response TEXT,
    evidence TEXT,
    reproduction TEXT,
    remediation TEXT,
    cvss_score REAL,
    cwe TEXT,
    cve_refs TEXT,
    ref_urls TEXT,
    extra TEXT,
    status TEXT DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS module_runs (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    module TEXT NOT NULL,
    target TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT DEFAULT 'running',
    error TEXT,
    output_summary TEXT
);
CREATE TABLE IF NOT EXISTS chain_runs (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    chain_name TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT DEFAULT 'running',
    step_outputs TEXT,
    error TEXT
);
CREATE TABLE IF NOT EXISTS session_notes (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_targets_session ON targets(session_id);
"""

def _now() -> str:
    return datetime.utcnow().isoformat()

def _uid() -> str:
    return str(uuid.uuid4())

class Session:
    def __init__(self, name: str, session_dir: Path | None = None):
        self.name = name
        self.id = name
        self.dir = (session_dir or SESSIONS_DIR) / name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.dir / "session.db"
        self.raw_dir = self.dir / "raw"
        self.raw_dir.mkdir(exist_ok=True)
        self.screenshots_dir = self.dir / "screenshots"
        self.screenshots_dir.mkdir(exist_ok=True)
        self.exports_dir = self.dir / "exports"
        self.exports_dir.mkdir(exist_ok=True)
        self._db: aiosqlite.Connection | None = None

    async def open(self) -> "Session":
        self._db = await aiosqlite.connect(str(self.db_path))
        self._db.row_factory = aiosqlite.Row
        # Execute each statement separately to avoid reserved-word issues with executescript
        for stmt in [s.strip() for s in SCHEMA.split(";") if s.strip()]:
            try:
                await self._db.execute(stmt)
            except Exception as e:
                log.debug("schema_stmt_skip", error=str(e), stmt=stmt[:60])
        await self._db.commit()
        log.info("session_opened", name=self.name, db=str(self.db_path))
        return self

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def __aenter__(self) -> "Session":
        return await self.open()

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # ── Targets ──────────────────────────────────────────────────────────────
    async def add_target(self, host: str, **kwargs: Any) -> str:
        tid = _uid()
        now = _now()
        await self._db.execute(
            "INSERT OR IGNORE INTO targets VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid, self.id, host,
             kwargs.get("ip"), kwargs.get("port"), kwargs.get("protocol"),
             json.dumps(kwargs.get("tech_stack", [])),
             kwargs.get("status", "active"),
             kwargs.get("waf_detected"),
             kwargs.get("notes"),
             now, now)
        )
        await self._db.commit()
        return tid

    async def get_targets(self) -> list[dict]:
        async with self._db.execute("SELECT * FROM targets WHERE session_id=?", (self.id,)) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ── Findings ─────────────────────────────────────────────────────────────
    async def add_finding(
        self, target: str, module: str, vuln_type: str, severity: str,
        confidence: str, title: str, **kwargs: Any
    ) -> str:
        fid = _uid()
        now = _now()
        await self._db.execute(
            """INSERT INTO findings
               (id,session_id,target,module,vuln_type,severity,confidence,title,
                description,request,response,evidence,reproduction,remediation,
                cvss_score,cwe,cve_refs,ref_urls,extra,status,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (fid, self.id, target, module, vuln_type, severity, confidence, title,
             kwargs.get("description"), kwargs.get("request"), kwargs.get("response"),
             kwargs.get("evidence"), kwargs.get("reproduction"), kwargs.get("remediation"),
             kwargs.get("cvss_score"), kwargs.get("cwe"),
             json.dumps(kwargs.get("cve_refs", [])),
             json.dumps(kwargs.get("references", [])),
             json.dumps(kwargs.get("extra", {})),
             kwargs.get("status", "open"),
             now, now)
        )
        await self._db.commit()
        log.info("finding_saved", id=fid, title=title, severity=severity, target=target)
        return fid

    async def get_findings(
        self, severity: list[str] | None = None, status: str | None = None
    ) -> list[dict]:
        query = "SELECT * FROM findings WHERE session_id=?"
        params: list[Any] = [self.id]
        if severity:
            placeholders = ",".join("?" for _ in severity)
            query += f" AND severity IN ({placeholders})"
            params.extend(severity)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
        async with self._db.execute(query, params) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def update_finding_status(self, finding_id: str, status: str) -> None:
        await self._db.execute(
            "UPDATE findings SET status=?, updated_at=? WHERE id=?",
            (status, _now(), finding_id)
        )
        await self._db.commit()

    async def finding_count_by_severity(self) -> dict[str, int]:
        async with self._db.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings WHERE session_id=? GROUP BY severity",
            (self.id,)
        ) as cur:
            rows = await cur.fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    # ── Module runs ───────────────────────────────────────────────────────────
    async def start_module_run(self, module: str, target: str | None = None) -> str:
        rid = _uid()
        await self._db.execute(
            "INSERT INTO module_runs VALUES (?,?,?,?,?,?,?,?,?)",
            (rid, self.id, module, target, _now(), None, "running", None, None)
        )
        await self._db.commit()
        return rid

    async def complete_module_run(
        self, run_id: str, status: str = "success",
        error: str | None = None, summary: str | None = None
    ) -> None:
        await self._db.execute(
            "UPDATE module_runs SET completed_at=?,status=?,error=?,output_summary=? WHERE id=?",
            (_now(), status, error, summary, run_id)
        )
        await self._db.commit()

    # ── Notes ─────────────────────────────────────────────────────────────────
    async def add_note(self, note: str) -> str:
        nid = _uid()
        await self._db.execute(
            "INSERT INTO session_notes VALUES (?,?,?,?)",
            (nid, self.id, note, _now())
        )
        await self._db.commit()
        return nid

    async def get_notes(self) -> list[dict]:
        async with self._db.execute(
            "SELECT * FROM session_notes WHERE session_id=? ORDER BY created_at",
            (self.id,)
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ── Summary ───────────────────────────────────────────────────────────────
    async def summary(self) -> dict[str, Any]:
        counts = await self.finding_count_by_severity()
        targets = await self.get_targets()
        return {
            "session": self.name,
            "targets": len(targets),
            "findings": counts,
            "total_findings": sum(counts.values()),
        }


class SessionManager:
    def __init__(self, base_dir: Path | None = None):
        self._base = base_dir or SESSIONS_DIR
        self._base.mkdir(parents=True, exist_ok=True)

    def list_sessions(self) -> list[str]:
        return sorted(p.name for p in self._base.iterdir() if p.is_dir())

    def get(self, name: str) -> Session:
        return Session(name, self._base)

    def create(self, name: str) -> Session:
        s = Session(name, self._base)
        log.info("session_created", name=name)
        return s

    def exists(self, name: str) -> bool:
        return (self._base / name).exists()

    def delete(self, name: str) -> None:
        import shutil
        path = self._base / name
        if path.exists():
            shutil.rmtree(path)
            log.info("session_deleted", name=name)
