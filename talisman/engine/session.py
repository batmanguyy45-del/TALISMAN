"""SQLite-backed session management. Every run is persistent and resumable."""
from __future__ import annotations
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite
from talisman.utils.logger import get_logger
from talisman.utils.redaction import redact_sensitive_text, redact_sensitive_value

log = get_logger(__name__)
SESSIONS_DIR = Path.home() / ".talisman" / "sessions"
_SESSION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _validate_session_name(name: str) -> str:
    if not isinstance(name, str) or not _SESSION_NAME_RE.fullmatch(name) or name in {".", ".."}:
        raise ValueError("Invalid session name; use 1-64 letters, digits, dots, underscores or hyphens, starting with a letter or digit")
    return name

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
    return datetime.now(UTC).isoformat()

def _uid() -> str:
    return str(uuid.uuid4())

def _finding_fingerprint(finding: dict) -> str:
    target = finding.get("target", "")
    module = finding.get("module", "")
    vuln_type = finding.get("vuln_type", "")
    evidence = finding.get("evidence", "")[:200]
    return f"{target}|{module}|{vuln_type}|{hash(evidence)}"

class Session:
 def __init__(self, name: str, session_dir: Path | None = None):
  self.name = _validate_session_name(name)
  self.id = self.name
  base_dir = (session_dir or SESSIONS_DIR).expanduser()
  if base_dir.is_symlink():
   raise ValueError("Session base directory must not be a symbolic link")
  base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
  os.chmod(base_dir, 0o700)
  self.dir = base_dir / self.name
  if self.dir.is_symlink():
   raise ValueError("Session path must not be a symbolic link")
  self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
  os.chmod(self.dir, 0o700)
  self.db_path = self.dir / "session.db"
  if self.db_path.is_symlink():
   raise ValueError("Session database must not be a symbolic link")
  self.raw_dir = self.dir / "raw"
  self.screenshots_dir = self.dir / "screenshots"
  self.exports_dir = self.dir / "exports"
  for private_dir in (
   self.raw_dir,
   self.screenshots_dir,
   self.exports_dir,
  ):
   if private_dir.is_symlink():
    raise ValueError("Session data directories must not be symbolic links")
   private_dir.mkdir(exist_ok=True, mode=0o700)
   os.chmod(private_dir, 0o700)
  self._db: aiosqlite.Connection | None = None
  self._scope_token: Any = None

 def _reset_scope_context(self) -> None:
  """Restore the previous active scope exactly once."""
  token = self._scope_token
  self._scope_token = None
  if token is not None:
   from talisman.engine.scope import reset_active_scope
   reset_active_scope(token)

 @property
 def db(self) -> aiosqlite.Connection:
  """Return the open SQLite connection or fail clearly when the session is closed."""
  if self._db is None:
   raise RuntimeError("Session is not open")
  return self._db

 async def open(self) -> Session:
  if self._db is not None:
   return self
  connection: aiosqlite.Connection | None = None
  try:
   if self.db_path.is_symlink():
    raise ValueError("Session database must not be a symbolic link")
   connection = await aiosqlite.connect(str(self.db_path))
   self._db = connection
   os.chmod(self.db_path, 0o600)
   connection.row_factory = aiosqlite.Row
   # Execute schema statements separately so failures are not silently hidden.
   for stmt in (item.strip() for item in SCHEMA.split(";") if item.strip()):
    await connection.execute(stmt)
   await connection.commit()
  except BaseException:
   self._db = None
   try:
    if connection is not None:
     await connection.close()
   except BaseException as cleanup_error:
    log.warning(
     "session_open_cleanup_failed",
     error=type(cleanup_error).__name__,
    )
   finally:
    self._reset_scope_context()
   raise
  log.info("session_opened", name=self.name, db=str(self.db_path))
  return self

 async def close(self) -> None:
  connection = self._db
  self._db = None
  try:
   if connection is not None:
    await connection.close()
  finally:
   self._reset_scope_context()

 async def __aenter__(self) -> Session:
  return await self.open()

 async def __aexit__(self, *args: Any) -> None:
  await self.close()

 # ── Targets ──────────────────────────────────────────────────────────────
 async def add_target(self, host: str, **kwargs: Any) -> str:
  tid = _uid()
  now = _now()
  safe_host = redact_sensitive_text(host)
  safe_kwargs = redact_sensitive_value(kwargs)
  await self.db.execute(
   "INSERT OR IGNORE INTO targets VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
   (tid, self.id, safe_host,
    safe_kwargs.get("ip"), safe_kwargs.get("port"), safe_kwargs.get("protocol"),
    json.dumps(safe_kwargs.get("tech_stack", [])),
    safe_kwargs.get("status", "active"),
    safe_kwargs.get("waf_detected"),
    safe_kwargs.get("notes"),
    now, now)
  )
  await self.db.commit()
  return tid

 async def get_targets(self) -> list[dict[str, Any]]:
  async with self.db.execute("SELECT * FROM targets WHERE session_id=?", (self.id,)) as cur:
   rows = await cur.fetchall()
  return [dict(r) for r in rows]

 # ── Findings ─────────────────────────────────────────────────────────────
 async def add_finding(
  self, target: str, module: str, vuln_type: str, severity: str,
  confidence: str, title: str, **kwargs: Any
 ) -> str | None:
  safe_target = redact_sensitive_text(target)
  safe_module = redact_sensitive_text(module)
  safe_vuln_type = redact_sensitive_text(vuln_type)
  safe_severity = redact_sensitive_text(severity)
  safe_confidence = redact_sensitive_text(confidence)
  safe_title = redact_sensitive_text(title)
  safe_kwargs = redact_sensitive_value(kwargs)

  evidence_value = safe_kwargs.get("evidence", "") or ""
  async with self.db.execute(
   "SELECT id FROM findings WHERE session_id=? AND target=? AND module=? "
   "AND vuln_type=? AND ((? <> '' AND COALESCE(evidence, '') = ?) "
   "OR (? = '' AND title = ?))",
   (
    self.id, safe_target, safe_module, safe_vuln_type,
    evidence_value, evidence_value, evidence_value, safe_title,
   )
  ) as cur:
   existing = await cur.fetchone()
  if existing:
   log.debug(
    "finding_duplicate_skipped",
    target=safe_target,
    vuln_type=safe_vuln_type,
   )
   return None

  fid = _uid()
  now = _now()
  await self.db.execute(
   """INSERT INTO findings
    (id,session_id,target,module,vuln_type,severity,confidence,title,
    description,request,response,evidence,reproduction,remediation,
    cvss_score,cwe,cve_refs,ref_urls,extra,status,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
   (
    fid, self.id, safe_target, safe_module, safe_vuln_type,
    safe_severity, safe_confidence, safe_title,
    safe_kwargs.get("description"),
    safe_kwargs.get("request"),
    safe_kwargs.get("response"),
    evidence_value,
    safe_kwargs.get("reproduction"),
    safe_kwargs.get("remediation"),
    safe_kwargs.get("cvss_score"),
    safe_kwargs.get("cwe"),
    json.dumps(safe_kwargs.get("cve_refs", [])),
    json.dumps(safe_kwargs.get("references", [])),
    json.dumps(safe_kwargs.get("extra", {})),
    safe_kwargs.get("status", "open"),
    now, now,
   )
  )
  await self.db.commit()
  log.info(
   "finding_saved",
   id=fid,
   title=safe_title,
   severity=safe_severity,
   target=safe_target,
  )
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
  async with self.db.execute(query, params) as cur:
   rows = await cur.fetchall()
  return [dict(r) for r in rows]

 async def update_finding_status(self, finding_id: str, status: str) -> None:
  await self.db.execute(
   "UPDATE findings SET status=?, updated_at=? WHERE id=?",
   (status, _now(), finding_id)
  )
  await self.db.commit()

 async def finding_count_by_severity(self) -> dict[str, int]:
  async with self.db.execute(
   "SELECT severity, COUNT(*) as cnt FROM findings WHERE session_id=? GROUP BY severity",
   (self.id,)
  ) as cur:
   rows = await cur.fetchall()
  return {r["severity"]: r["cnt"] for r in rows}

 # ── Module runs ───────────────────────────────────────────────────────────
 async def start_module_run(self, module: str, target: str | None = None) -> str:
  rid = _uid()
  safe_module = redact_sensitive_text(module)
  safe_target = redact_sensitive_text(target) if target is not None else None
  await self.db.execute(
   "INSERT INTO module_runs VALUES (?,?,?,?,?,?,?,?,?)",
   (rid, self.id, safe_module, safe_target, _now(), None, "running", None, None)
  )
  await self.db.commit()
  return rid

 async def complete_module_run(
  self, run_id: str, status: str = "success",
  error: str | None = None, summary: str | None = None
 ) -> None:
  safe_error = redact_sensitive_text(error) if error is not None else None
  safe_summary = redact_sensitive_text(summary) if summary is not None else None
  await self.db.execute(
   "UPDATE module_runs SET completed_at=?,status=?,error=?,output_summary=? WHERE id=?",
   (_now(), status, safe_error, safe_summary, run_id)
  )
  await self.db.commit()

 # ── Notes ─────────────────────────────────────────────────────────────────
 async def add_note(self, note: str) -> str:
  nid = _uid()
  safe_note = redact_sensitive_text(note)
  await self.db.execute(
   "INSERT INTO session_notes VALUES (?,?,?,?)",
   (nid, self.id, safe_note, _now())
  )
  await self.db.commit()
  return nid

 async def get_notes(self) -> list[dict]:
  async with self.db.execute(
   "SELECT * FROM session_notes WHERE session_id=? ORDER BY created_at",
   (self.id,)
  ) as cur:
   rows = await cur.fetchall()
  return [dict(r) for r in rows]

 # ── Summary ───────────────────────────────────────────────────────────────
 async def summary(self) -> dict[str, Any]:
  counts = await self.finding_count_by_severity()
  targets = await self.get_targets()
  async with self.db.execute(
   "SELECT COUNT(*) FROM module_runs WHERE session_id=?",
   (self.id,),
  ) as cursor:
   row = await cursor.fetchone()
  modules_run = int(row[0]) if row else 0
  total_findings = sum(counts.values())
  return {
   "session": self.name,
   "targets": len(targets),
   "targets_count": len(targets),
   "findings": counts,
   "severity_breakdown": counts,
   "total_findings": total_findings,
   "modules_run": modules_run,
  }


class SessionManager:
 def __init__(self, base_dir: Path | None = None):
  self._base = (base_dir or SESSIONS_DIR).expanduser()
  if self._base.is_symlink():
   raise ValueError("Session base directory must not be a symbolic link")
  self._base.mkdir(parents=True, exist_ok=True, mode=0o700)
  os.chmod(self._base, 0o700)

 def list_sessions(self) -> list[str]:
  return sorted(
   path.name
   for path in self._base.iterdir()
   if path.is_dir()
   and not path.is_symlink()
   and _SESSION_NAME_RE.fullmatch(path.name)
  )

 def get(self, name: str) -> Session:
  return Session(_validate_session_name(name), self._base)

 def create(self, name: str) -> Session:
  s = Session(name, self._base)
  log.info("session_created", name=name)
  return s

 def exists(self, name: str) -> bool:
  path = self._base / _validate_session_name(name)
  if path.is_symlink():
   raise ValueError("Session path must not be a symbolic link")
  return path.is_dir()

 def delete(self, name: str) -> None:
  import shutil
  path = self._base / _validate_session_name(name)
  if path.is_symlink():
   raise ValueError("Session path must not be a symbolic link")
  if path.exists():
   shutil.rmtree(path)
   log.info("session_deleted", name=name)
