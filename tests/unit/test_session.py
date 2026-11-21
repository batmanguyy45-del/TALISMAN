"""Unit tests for session management."""
import asyncio
import pytest
import tempfile
from pathlib import Path
from talisman.engine.session import Session, SessionManager

@pytest.fixture
def tmp_session_dir(tmp_path):
 return tmp_path

@pytest.mark.asyncio
async def test_session_create_open(tmp_session_dir):
 sess = Session("test-session", tmp_session_dir)
 async with sess:
  assert sess.db_path.exists()

@pytest.mark.asyncio
async def test_add_and_get_finding(tmp_session_dir):
 sess = Session("test-session", tmp_session_dir)
 async with sess:
  fid = await sess.add_finding(
   target="https://example.com",
   module="xss",
   vuln_type="reflected_xss",
   severity="high",
   confidence="confirmed",
   title="Test XSS Finding",
   description="Test description",
  )
  assert fid is not None
  findings = await sess.get_findings()
  assert len(findings) == 1
  assert findings[0]["title"] == "Test XSS Finding"

@pytest.mark.asyncio
async def test_severity_filter(tmp_session_dir):
 sess = Session("test-session", tmp_session_dir)
 async with sess:
  await sess.add_finding("t", "m", "xss", "high", "confirmed", "High Finding")
  await sess.add_finding("t", "m", "sqli", "low", "confirmed", "Low Finding")
  highs = await sess.get_findings(severity=["high"])
  assert len(highs) == 1
  assert highs[0]["severity"] == "high"

@pytest.mark.asyncio
async def test_summary(tmp_session_dir):
 sess = Session("test-session", tmp_session_dir)
 async with sess:
  await sess.add_finding("t", "m", "xss", "critical", "confirmed", "Crit")
  await sess.add_finding("t", "m", "sqli", "high", "confirmed", "High")
  summary = await sess.summary()
  assert summary["total_findings"] == 2
  assert summary["findings"]["critical"] == 1
  assert summary["findings"]["high"] == 1

@pytest.mark.asyncio
async def test_module_run_tracking(tmp_session_dir):
 sess = Session("test-session", tmp_session_dir)
 async with sess:
  run_id = await sess.start_module_run("xss", "https://example.com")
  assert run_id is not None
  await sess.complete_module_run(run_id, status="success", summary="Found 2 issues")

@pytest.mark.asyncio
async def test_notes(tmp_session_dir):
 sess = Session("test-session", tmp_session_dir)
 async with sess:
  await sess.add_note("First login uses JWT HS256")
  notes = await sess.get_notes()
  assert len(notes) == 1
  assert "JWT" in notes[0]["note"]

def test_session_manager(tmp_session_dir):
 sm = SessionManager(tmp_session_dir)
 sm.create("bounty-q1")
 sm.create("bounty-q2")
 sessions = sm.list_sessions()
 assert "bounty-q1" in sessions
 assert "bounty-q2" in sessions
 assert sm.exists("bounty-q1")
 sm.delete("bounty-q1")
 assert not sm.exists("bounty-q1")



def test_session_names_cannot_escape_base_directory(tmp_path):
    from talisman.engine.session import Session

    with pytest.raises(ValueError):
        Session("../outside", tmp_path)
    with pytest.raises(ValueError):
        Session("nested/name", tmp_path)


def test_session_directory_permissions_are_private(tmp_path):
    import stat

    sess = Session("private-session", tmp_path)
    assert stat.S_IMODE(sess.dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(sess.raw_dir.stat().st_mode) == 0o700


@pytest.mark.asyncio
async def test_empty_evidence_does_not_hide_distinct_findings(tmp_path):
    sess = Session("empty-evidence", tmp_path)
    async with sess:
        first = await sess.add_finding("https://example.com", "scanner", "issue", "low", "low", "First")
        second = await sess.add_finding("https://example.com", "scanner", "issue", "low", "low", "Second")
        assert first is not None
        assert second is not None
        assert len(await sess.get_findings()) == 2


def test_session_manager_rejects_traversal_for_delete_and_exists(tmp_path):
    sm = SessionManager(tmp_path)
    with pytest.raises(ValueError):
        sm.exists("../outside")
    with pytest.raises(ValueError):
        sm.delete("../outside")



@pytest.mark.asyncio
async def test_open_is_idempotent_and_scope_is_reset_on_close(tmp_path):
    from talisman.engine.scope import (
        ScopeConfig,
        ScopeEnforcer,
        get_active_scope,
        set_active_scope,
    )

    sess = Session("scope-lifetime", tmp_path)
    scope = ScopeEnforcer(ScopeConfig(include=["example.com"], service_allowlist=[]))
    sess._scope_token = set_active_scope(scope)

    await sess.open()
    first_connection = sess._db
    await sess.open()
    assert sess._db is first_connection

    await sess.close()
    assert get_active_scope() is None



@pytest.mark.asyncio
async def test_summary_exposes_dashboard_compatible_counts(tmp_path):
    sess = Session("dashboard-summary", tmp_path)
    async with sess:
        await sess.add_target("example.com")
        await sess.add_finding(
            "https://example.com",
            "scanner",
            "xss",
            "medium",
            "likely",
            "Possible XSS",
            evidence="controlled evidence",
        )
        await sess.start_module_run("scanner.xss", "https://example.com")
        summary = await sess.summary()

    assert summary["targets_count"] == 1
    assert summary["severity_breakdown"]["medium"] == 1
    assert summary["total_findings"] == 1
    assert summary["modules_run"] == 1


def test_session_constructor_rejects_database_symlink(tmp_path):
    import pytest

    session_dir = tmp_path / "session"
    session_dir.mkdir()
    external_db = tmp_path / "external.db"
    external_db.write_text("do not overwrite", encoding="utf-8")
    (session_dir / "session.db").symlink_to(external_db)

    with pytest.raises(ValueError, match="database must not be a symbolic link"):
        Session("session", tmp_path)


def test_session_manager_ignores_symlinked_session_directories(tmp_path):
    import pytest

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "session.db").write_text("", encoding="utf-8")
    sm = SessionManager(tmp_path / "sessions")
    try:
        (sm._base / "linked-session").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are not available on this platform")

    assert "linked-session" not in sm.list_sessions()


@pytest.mark.asyncio
async def test_add_finding_redacts_credentials_before_persistence(tmp_path):
    sess = Session("redaction-test", tmp_path)
    raw_token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    raw_cookie = "sessionid=super-secret-session"
    async with sess:
        finding_id = await sess.add_finding(
            "https://example.com/reset?token=raw-reset-token",
            "scanner",
            "credential_leak",
            "high",
            "confirmed",
            "Credential-bearing response",
            request=f"GET /api\nAuthorization: Bearer {raw_token}",
            response=f"Set-Cookie: {raw_cookie}",
            evidence=f"Found access token {raw_token}",
            extra={"raw": raw_token},
        )
        assert finding_id is not None
        findings = await sess.get_findings()

    assert len(findings) == 1
    serialized = str(findings[0])
    assert raw_token not in serialized
    assert raw_cookie not in serialized
    assert "raw-reset-token" not in serialized
    assert "[GITHUB_TOKEN_REDACTED]" in serialized or "[REDACTED]" in serialized


@pytest.mark.asyncio
async def test_target_and_module_run_metadata_are_redacted_before_persistence(tmp_path):
    sess = Session("metadata-redaction", tmp_path)
    target_token = "opaque-target-token-91"
    tech_secret = "opaque-tech-secret-92"
    note_password = "opaque-note-password-93"
    run_token = "opaque-run-token-94"
    error_password = "opaque-error-password-95"
    summary_token = "opaque-summary-token-96"

    async with sess:
        await sess.add_target(
            f"https://example.com/?access_token={target_token}",
            tech_stack=[{"api_key": tech_secret}],
            notes=f'{{"password": "{note_password}"}}',
        )
        run_id = await sess.start_module_run(
            "scanner.test",
            f"https://example.com/?token={run_token}",
        )
        await sess.complete_module_run(
            run_id,
            status="error",
            error=f'{{"password": "{error_password}"}}',
            summary=f'{{"access_token": "{summary_token}"}}',
        )

        async with sess.db.execute(
            "SELECT host, tech_stack, notes FROM targets WHERE session_id=?",
            (sess.id,),
        ) as cursor:
            target_row = await cursor.fetchone()
        async with sess.db.execute(
            "SELECT target, error, output_summary FROM module_runs WHERE session_id=?",
            (sess.id,),
        ) as cursor:
            run_row = await cursor.fetchone()

    persisted = str(dict(target_row)) + str(dict(run_row))
    for secret in (
        target_token,
        tech_secret,
        note_password,
        run_token,
        error_password,
        summary_token,
    ):
        assert secret not in persisted
    assert "[REDACTED]" in persisted


@pytest.mark.asyncio
async def test_session_notes_redact_serialized_credentials(tmp_path):
    sess = Session("note-redaction", tmp_path)
    note_secret = "opaque-note-json-secret-97"
    async with sess:
        await sess.add_note(f'{{"client_secret": "{note_secret}"}}')
        notes = await sess.get_notes()

    assert note_secret not in str(notes)
    assert "[REDACTED]" in str(notes)


@pytest.mark.asyncio
async def test_session_database_access_fails_clearly_after_close(tmp_path):
    sess = Session("closed-session", tmp_path)
    await sess.open()
    await sess.close()

    with pytest.raises(RuntimeError, match="Session is not open"):
        _ = sess.db

    with pytest.raises(RuntimeError, match="Session is not open"):
        await sess.add_note("must not persist after close")

    with pytest.raises(RuntimeError, match="Session is not open"):
        await sess.get_targets()

