"""Tests for HTTP response-boundary parsing in request-smuggling confirmation."""
from talisman.modules.scanner.smuggling import (
    SMUGGLING_PREFIX,
    _http_response_bodies,
)


def _response(body: bytes, status: int = 200) -> bytes:
    return (
        f"HTTP/1.1 {status} OK\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode() + body


def test_marker_in_second_response_is_separated_from_first_response():
    first = _response(b"normal response")
    second_body = SMUGGLING_PREFIX.encode()
    second = _response(second_body, status=200)

    bodies = _http_response_bodies(first + second)

    assert bodies == [b"normal response", second_body]
    assert SMUGGLING_PREFIX.encode().lower() in bodies[1].lower()


def test_marker_in_first_response_is_not_misidentified_as_second_response():
    first = _response(SMUGGLING_PREFIX.encode())
    second = _response(b"ordinary second response")

    bodies = _http_response_bodies(first + second)

    assert len(bodies) == 2
    assert SMUGGLING_PREFIX.encode().lower() in bodies[0].lower()
    assert SMUGGLING_PREFIX.encode().lower() not in bodies[1].lower()


def test_chunked_response_body_is_decoded_before_parsing_next_response():
    marker = SMUGGLING_PREFIX.encode()
    chunked = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: keep-alive\r\n\r\n"
        + f"{len(marker):X}\r\n".encode()
        + marker
        + b"\r\n0\r\n\r\n"
    )
    second = _response(b"second response")

    bodies = _http_response_bodies(chunked + second)

    assert bodies == [marker, b"second response"]


def test_unframed_response_is_not_split_speculatively():
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Connection: close\r\n\r\n"
        + SMUGGLING_PREFIX.encode()
        + b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )

    assert _http_response_bodies(raw) == []


@pytest.mark.asyncio
async def test_smuggling_refuses_to_bypass_configured_proxy(monkeypatch):
    from talisman.engine.scope import ScopeConfig, ScopeEnforcer
    from talisman.modules.scanner import smuggling

    scope = ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            allow_state_changing_requests=True,
            avoid_writes=False,
            avoid_destructive=False,
        )
    )

    async def must_not_probe(*args, **kwargs):
        raise AssertionError("raw probes must not bypass the configured proxy")

    monkeypatch.setattr(smuggling, "_confirm_smuggling", must_not_probe)
    result = await smuggling.run(
        target="https://example.com/",
        scope=scope,
        proxy="http://127.0.0.1:8080",
    )

    assert result["skipped"] is True
    assert result["findings"] == []
    assert "cannot honor the configured proxy" in result["reason"]


@pytest.mark.asyncio
async def test_smuggling_timing_only_signal_is_candidate_not_finding(monkeypatch):
    from talisman.engine.scope import ScopeConfig, ScopeEnforcer
    from talisman.modules.scanner import smuggling

    scope = ScopeEnforcer(
        ScopeConfig(
            include=["example.com"],
            service_allowlist=[],
            allow_state_changing_requests=True,
            avoid_writes=False,
            avoid_destructive=False,
        )
    )

    async def timing_only(host, port, use_tls, technique, probe, scope, url, host_header):
        return {
            "confirmed": False,
            "timing_differential": technique == "CL.TE",
            "evidence": "single timing sample",
        }

    monkeypatch.setattr(smuggling, "_confirm_smuggling", timing_only)

    class Session:
        def __init__(self):
            self.saved = []

        async def add_finding(self, *args, **kwargs):
            self.saved.append((args, kwargs))

    session = Session()
    result = await smuggling.run(
        target="https://example.com/",
        scope=scope,
        session=session,
    )

    assert result["findings"] == []
    assert result["count"] == 0
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["confidence"] == "candidate"
    assert session.saved == []
