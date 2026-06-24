"""Comprehensive test target server that simulates vulnerable endpoints for all TALISMAN scanner modules."""
from __future__ import annotations
import json
import html
import asyncio
from urllib.parse import parse_qs, urlparse
from typing import Any
from http import HTTPStatus


# ---------------------------------------------------------------------------
# Request/Response helpers (stdlib asyncio HTTP)
# ---------------------------------------------------------------------------

async def send_json(writer: asyncio.StreamWriter, data: dict, status: int = 200) -> None:
    body = json.dumps(data).encode()
    resp = (
        f"HTTP/1.1 {status} {HTTPStatus(status).phrase}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body
    writer.write(resp)
    await writer.drain()
    writer.close()


async def send_html(writer: asyncio.StreamWriter, body: str, status: int = 200, extra_headers: dict[str, str] | None = None) -> None:
    body_bytes = body.encode()
    headers = (
        f"HTTP/1.1 {status} {HTTPStatus(status).phrase}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
    )
    if extra_headers:
        for k, v in extra_headers.items():
            headers += f"{k}: {v}\r\n"
    headers += "Connection: close\r\n\r\n"
    writer.write(headers.encode() + body_bytes)
    await writer.drain()
    writer.close()


async def send_text(writer: asyncio.StreamWriter, body: str, status: int = 200) -> None:
    body_bytes = body.encode()
    resp = (
        f"HTTP/1.1 {status} {HTTPStatus(status).phrase}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body_bytes
    writer.write(resp)
    await writer.drain()
    writer.close()


def _parse_request(data: bytes) -> dict[str, Any]:
    text = data.decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    if not lines:
        return {}
    start = lines[0].split()
    method = start[0] if len(start) > 0 else "GET"
    raw_path = start[1] if len(start) > 1 else "/"
    parsed = urlparse(raw_path)
    path = parsed.path
    params = parse_qs(parsed.query)
    headers: dict[str, str] = {}
    body_start = text.find("\r\n\r\n")
    body = text[body_start + 4:] if body_start > 0 else ""
    for line in lines[1:]:
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"method": method, "path": path, "params": params, "headers": headers, "body": body, "raw_path": raw_path}


# ---------------------------------------------------------------------------
# Response helpers per module
# ---------------------------------------------------------------------------

GIT_CONFIG_SAMPLE = """[core]
\tbare = false
\trepositoryformatversion = 0
[remote "origin"]
\turl = https://github.com/org/repo.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
"""

GIT_HEAD_SAMPLE = "ref: refs/heads/main\n"

ENV_SAMPLE = """SECRET_KEY=sk-live-abc123def456
DB_PASSWORD=supersecret
API_TOKEN=tkn-abc123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
"""

SSH_KEY_SAMPLE = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA6NF1x1c3JjPkR5H3a3Y7TjK9s8z8Uq7yZ3L9zX2w4Q==
-----END OPENSSH PRIVATE KEY-----
"""

PACKAGE_JSON_SAMPLE = json.dumps({
    "name": "test-app",
    "version": "1.0.0",
    "dependencies": {
        "express": "^4.18.0",
        "lodash": "^4.17.21",
        "debug": "^2.6.9",
    }
})

# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

HANDLERS: dict[str, dict[str, Any]] = {}


def route(methods: list[str], path: str, description: str = ""):
    def decorator(func):
        for m in methods:
            key = f"{m.upper()}:{path}"
            HANDLERS[key] = {"handler": func, "desc": description}
        return func
    return decorator


@route(["GET"], "/", "Root")
async def handle_root(req, writer):
    await send_html(writer, "<html><body><h1>TALISMAN Test Target</h1></body></html>",
                    extra_headers={
                        "Content-Security-Policy": "default-src 'self'",
                        "Strict-Transport-Security": "max-age=31536000",
                        "X-Frame-Options": "DENY",
                        "X-Content-Type-Options": "nosniff",
                    })


@route(["GET"], "/.git/config", "Git exposure")
async def handle_git_config(req, writer):
    if req.get("headers", {}).get("user-agent", "").startswith("TALISMAN"):
        await send_text(writer, GIT_CONFIG_SAMPLE)
    else:
        await send_text(writer, GIT_CONFIG_SAMPLE)


@route(["GET"], "/.git/HEAD", "Git HEAD")
async def handle_git_head(req, writer):
    await send_text(writer, GIT_HEAD_SAMPLE)


@route(["GET"], "/.env", "Env exposure")
async def handle_env(req, writer):
    await send_text(writer, ENV_SAMPLE)


@route(["GET"], "/.ssh/id_rsa", "SSH key")
async def handle_ssh(req, writer):
    await send_text(writer, SSH_KEY_SAMPLE)


@route(["GET"], "/package.json", "Package file")
async def handle_pkg(req, writer):
    await send_text(writer, PACKAGE_JSON_SAMPLE)


@route(["GET"], "/dump.sql", "DB dump")
async def handle_dump(req, writer):
    await send_text(writer, "INSERT INTO users VALUES (1, 'admin', 'hash123');\nCREATE TABLE secrets;")
    await send_text(writer, "INSERT INTO users VALUES (1, 'admin', 'hash123');\nCREATE TABLE secrets;")


@route(["GET"], "/credentials.json", "Cloud creds")
async def handle_creds(req, writer):
    await send_json(writer, {"type": "service_account", "project_id": "test-project", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"})


@route(["GET"], "/.aws/credentials", "AWS creds")
async def handle_aws(req, writer):
    await send_text(writer, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")


@route(["GET"], "/api/user", "User API")
async def handle_api_user(req, writer):
    await send_json(writer, {"id": 1, "username": "admin", "role": "admin"})


@route(["GET"], "/api/users", "Users API")
async def handle_api_users(req, writer):
    await send_json(writer, [{"id": 1, "username": "admin", "role": "admin"}])


@route(["POST"], "/api/user", "User POST")
async def handle_api_user_post(req, writer):
    await send_json(writer, {"status": "ok", "id": 2})


@route(["POST"], "/api/login", "Login endpoint")
async def handle_login(req, writer):
    await send_json(writer, {"success": True, "token": "eyJhbGciOiJIUzI1NiJ9.test.test"}, status=200)


@route(["POST"], "/api/auth", "Auth endpoint")
async def handle_auth(req, writer):
    await send_json(writer, {"authenticated": True})


@route(["GET"], "/api/config", "Config endpoint")
async def handle_config(req, writer):
    await send_json(writer, {"debug": True, "version": "1.0.0"})


@route(["POST"], "/graphql", "GraphQL endpoint")
async def handle_graphql(req, writer):
    await send_json(writer, {"data": {"__schema": {"types": []}}})


@route(["GET"], "/api/health", "Health check")
async def handle_health(req, writer):
    await send_text(writer, "OK")


@route(["GET"], "/api/status", "Status")
async def handle_status(req, writer):
    await send_json(writer, {"status": "running", "uptime": 3600})


@route(["GET"], "/api/data", "Data endpoint")
async def handle_data(req, writer):
    qs = req.get("params", {})
    page = qs.get("page", ["1"])[0]
    await send_json(writer, {"page": int(page), "items": []})


@route(["POST"], "/api/data", "Data POST")
async def handle_data_post(req, writer):
    body = req.get("body", "")
    try:
        data = json.loads(body)
        # Reflect __proto__ if present (for SSPP / proto pollution testing)
        if isinstance(data, dict) and ("__proto__" in data or "constructor" in data):
            # Return indented JSON to simulate SSPP
            resp = json.dumps({"reflected": True, "input": data}, indent=4)
            body_bytes = resp.encode()
            headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(headers.encode() + body_bytes)
            await writer.drain()
            writer.close()
            return
    except json.JSONDecodeError:
        pass
    await send_json(writer, {"status": "received"})


@route(["GET"], "/api/settings", "Settings endpoint")
async def handle_settings(req, writer):
    await send_json(writer, {"theme": "dark", "notifications": True})


@route(["GET"], "/api/profile", "Profile endpoint")
async def handle_profile(req, writer):
    qs = req.get("params", {})
    user_id = qs.get("user_id", ["1"])[0]
    await send_json(writer, {"user_id": user_id, "name": "Test User", "email": "test@example.com"})


@route(["PUT"], "/api/profile", "Profile PUT")
async def handle_profile_put(req, writer):
    await send_json(writer, {"updated": True, "role": "admin"})


@route(["POST"], "/api/register", "Register endpoint")
async def handle_register(req, writer):
    await send_json(writer, {"success": True, "message": "User created"})


@route(["GET"], "/api/v1/user", "V1 user")
async def handle_v1_user(req, writer):
    await send_json(writer, {"id": 1, "username": "admin"})


@route(["GET"], "/api/v1/users", "V1 users")
async def handle_v1_users(req, writer):
    await send_json(writer, [{"id": 1, "username": "admin"}])


@route(["GET"], "/api/v1/profile", "V1 profile")
async def handle_v1_profile(req, writer):
    await send_json(writer, {"user_id": 1, "name": "Admin"})


@route(["GET"], "/admin/backup", "Admin backup")
async def handle_admin_backup(req, writer):
    await send_text(writer, "db_backup_2024.sql.gz")


@route(["GET"], "/backup", "Backup")
async def handle_backup(req, writer):
    await send_text(writer, "This is a backup directory")


@route(["GET"], "/backup.tar.gz", "Backup tar")
async def handle_backup_tar(req, writer):
    await send_text(writer, "\x1f\x8b\x08\x00backup data")


@route(["GET"], "/Dockerfile", "Dockerfile")
async def handle_dockerfile(req, writer):
    await send_text(writer, "FROM node:18\nWORKDIR /app\nCOPY . .\nRUN npm install\nCMD [\"node\", \"app.js\"]")


@route(["GET"], "/docker-compose.yml", "Docker compose")
async def handle_docker_compose(req, writer):
    await send_text(writer, "version: '3'\nservices:\n  app:\n    image: node:18\n    ports:\n      - '3000:3000'")


@route(["GET"], "/.gitlab-ci.yml", "GitLab CI")
async def handle_gitlab_ci(req, writer):
    await send_text(writer, "deploy:\n  script:\n    - echo $DEPLOY_TOKEN")


@route(["GET"], "/Jenkinsfile", "Jenkinsfile")
async def handle_jenkins(req, writer):
    await send_text(writer, "pipeline {\n  environment { SECRET = credentials('secret') }\n}")


@route(["GET"], "/.circleci/config.yml", "CircleCI")
async def handle_circleci(req, writer):
    await send_text(writer, "version: 2.1\njobs:\n  build:\n    steps:\n      - run: echo $API_KEY")


@route(["GET"], "/.travis.yml", "Travis CI")
async def handle_travis(req, writer):
    await send_text(writer, "language: node_js\nenv:\n  global:\n    - secure: encrypted-secret-value")


@route(["GET"], "/.github/workflows/main.yml", "GitHub Actions")
async def handle_gh_actions(req, writer):
    await send_text(writer, "name: CI\non: push\nenv:\n  DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}")


@route(["GET"], "/requirements.txt", "Requirements")
async def handle_requirements(req, writer):
    await send_text(writer, "flask==2.3.0\nrequests==2.31.0\nnumpy==1.24.0")


@route(["GET"], "/go.mod", "Go mod")
async def handle_gomod(req, writer):
    await send_text(writer, "module example.com/app\ngo 1.21\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)")


@route(["GET"], "/Cargo.toml", "Cargo")
async def handle_cargo(req, writer):
    await send_text(writer, "[package]\nname = \"test-app\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1.0\"")


@route(["GET"], "/composer.json", "Composer")
async def handle_composer(req, writer):
    await send_text(writer, '{"require":{"monolog/monolog":"2.0.0"}}')


@route(["GET"], "/Gemfile", "Gemfile")
async def handle_gemfile(req, writer):
    await send_text(writer, "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'")


@route(["GET"], "/Pipfile", "Pipfile")
async def handle_pipfile(req, writer):
    await send_text(writer, "[[source]]\nurl = 'https://pypi.org/simple'\n[packages]\ndjango = '*'")


@route(["GET"], "/service-account.json", "Service account")
async def handle_sa_json(req, writer):
    await send_json(writer, {
        "type": "service_account",
        "project_id": "test",
        "private_key_id": "abc123",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        "client_email": "test@test.iam.gserviceaccount.com",
    })


@route(["GET"], "/.gcloud/config.json", "GCloud config")
async def handle_gcloud(req, writer):
    await send_json(writer, {"project": "test-project", "zone": "us-central1-a"})


@route(["GET"], "/.npmrc", "NPM RC")
async def handle_npmrc(req, writer):
    await send_text(writer, "//registry.npmjs.org/:_authToken=npm_abc123def456\nregistry=https://registry.npmjs.org/")


@route(["GET"], "/.pypirc", "PyPI RC")
async def handle_pypirc(req, writer):
    await send_text(writer, "[distutils]\nindex-servers = pypi\n[pypi]\nusername = __token__\npassword = pypi-abc123def456")


@route(["GET"], "/.netrc", "Netrc")
async def handle_netrc(req, writer):
    await send_text(writer, "machine github.com\nlogin token\npassword ghp_abc123def456")


@route(["GET"], "/.vscode/settings.json", "VSCode settings")
async def handle_vscode(req, writer):
    await send_json(writer, {"git.enableCommitSigning": True})


@route(["GET"], "/.idea/workspace.xml", "Idea workspace")
async def handle_idea(req, writer):
    await send_text(writer, '<?xml version="1.0"?><project><component>config</component></project>')


@route(["GET"], "/phpunit.xml", "PHPUnit")
async def handle_phpunit(req, writer):
    await send_text(writer, '<?xml version="1.0"?><phpunit><php><env name="DB_PASSWORD" value="secret"/></php></phpunit>')


@route(["GET"], "/config.php", "Config PHP")
async def handle_config_php(req, writer):
    await send_text(writer, '<?php\n$db_password = "secret123";\n?>')


@route(["GET"], "/settings.py", "Settings py")
async def handle_settings_py(req, writer):
    await send_text(writer, "SECRET_KEY = 'django-secret-key-here'\nDATABASES = {'default': {'PASSWORD': 'dbpass'}}")


@route(["GET"], "/appsettings.json", "AppSettings")
async def handle_appsettings(req, writer):
    await send_json(writer, {"ConnectionStrings": {"Default": "Server=db;Password=secret"}})


@route(["GET"], "/config.json", "Config JSON")
async def handle_config_json(req, writer):
    await send_json(writer, {"api_secret": "sk-live-test-key", "jwt_secret": "jwt-test-secret"})


@route(["GET"], "/private", "Private directory")
async def handle_private(req, writer):
    await send_text(writer, "Index of /private\n\n../\nkeys.txt\nsecrets.txt\nbackup.sql")


@route(["GET"], "/internal", "Internal directory")
async def handle_internal(req, writer):
    await send_text(writer, "Internal documentation - not for public access")


@route(["GET"], "/logs", "Logs directory")
async def handle_logs(req, writer):
    await send_text(writer, "access.log\nerror.log\naudit.log")


@route(["GET"], "/access_log", "Access log")
async def handle_access_log(req, writer):
    await send_text(writer, "192.168.1.1 - admin [01/Jan/2024:00:00:01 +0000] \"POST /admin HTTP/1.1\" 200 1234")


@route(["GET"], "/error_log", "Error log")
async def handle_error_log(req, writer):
    await send_text(writer, "[01-Jan-2024 00:00:01] PHP Fatal error:  Uncaught Exception: DB connection failed")


# CORS headers for CORS module testing
@route(["GET"], "/api/cors", "CORS test endpoint")
async def handle_cors(req, writer):
    origin = req.get("headers", {}).get("origin", "*")
    body = json.dumps({"cors": "test"}).encode()
    resp = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        f"Access-Control-Allow-Origin: {origin}\r\n"
        f"Access-Control-Allow-Credentials: true\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body
    writer.write(resp)
    await writer.drain()
    writer.close()


@route(["OPTIONS"], "/api/cors", "CORS preflight")
async def handle_cors_preflight(req, writer):
    writer.write(
        "HTTP/1.1 200 OK\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE\r\n"
        "Access-Control-Allow-Headers: *\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n".encode()
    )
    await writer.drain()
    writer.close()


# XSS reflection
@route(["GET"], "/search", "Search endpoint - reflects query")
async def handle_search(req, writer):
    q = req.get("params", {}).get("q", [""])[0]
    body = f"<html><body>Search results for: {q}<br/>No results found.</body></html>"
    await send_html(writer, body)


@route(["GET"], "/api/reflect", "Reflection endpoint")
async def handle_reflect(req, writer):
    qs = req.get("params", {})
    await send_json(writer, {"input": qs.get("input", [""])[0], "echo": qs.get("echo", [""])[0]})


# SQLi simulation - reflect error messages
@route(["GET"], "/api/users/search", "User search - SQL simulation")
async def handle_user_search(req, writer):
    name = req.get("params", {}).get("name", [""])[0]
    if "'" in name or '"' in name:
        await send_text(writer, "SQL error: syntax error near unexpected ''' at line 1", status=500)
    else:
        await send_json(writer, {"users": []})


@route(["GET"], "/api/users/login", "User login - SQL simulation")
async def handle_user_login(req, writer):
    user = req.get("params", {}).get("user", [""])[0]
    if "' OR '1'='1" in user:
        await send_json(writer, {"success": True, "admin": True})
    else:
        await send_json(writer, {"success": False})


# SSRF simulation - echo back URL
@route(["GET"], "/fetch", "Fetch endpoint - SSRF simulation")
async def handle_fetch(req, writer):
    url = req.get("params", {}).get("url", [""])[0]
    await send_json(writer, {"fetched": url, "content": f"Content from {url}"})


@route(["GET"], "/proxy", "Proxy endpoint")
async def handle_proxy(req, writer):
    url = req.get("params", {}).get("url", [""])[0]
    await send_json(writer, {"proxy_response": f"Fetched: {url}"})


# CMDi simulation - time-based detection
@route(["GET"], "/ping", "Ping endpoint")
async def handle_ping(req, writer):
    host = req.get("params", {}).get("host", ["localhost"])[0]
    await send_text(writer, f"PING {host} (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.042ms")


# SSTI reflection
@route(["GET"], "/greet", "Greet endpoint - SSTI simulation")
async def handle_greet(req, writer):
    name = req.get("params", {}).get("name", ["world"])[0]
    await send_text(writer, f"Hello {name}!")


# LFI simulation
@route(["GET"], "/file", "File read endpoint")
async def handle_file(req, writer):
    f = req.get("params", {}).get("file", [""])[0]
    if "etc/passwd" in f:
        await send_text(writer, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
    else:
        await send_text(writer, f"File content placeholder for: {f}")


# XXE simulation
@route(["POST"], "/api/xml", "XML endpoint")
async def handle_xml(req, writer):
    body = req.get("body", "")
    if "DOCTYPE" in body or "ENTITY" in body:
        # Simulate XXE - echo the entity
        await send_text(writer, "John Doe\nAdmin\nsecret_password")
    elif "<user" in body:
        await send_json(writer, {"status": "user created"})
    else:
        await send_text(writer, "Invalid XML")


# Log4Shell simulation
@route(["GET"], "/api/headers", "Headers echo endpoint")
async def handle_headers(req, writer):
    await send_json(writer, {"headers": dict(req.get("headers", {}))})


@route(["GET"], "/api/echo", "Echo endpoint")
async def handle_echo(req, writer):
    await send_json(writer, {
        "method": req.get("method"),
        "path": req.get("raw_path"),
        "params": req.get("params"),
        "headers": dict(req.get("headers", {})),
    })


# Host header injection test
@route(["GET"], "/api/host", "Host echo endpoint")
async def handle_host(req, writer):
    host = req.get("headers", {}).get("host", "unknown")
    await send_json(writer, {"host": host})


# Open redirect simulation
@route(["GET"], "/redirect", "Redirect endpoint")
async def handle_redirect(req, writer):
    next_url = req.get("params", {}).get("next", [""])[0]
    if next_url:
        writer.write(
            f"HTTP/1.1 302 Found\r\n"
            f"Location: {next_url}\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        await writer.drain()
        writer.close()
    else:
        await send_text(writer, "Redirect endpoint")


@route(["GET"], "/api/openredirect", "Open redirect")
async def handle_openredirect(req, writer):
    to = req.get("params", {}).get("to", [""])[0]
    if to:
        writer.write(
            f"HTTP/1.1 302 Found\r\n"
            f"Location: {to}\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        await writer.drain()
        writer.close()
    else:
        await send_text(writer, "redirect test")


@route(["GET"], "/logout", "Logout redirect")
async def handle_logout(req, writer):
    redirect_url = req.get("params", {}).get("redirect", ["/"])[0]
    writer.write(
        f"HTTP/1.1 302 Found\r\n"
        f"Location: {redirect_url}\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: close\r\n\r\n".encode()
    )
    await writer.drain()
    writer.close()


# API key in response
@route(["GET"], "/api/key", "API key endpoint")
async def handle_api_key(req, writer):
    await send_json(writer, {"api_key": "AIzaSyDfakeKeyForTestingPurposesOnly123456", "usage": 42})


# Non-existent paths
@route(["GET"], "/private/keys.txt", "Private keys")
async def handle_private_keys(req, writer):
    await send_text(writer, "SSH_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...")


@route(["GET"], "/temp", "Temp directory")
async def handle_temp(req, writer):
    await send_text(writer, "Index of /temp\n\nbackup.sql\ndebug.log")


# CSRF token check
@route(["POST"], "/api/transfer", "Transfer endpoint - CSRF check")
async def handle_transfer(req, writer):
    await send_json(writer, {"status": "completed", "amount": 100})


# Cache deception test
@route(["GET"], "/api/profile/nonexistent.css", "Cache deception .css")
async def handle_cache_deception_css(req, writer):
    await send_json(writer, {"user_id": 1, "ssn": "123-45-6789", "role": "admin"})


@route(["GET"], "/api/private_data/nonexistent.jpg", "Cache deception .jpg")
async def handle_cache_deception_jpg(req, writer):
    await send_json(writer, {"private_key": "sk-test-abc123"})


@route(["GET"], "/api/profile/1/test.css", "Cache deception test.css")
async def handle_cache_deception_test_css(req, writer):
    await send_json(writer, {"email": "admin@example.com", "token": "sess-abc123"})


# Rate limit simulation
@route(["POST"], "/api/reset-password", "Password reset")
async def handle_reset_password(req, writer):
    await send_json(writer, {"status": "ok", "message": "Reset email sent"})


@route(["POST"], "/api/otp", "OTP endpoint")
async def handle_otp(req, writer):
    await send_json(writer, {"status": "ok", "verified": True})


@route(["POST"], "/api/2fa", "2FA endpoint")
async def handle_2fa(req, writer):
    await send_json(writer, {"status": "ok", "token": "2fa-token-abc"})


# Mass assignment
@route(["GET"], "/api/account", "Account endpoint")
async def handle_account(req, writer):
    await send_json(writer, {"id": 1, "username": "user1", "role": "user"})


@route(["PUT"], "/api/account", "Account PUT")
async def handle_account_put(req, writer):
    await send_json(writer, {"id": 1, "username": "user1", "role": "admin", "is_admin": True})


@route(["PATCH"], "/api/account", "Account PATCH")
async def handle_account_patch(req, writer):
    await send_json(writer, {"id": 1, "username": "user1", "role": "admin"})


# Host header
@route(["GET"], "/api/password-reset", "Password reset endpoint")
async def handle_password_reset(req, writer):
    host = req.get("headers", {}).get("host", "unknown")
    await send_json(writer, {"reset_link": f"http://{host}/reset?token=abc123", "host": host})


# Parser differential
@route(["POST"], "/api/parse", "Parse endpoint")
async def handle_parse(req, writer):
    ct = req.get("headers", {}).get("content-type", "")
    body = req.get("body", "")
    if "json" in ct:
        try:
            data = json.loads(body)
            if isinstance(data, list):
                await send_json(writer, {"parsed_as": "json_array", "length": len(data)})
            elif isinstance(data, dict) and "__proto__" in data:
                await send_json(writer, {"parsed_as": "json_object", "proto": True})
            else:
                await send_json(writer, {"parsed_as": "json"})
        except json.JSONDecodeError:
            await send_text(writer, "bad json", status=400)
    elif "x-www-form-urlencoded" in ct:
        await send_json(writer, {"parsed_as": "form"})
    else:
        await send_text(writer, body, status=200)


# Verb tampering
@route(["GET"], "/api/restricted", "Restricted endpoint GET")
async def handle_restricted_get(req, writer):
    await send_text(writer, "GET request received", status=200)


@route(["POST"], "/api/restricted", "Restricted endpoint POST")
async def handle_restricted_post(req, writer):
    await send_text(writer, "POST request received", status=200)


# File upload
@route(["POST"], "/upload", "Upload endpoint")
async def handle_upload(req, writer):
    await send_json(writer, {"status": "uploaded", "filename": "test.php"})


@route(["POST"], "/api/upload", "API upload")
async def handle_api_upload(req, writer):
    await send_json(writer, {"status": "success", "path": "/uploads/file.jsp"})


# HPP
@route(["GET"], "/api/hpp", "HPP test endpoint")
async def handle_hpp(req, writer):
    qs = req.get("params", {})
    action = qs.get("action", ["none"])[0]
    user = qs.get("user", ["none"])[-1]
    admin = qs.get("admin", ["false"])[-1]
    await send_json(writer, {"action": action, "user": user, "admin": admin})


# LDAP injection
@route(["GET"], "/api/ldap_login", "LDAP login endpoint")
async def handle_ldap_login(req, writer):
    user = req.get("params", {}).get("user", [""])[0]
    if "*" in user or ")" in user:
        await send_json(writer, {"authenticated": True, "dn": f"cn={user},dc=example,dc=com"})
    else:
        await send_json(writer, {"authenticated": False})


@route(["POST"], "/api/ldap_auth", "LDAP auth POST")
async def handle_ldap_auth(req, writer):
    body = req.get("body", "")
    if "*" in body or "(" in body:
        await send_json(writer, {"authenticated": True, "role": "admin"})
    else:
        await send_json(writer, {"authenticated": False})


# SSJI
@route(["POST"], "/api/eval", "Eval endpoint")
async def handle_eval(req, writer):
    body = req.get("body", "")
    try:
        data = json.loads(body)
        expr = data.get("expr", "") if isinstance(data, dict) else ""
    except json.JSONDecodeError:
        expr = ""
    if "require" in expr or "process" in expr or "global" in expr:
        await send_json(writer, {"result": "[Function]", "executed": True})
    else:
        await send_json(writer, {"result": None})


# DOM clobbering
@route(["GET"], "/api/dom", "DOM clobbering endpoint")
async def handle_dom(req, writer):
    await send_json(writer, {"trusted_config": {
        "user": "admin",
        "is_admin": True,
        "callback_url": "javascript:alert(1)",
    }})


# Dangling markup
@route(["GET"], "/api/dangling", "Dangling markup endpoint")
async def handle_dangling(req, writer):
    body = "<html><body><a href=\"/api/user\">Click here</a><img src=\"https://evil.com/steal?\"</body></html>"
    await send_html(writer, body)


# Unicode/Bidi
@route(["GET"], "/api/unicode", "Unicode test endpoint")
async def handle_unicode(req, writer):
    bidi_text = "abc\\u202Edef\\u202Dghi"
    await send_json(writer, {"comment": f"// The following is {bidi_text}"})


# NoSQLi
@route(["GET"], "/api/nosqli_login", "NoSQL login")
async def handle_nosqli_login(req, writer):
    qs = req.get("params", {})
    passwd = qs.get("password", [""])[0]
    if passwd in ('{"$ne": ""}', '{"$gt": ""}', '{"$regex": ".*"}', '{"$ne": null}'):
        await send_json(writer, {"success": True, "token": "nosqli-token"})
    else:
        await send_json(writer, {"success": False})


@route(["POST"], "/api/nosqli_login", "NoSQL login POST")
async def handle_nosqli_login_post(req, writer):
    body = req.get("body", "")
    if '$ne' in body or '$gt' in body or '$regex' in body or '$where' in body:
        await send_json(writer, {"success": True, "token": "nosqli-token"})
    else:
        await send_json(writer, {"success": False})


@route(["POST"], "/api/nosqli/search", "NoSQL search")
async def handle_nosqli_search(req, writer):
    body = req.get("body", "")
    if '$regex' in body:
        await send_json(writer, {"results": [{"username": "admin", "password": "hashed"}]})
    else:
        await send_json(writer, {"results": []})


# SSRF additional
@route(["GET"], "/api/ssrf", "SSRF test")
async def handle_ssrf(req, writer):
    url = req.get("params", {}).get("url", [""])[0]
    await send_json(writer, {"content": f"Page content from {url}"})


# WebSocket test endpoint (just returns upgrade response)
@route(["GET"], "/ws", "WebSocket test endpoint")
async def handle_ws(req, writer):
    key = req.get("headers", {}).get("sec-websocket-key", "")
    accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="  # dummy
    resp = (
        f"HTTP/1.1 101 Switching Protocols\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        f"\r\n"
    ).encode()
    writer.write(resp)
    await writer.drain()


# CSRF endpoints
@route(["POST"], "/api/email/change", "Email change endpoint")
async def handle_email_change(req, writer):
    await send_json(writer, {"status": "ok", "email": "changed@example.com"})


@route(["POST"], "/api/password/change", "Password change endpoint")
async def handle_password_change(req, writer):
    await send_json(writer, {"status": "ok", "message": "Password updated"})


@route(["POST"], "/api/admin/delete", "Admin delete endpoint")
async def handle_admin_delete(req, writer):
    await send_json(writer, {"status": "deleted"})


# Second order injection
@route(["POST"], "/api/comments", "Comments POST")
async def handle_comments_post(req, writer):
    await send_json(writer, {"status": "created", "id": 1})


@route(["GET"], "/api/comments", "Comments GET")
async def handle_comments_get(req, writer):
    await send_json(writer, {"comments": [
        {"id": 1, "body": "<script>alert('xss')</script>", "user": "attacker"}
    ]})


# Dep confusion
@route(["GET"], "/api/dependencies", "Dependencies API")
async def handle_dependencies(req, writer):
    await send_json(writer, {"dependencies": ["express", "lodash", "debug"]})


# Prototype pollution
@route(["POST"], "/api/proto", "Prototype pollution endpoint")
async def handle_proto(req, writer):
    body = req.get("body", "")
    try:
        data = json.loads(body)
        if isinstance(data, dict) and ("__proto__" in data or "constructor" in data):
            await send_json(writer, {"polluted": True, "json spaces": 4})
        else:
            await send_json(writer, {"status": "ok", "echo": data})
    except json.JSONDecodeError:
        await send_text(writer, "bad json", status=400)


# Race condition
@route(["POST"], "/api/coupon/redeem", "Coupon redeem endpoint")
async def handle_coupon_redeem(req, writer):
    await send_json(writer, {"success": True, "discount": 50, "remaining": 0})


# Bizlogic
@route(["POST"], "/api/cart/checkout", "Checkout endpoint")
async def handle_checkout(req, writer):
    await send_json(writer, {"order_id": 1, "total": 0, "status": "completed"})


@route(["POST"], "/api/order", "Order endpoint")
async def handle_order(req, writer):
    await send_json(writer, {"order_id": 1, "status": "created"})


# MFA
@route(["POST"], "/api/verify-mfa", "Verify MFA endpoint")
async def handle_verify_mfa(req, writer):
    await send_json(writer, {"verified": True, "session": "sess-mfa-token"})


@route(["POST"], "/api/mfa/skip", "MFA skip endpoint")
async def handle_mfa_skip(req, writer):
    await send_json(writer, {"status": "ok", "message": "MFA skipped"})


# Auth module
@route(["GET"], "/admin", "Admin panel")
async def handle_admin(req, writer):
    await send_html(writer, "<html><body><h1>Admin Panel</h1><form action='/admin/login' method='POST'>"
                   "<input name='user'><input name='pass' type='password'><input type='submit'></form></body></html>")


@route(["GET"], "/login", "Login page")
async def handle_login_page(req, writer):
    await send_html(writer, "<html><body><h1>Login</h1><form action='/login' method='POST'>"
                   "<input name='username'><input name='password' type='password'>"
                   "<input type='hidden' name='csrf' value='abc123'>"
                   "<input type='submit'></form></body></html>")


@route(["POST"], "/login", "Login POST")
async def handle_login_post(req, writer):
    await send_json(writer, {"success": True, "session": "sess-abc"})


# IDOR
@route(["GET"], "/api/user/1", "User 1")
async def handle_user_1(req, writer):
    await send_json(writer, {"id": 1, "username": "admin", "email": "admin@test.com"})


@route(["GET"], "/api/user/2", "User 2")
async def handle_user_2(req, writer):
    await send_json(writer, {"id": 2, "username": "user", "email": "user@test.com"})


@route(["GET"], "/api/order/1", "Order 1")
async def handle_order_1(req, writer):
    await send_json(writer, {"id": 1, "total": 99.99, "user_id": 1})


@route(["GET"], "/api/order/2", "Order 2")
async def handle_order_2(req, writer):
    await send_json(writer, {"id": 2, "total": 49.99, "user_id": 2})


# Default 404 for everything else
@route(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], "__fallback__", "Fallback 404")
async def handle_404(req, writer):
    resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found".encode()
    writer.write(resp)
    await writer.drain()
    writer.close()


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        data = await asyncio.wait_for(reader.read(65536), timeout=10)
        if not data:
            writer.close()
            return
        req = _parse_request(data)
        method = req.get("method", "GET")
        path = req.get("path", "/")

        # Log HackerOne research header if present
        h1 = req.get("headers", {}).get("x-hackerone-research", "")
        if h1:
            print(f"[H1] X-HackerOne-Research: {h1} on {method} {path}")

        handler_key = f"{method}:{path}"
        handler_info = HANDLERS.get(handler_key)

        if handler_info:
            await handler_info["handler"](req, writer)
        else:
            fallback = HANDLERS.get("GET:__fallback__")
            if fallback:
                await fallback["handler"](req, writer)
            else:
                await send_text(writer, "Not Found", status=404)
    except asyncio.TimeoutError:
        writer.close()
    except Exception:
        try:
            await send_text(writer, "Internal Server Error", status=500)
        except Exception:
            pass
        writer.close()


async def main(host: str = "127.0.0.1", port: int = 9999) -> None:
    print(f"TALISMAN test target listening on {host}:{port}")
    print(f"  {len(HANDLERS) - 1} route handlers registered (+ 404 fallback)")
    server = await asyncio.start_server(
        handle_connection, host, port,
        reuse_address=True, reuse_port=True,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    asyncio.run(main(port=port))
