"""Kubernetes misconfiguration — API server, kubelet, etcd, dashboard exposure."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

K8S_API_ENDPOINTS = [
    ("/api/v1/namespaces",                      "List all namespaces",         "critical"),
    ("/api/v1/pods",                            "List all pods",               "critical"),
    ("/api/v1/secrets",                         "List all secrets",            "critical"),
    ("/api/v1/configmaps",                      "List all configmaps",         "high"),
    ("/api/v1/services",                        "List all services",           "high"),
    ("/api/v1/nodes",                           "List all nodes",              "high"),
    ("/apis/apps/v1/deployments",               "List all deployments",        "high"),
    ("/api/v1/namespaces/default/pods",         "Default namespace pods",      "critical"),
    ("/api/v1/namespaces/default/secrets",      "Default namespace secrets",   "critical"),
    ("/api/v1/namespaces/kube-system/secrets",  "kube-system secrets",         "critical"),
]

KUBELET_ENDPOINTS = [
    ("/pods",    "List running pods (port 10255)", "high"),
    ("/metrics", "Prometheus metrics",             "medium"),
    ("/spec",    "Node specification",             "medium"),
]

ETCD_ENDPOINTS = [
    ("/v2/keys/",  "etcd v2 all keys",  "critical"),
    ("/health",    "etcd health check", "info"),
]

K8S_DASHBOARD_PORTS = [8001, 8443, 30000, 30001, 31000]


async def _probe(url: str, client: TalismanHTTPClient) -> tuple[int, str]:
    try:
        r = await client.get(url, timeout=8)
        return r.status_code, r.text[:500]
    except Exception:
        return 0, ""


async def run(
    target: str,
    session: Any = None,
    scope: Any = None,
    rate_limiter: Any = None,
    proxy: str | None = None,
    api_server_port: int = 6443,
    kubelet_port: int = 10255,
    etcd_port: int = 2379,
    dashboard_check: bool = True,
    **kwargs: Any,
) -> dict[str, Any]:
    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    console.print(f"\n[module] Kubernetes Audit[/module] → [target]{host}[/target]")
    findings: list[dict[str, Any]] = []

    async with TalismanHTTPClient(proxy=proxy, timeout=10) as client:
        # K8s API server
        console.print(f"  Testing K8s API server ({api_server_port})...")
        for path, desc, severity in K8S_API_ENDPOINTS:
            for scheme in ["https", "http"]:
                api_url = f"{scheme}://{host}:{api_server_port}{path}"
                status, body = await _probe(api_url, client)
                if status == 200 and ("items" in body or "apiVersion" in body):
                    title = f"K8s API unauthenticated: {path}"
                    print_finding(title, severity, host)
                    findings.append({"path": path, "severity": severity, "url": api_url})
                    if session:
                        await session.add_finding(
                            target=host, module="kubernetes",
                            vuln_type="k8s_api_exposed",
                            severity=severity, confidence="confirmed",
                            title=title,
                            description=f"Kubernetes API {path} accessible without authentication.",
                            evidence=body[:300],
                            remediation=(
                                "1. Set --anonymous-auth=false on the API server.\n"
                                "2. Enable RBAC with proper role bindings.\n"
                                "3. Use network policies to restrict API access."
                            ),
                            cvss_score=10.0 if severity == "critical" else 8.6,
                            cwe="CWE-306",
                        )
                    break

        # Kubelet read-only port
        console.print(f"  Testing Kubelet port ({kubelet_port})...")
        for path, desc, severity in KUBELET_ENDPOINTS:
            kubelet_url = f"http://{host}:{kubelet_port}{path}"
            status, body = await _probe(kubelet_url, client)
            if status == 200 and len(body) > 20:
                title = f"Kubelet read-only exposed: {path}"
                print_finding(title, severity, host)
                findings.append({"path": path, "severity": severity, "port": kubelet_port})
                if session and severity != "info":
                    await session.add_finding(
                        target=host, module="kubernetes",
                        vuln_type="kubelet_exposed",
                        severity=severity, confidence="confirmed",
                        title=title,
                        description=f"Kubelet read-only port {kubelet_port} exposed: {desc}",
                        remediation="Disable read-only port: --read-only-port=0",
                        cwe="CWE-200",
                    )

        # etcd
        console.print(f"  Testing etcd ({etcd_port})...")
        for path, desc, severity in ETCD_ENDPOINTS:
            etcd_url = f"http://{host}:{etcd_port}{path}"
            status, body = await _probe(etcd_url, client)
            if status == 200 and len(body) > 5:
                title = f"etcd accessible without auth: {path}"
                print_finding(title, severity, host)
                findings.append({"path": path, "severity": severity, "port": etcd_port})
                if session and severity == "critical":
                    await session.add_finding(
                        target=host, module="kubernetes",
                        vuln_type="etcd_exposed",
                        severity=severity, confidence="confirmed",
                        title=title,
                        description="etcd accessible without authentication — contains all cluster secrets.",
                        remediation=(
                            "1. Enable etcd client certificate authentication.\n"
                            "2. Firewall etcd ports to API server only."
                        ),
                        cvss_score=10.0, cwe="CWE-306",
                    )

        # Dashboard
        if dashboard_check:
            for port in K8S_DASHBOARD_PORTS:
                for scheme in ["https", "http"]:
                    dash_url = f"{scheme}://{host}:{port}/"
                    status, body = await _probe(dash_url, client)
                    if status == 200 and ("kubernetes" in body.lower() or "dashboard" in body.lower()):
                        title = f"Kubernetes Dashboard on port {port}"
                        print_finding(title, "critical", host)
                        findings.append({"port": port, "url": dash_url})
                        if session:
                            await session.add_finding(
                                target=host, module="kubernetes",
                                vuln_type="k8s_dashboard_exposed",
                                severity="critical", confidence="confirmed",
                                title=title,
                                description="Kubernetes Dashboard publicly accessible.",
                                remediation="Use kubectl proxy. Require RBAC authentication. Remove --enable-skip-login.",
                                cvss_score=9.8, cwe="CWE-306",
                            )
                        break

    console.print(f"  K8s audit complete — {len(findings)} issues")
    return {"target": host, "findings": findings, "count": len(findings)}
