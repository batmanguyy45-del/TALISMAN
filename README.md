```
████████╗ █████╗ ██╗     ██╗███████╗███╗   ███╗ █████╗ ███╗   ██╗
╚══██╔══╝██╔══██╗██║     ██║██╔════╝████╗ ████║██╔══██╗████╗  ██║
   ██║   ███████║██║     ██║███████╗██╔████╔██║███████║██╔██╗ ██║
   ██║   ██╔══██║██║     ██║╚════██║██║╚██╔╝██║██╔══██║██║╚██╗██║
   ██║   ██║  ██║███████╗██║███████║██║ ╚═╝ ██║██║  ██║██║ ╚████║
   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**TALISMAN** -- Threat Analysis, Lateral Intelligence and Security Management for Advanced Networks

*Industrial-grade security research platform for professional bug bounty hunters, red teamers, and security engineers.*

---

## Installation

### From Source (Recommended)
```bash
git clone https://github.com/batmanguyy45-del/TALISMAN
cd TALISMAN
pip install -e ".[all]"
```

### Quick Install
```bash
pip install talisman-recon
```

### Verify Installation
```bash
talisman --help
talisman version
```

---

## Quick Start

```bash
# One-command automated assessment
talisman autopilot -t example.com -s my-session

# Full web vulnerability scan
talisman chain run web_vuln_scan -t https://target.com -s my-session

# Generate report
talisman report generate my-session --format html,markdown
```

---

## Full Command Reference

### Reconnaissance
```bash
talisman recon subdomain -t example.com -s my-session --bruteforce
talisman recon dns -t example.com --zone-transfer
talisman recon tech -t https://example.com
talisman recon crawl -t https://example.com --depth 4 --js-parse
talisman recon osint -t example.com
talisman recon whois -t example.com
talisman network ssl -t example.com
talisman network email -t example.com
talisman network takeover -t example.com
```

### Web Vulnerability Scanners
```bash
# Core web scanners
talisman scan xss   -t "https://target.com/search?q=FUZZ"
talisman scan sqli  -t "https://target.com/item?id=1"
talisman scan ssrf  -t https://target.com
talisman scan cmdi  -t https://target.com
talisman scan ssti  -t "https://target.com/greet?name=FUZZ"
talisman scan lfi   -t "https://target.com/page?file=FUZZ"
talisman scan xxe   -t https://target.com/upload

# Modern / advanced scanners
talisman scan nosqli -t https://target.com
talisman scan proto  -t https://target.com
talisman scan deserialize -t https://target.com
talisman scan websocket -t https://target.com
talisman scan crlf   -t https://target.com
talisman scan smuggle -t https://target.com
talisman scan csrf   -t https://target.com

# Configuration / logic scanners
talisman scan cors   -t https://target.com
talisman scan headers -t https://target.com
talisman scan cache  -t https://target.com
talisman scan idor   -t "https://target.com/api/users/123"
talisman scan auth   -t https://target.com
talisman scan redirect -t "https://target.com/go?url=FUZZ"
talisman scan mfa    -t https://target.com
talisman scan bizlogic -t https://target.com
talisman scan race   -t https://target.com
talisman scan log4shell -t https://target.com
talisman scan rate_limit -t https://target.com

# Advanced scanners (2025-2026 methodology)
talisman scan sspp   -t https://target.com
talisman scan csp    -t https://target.com
talisman scan verb   -t https://target.com
talisman scan upload -t https://target.com
talisman scan git    -t https://target.com
talisman scan depconf -t https://target.com
talisman scan mass   -t https://target.com
talisman scan host   -t https://target.com
talisman scan cache_deception -t https://target.com
talisman scan parser -t https://target.com
talisman scan second_order -t https://target.com
talisman scan nuclei -t https://target.com
```

### API Security
```bash
talisman api graphql -t https://api.target.com
talisman api jwt    -t https://api.target.com --token "eyJ0eXAi..."
talisman api oauth  -t https://api.target.com --args client_id=xxx
talisman api swagger -t https://api.target.com
talisman api grpc   -t https://api.target.com
```

### WAF Testing
```bash
talisman waf detect  -t https://target.com
talisman waf origin  -t example.com
talisman waf bypass  -t https://target.com --waf Cloudflare --type xss
```

### Cloud Security
```bash
talisman cloud aws    -t example.com
talisman cloud gcp    -t example.com
talisman cloud azure  -t example.com
talisman cloud secrets -t https://target.com
```

### Misconfiguration Checks
```bash
talisman misconfig spring     -t https://api.target.com
talisman misconfig kubernetes -t k8s-cluster.target.com
talisman misconfig database   -t target.com
talisman misconfig server     -t https://target.com
talisman misconfig nginx      -t https://target.com
```

### CMS
```bash
talisman cms wordpress          -t https://wp-site.com
talisman cms wordpress plugins  -t https://wp-site.com
talisman cms wordpress xmlrpc   -t https://wp-site.com
```

### Active Directory
```bash
talisman ad recon   -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 --user test --password P@ss
talisman ad kerberos -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 --user test --password P@ss
talisman ad smb     -t 192.168.1.10 --user test --password P@ss --domain corp.local
```

### Chain Orchestrator
```bash
# List available chains
talisman chain list

# Run assessment chains
talisman chain run full_recon       -t example.com -s my-session
talisman chain run web_vuln_scan    -t https://target.com -s my-session
talisman chain run api_audit        -t https://api.target.com -s my-session
talisman chain run wordpress_full   -t https://wp-site.com -s my-session
talisman chain run cloud_breach     -t example.com -s my-session
talisman chain run waf_bypass_probe -t https://target.com -s my-session
talisman chain run windows_ad       -t 192.168.1.10 -s ad-session --profile stealth

# Dry run
talisman chain run full_recon -t example.com --dry-run
```

### Session Management
```bash
talisman session list
talisman session summary my-session
talisman session findings my-session --severity critical,high
talisman session findings my-session --format json
```

### Reports
```bash
talisman report generate my-session --format html,markdown,json --output ./reports/
talisman report generate my-session --severity critical,high
```

### One-Command Full Assessment
```bash
talisman autopilot -t example.com -s my-session --profile normal --report
```

---

## Example: Full Bug Bounty Assessment

```bash
# Step 1: Reconnaissance
talisman chain run full_recon -t example.com -s bounty-q1

# Step 2: Web vulnerability scan (31 modules)
talisman chain run web_vuln_scan -t https://app.example.com -s bounty-q1

# Step 3: API audit
talisman chain run api_audit -t https://api.example.com -s bounty-q1

# Step 4: Deep analysis
talisman scan sspp  -t https://app.example.com
talisman scan csp   -t https://app.example.com
talisman scan git   -t https://app.example.com
talisman scan depconf -t https://app.example.com
talisman api grpc   -t https://api.example.com
talisman network email -t example.com

# Step 5: Generate professional report
talisman report generate bounty-q1 --format html,markdown --output ./reports/
```

---

## Chain YAML Format

Custom workflow chains are YAML-defined DAGs with parallel execution and conditional dependencies:

```yaml
name: my_chain
version: "1.0"
description: "Custom assessment"
tags: [web, api]
rate_profile: stealth

steps:
  - id: tech_detect
    module: recon.tech

  - id: xss_scan
    module: scanner.xss
    depends_on: [tech_detect]

  - id: sqli_scan
    module: scanner.sqli
    depends_on: [tech_detect]
    parallel: true
    args:
      techniques: [error, boolean, time]
```

**All 88 available modules:**

| Alias | Module | Description |
|---|---|---|
| `recon.subdomain` | Subdomain enumeration | Passive + active subdomain discovery |
| `recon.dns` | DNS analysis | Zone transfer, record enumeration |
| `recon.tech` | Tech detection | WAF, CMS, framework fingerprinting |
| `recon.crawl` | Web crawler | JS parsing, form discovery, endpoint extraction |
| `recon.osint` | OSINT | Email, S3 buckets, GitHub dorks |
| `recon.whois` | WHOIS/ASN | Domain registration and ASN lookup |
| `scanner.xss` | Cross-Site Scripting | Reflected, stored, DOM-based |
| `scanner.sqli` | SQL Injection | Error-based, boolean, time-blind |
| `scanner.ssrf` | SSRF | Server-side request forgery |
| `scanner.cmdi` | Command Injection | OS command injection |
| `scanner.ssti` | SSTI | Server-side template injection |
| `scanner.lfi` | LFI/RFI | Local/remote file inclusion |
| `scanner.xxe` | XXE | XML external entity injection |
| `scanner.nosqli` | NoSQL Injection | MongoDB operator injection |
| `scanner.prototype` | Prototype Pollution | Client + server-side |
| `scanner.sspp` | Server-Side PP | Non-destructive Node.js SSPP |
| `scanner.deserialize` | Deserialization | Java, PHP, Python, Node.js |
| `scanner.smuggle` | Request Smuggling | CL.TE, TE.CL, TE.TE, H2 downgrade |
| `scanner.crlf` | CRLF Injection | HTTP response splitting |
| `scanner.websocket` | WebSocket | Origin bypass, message injection |
| `scanner.cache` | Cache Poisoning | Web cache poisoning |
| `scanner.cache_deception` | Cache Deception | Path confusion, session leakage |
| `scanner.csrf` | CSRF | SameSite bypass, token validation |
| `scanner.cors` | CORS | Misconfiguration scanning |
| `scanner.headers` | Security Headers | CSP, HSTS, XFO, etc. |
| `scanner.host` | Host Header | Injection, password reset poisoning |
| `scanner.idor` | IDOR/BOLA | Insecure direct object reference |
| `scanner.auth` | Authentication | Login heuristics, bypass |
| `scanner.mfa` | MFA Bypass | 2FA/multi-factor bypass testing |
| `scanner.redirect` | Open Redirect | URL redirect bypass |
| `scanner.rate_limit` | Rate Limit Testing | Auth/burst/OTP rate limiting |
| `scanner.bizlogic` | Business Logic | Price/flood/negative value |
| `scanner.race` | Race Condition | Turbo, TOCTOU testing |
| `scanner.mass` | Mass Assignment | API parameter injection |
| `scanner.verb` | Verb Tampering | HTTP method abuse |
| `scanner.parser` | Parser Differential | JSON vs XML vs URL-encoded |
| `scanner.second_order` | Second-Order | Stored injection cross-endpoint |
| `scanner.upload` | File Upload | Extension/content/magic byte bypass |
| `scanner.git` | Git Exposure | .git, .env, backup, SSH exposure |
| `scanner.depconf` | Dep Confusion | npm/pip dependency confusion |
| `scanner.csp` | CSP Evaluator | Bypass technique analysis |
| `scanner.log4shell` | Log4Shell | Log4j JNDI injection |
| `scanner.nuclei` | Nuclei Runner | External template execution |
| `api.graphql` | GraphQL | Introspection, batching, injection |
| `api.jwt` | JWT | alg none, weak secret, kid injection |
| `api.oauth` | OAuth/OIDC | PKCE downgrade, redirect_uri, state |
| `api.swagger` | Swagger | OpenAPI/Swagger audit |
| `api.grpc` | gRPC | Reflection, TLS, health check |
| `waf.detector` | WAF Detection | 12+ WAF vendor fingerprinting |
| `waf.bypass` | WAF Bypass | Vendor-specific bypass payloads |
| `waf.origin` | Cloudflare Origin | Origin IP discovery |
| `cloud.aws` | AWS | S3, CloudFront, IAM checks |
| `cloud.gcp` | GCP | GCS, GKE misconfigurations |
| `cloud.azure` | Azure | Blob storage, Azure AD |
| `cloud.secrets` | Secrets | Secret/key exposure scanning |
| `misconfig.server` | Server Misconfig | Directory listing, info disclosure |
| `misconfig.spring` | Spring Boot | Actuator, heapdump, env |
| `misconfig.kubernetes` | K8s | API server, dashboard, etcd |
| `misconfig.database` | Database | MongoDB, Elasticsearch, CouchDB |
| `misconfig.nginx` | Nginx | ALIAS traversal, misconfiguration |
| `network.takeover` | Subdomain Takeover | DNS/CNAME detection |
| `network.ssl` | SSL/TLS | Certificate, cipher analysis |
| `network.email` | Email Security | SPF, DKIM, DMARC |
| `cms.wordpress` | WordPress | Core enumeration, vuln scan |
| `cms.wordpress.plugins` | WP Plugins | Plugin version detection |
| `cms.wordpress.xmlrpc` | WP XMLRPC | XMLRPC attack surface |
| `ad.recon` | AD Recon | LDAP enumeration, user spraying |
| `ad.kerberos` | Kerberos | Kerberoast, AS-REP roast |
| `ad.smb` | SMB | SMB shares, null session, GPP |
| `recon.ports` | Port Scanner | TCP connect port scanning |
| `fuzzer.paths` | Path Fuzzer | Directory/file brute force |

---

## Scanning Capabilities

| Category | Modules |
|---|---|
| Injection | XSS, SQLi, NoSQLi, CMDi, SSTI, LFI/RFI, XXE, CRLF |
| Authentication | Auth bypass, MFA bypass, JWT attacks, OAuth, rate limit |
| Access Control | IDOR/BOLA, CORS, Open Redirect, Mass Assignment, Host Header |
| Business Logic | Price manipulation, Workflow bypass, Race conditions |
| Modern Attacks | Prototype pollution (client+server), WebSocket, Deserialization |
| Infra Attacks | Cache poisoning, Cache deception, Request smuggling, Log4Shell |
| API Deep | GraphQL batching, gRPC scanner, Swagger, OAuth PKCE |
| Cloud | AWS, GCP, Azure, Secrets scanning |
| AD | Kerberos roasting, SMB audit, LDAP recon |
| Supply Chain | Dependency confusion, Git exposure |
| CSP Deep | 15 bypass technique checks, nonce quality |
| File Upload | Extension, content-type, magic byte polyglot |
| Parser Diff | JSON/XML/URL-encoded parsing discrepancies |
| Second-Order | Stored injection cross-endpoint detection |
| SS Deep | Verb tampering, Method override |
| Email | SPF, DKIM, DMARC posture scoring |

---

## Scope & Rate Limiting

### Scope File
```yaml
include:
  - "*.example.com"
  - "example.com"
exclude:
  - "mail.example.com"
restrictions:
  avoid_destructive: true
```

### Rate Profiles
| Profile | Req/s | Delay | Use Case |
|---|---|---|---|
| `aggressive` | 200 | 0-50ms | Internal networks |
| `normal` | 50 | 100-300ms | Bug bounty (default) |
| `stealth` | 10 | 500ms-2s | WAF-protected |
| `passive` | 5 | 1s-5s | Sensitive targets |

---

## Plugin System

Researchers can add custom modules without modifying core code:

```bash
# Create a plugin
mkdir -p ~/.talisman/plugins/my-scanner
```

Create `~/.talisman/plugins/my-scanner/plugin.yaml`:
```yaml
name: my-scanner
version: 1.0.0
author: researcher
type: scanner
entrypoint: module.MyScanner
module_alias: plugin.my_scanner
```

Write your plugin (extending `ScannerPlugin` from `talisman.plugins.base`):
```python
from talisman.plugins.base import ScannerPlugin, Finding

class MyScanner(ScannerPlugin):
    name = "my-scanner"
    description = "Custom vulnerability scanner"

    async def check(self, target, context, http_client, config):
        # Detection logic here
        yield Finding(title="Issue found", severity="high", ...)
```

List and use:
```bash
talisman plugin list
talisman scan plugin.my_scanner -t https://target.com
```

---

## Environment Variables

```bash
export GITHUB_TOKEN=ghp_xxx
export SHODAN_API_KEY=xxx
export DISCORD_WEBHOOK=https://...
```

---

## Architecture

```
talisman/
  cli.py              Typer CLI entry point
  engine/             Core: orchestrator, session, scope, rate limiter, plugin manager
  modules/
    recon/            7 modules
    scanner/          35+ modules
    api/              5 modules
    cloud/            4 modules
    waf/              3 modules
    cms/              3 modules
    misconfiguration/ 5 modules
    network/          3 modules
    activedirectory/  3 modules
  output/             HTML/Markdown/JSON report engine
  plugins/            Base classes + community loader
  chains/             7 YAML workflow definitions
  utils/              HTTP client, payload engine, structured logger
```

---

## Legal

Use TALISMAN exclusively on systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical.

*Built for professionals, by professionals. TALISMAN v1.0.0*
