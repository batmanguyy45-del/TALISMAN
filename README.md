```
████████╗ █████╗ ██╗     ██╗███████╗███╗   ███╗ █████╗ ███╗   ██╗
╚══██╔══╝██╔══██╗██║     ██║██╔════╝████╗ ████║██╔══██╗████╗  ██║
   ██║   ███████║██║     ██║███████╗██╔████╔██║███████║██╔██╗ ██║
   ██║   ██╔══██║██║     ██║╚════██║██║╚██╔╝██║██╔══██║██║╚██╗██║
   ██║   ██║  ██║███████╗██║███████║██║ ╚═╝ ██║██║  ██║██║ ╚████║
   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**TALISMAN** -- Threat Analysis, Lateral Intelligence and Security Management for Advanced Networks

*Advanced Bug Bounty and Professional Security Research Platform*

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-orange)](https://github.com/yourhandle/talisman)

> AUTHORIZED USE ONLY -- Use TALISMAN exclusively on systems you own or have explicit written permission to test.

---

## Overview

TALISMAN is an industrial-grade security research platform built for professional bug bounty hunters, red teamers, and security engineers. It chains tools, automates entire assessment workflows, and removes approximately 65% of manual researcher burden -- allowing focus on creative chaining and business logic exploitation.

### Feature Matrix

| Capability | TALISMAN | Burp Suite | Nuclei | Manual |
|---|---|---|---|---|
| Automated chain orchestration | YAML DAG | No | No | No |
| Session persistence and resume | SQLite | Limited | No | No |
| WAF fingerprint and vendor bypass | 12 vendors | Manual | No | Manual |
| WordPress deep audit | Full | No | Templates | No |
| AD/Kerberos attacks | Built-in | No | No | Manual |
| Scope enforcement (all modules) | Engine-level | Limited | No | No |
| HTML/Markdown/JSON reports | Platform-ready | Limited | No | No |
| Cloudflare origin discovery | Multi-method | No | No | Manual |
| OOB/OAST integration | All modules | Collaborator | No | No |

---

## Installation

### From Source (Recommended)
```bash
git clone https://github.com/yourhandle/talisman
cd talisman
pip install -e ".[all]"
talisman init
```

### Docker
```bash
docker-compose up -d
docker exec -it talisman talisman --help
```

### Quick Pip
```bash
pip install talisman-recon
talisman init
```

---

## Quick Start

```bash
# Initialize
talisman init

# Full automated assessment
talisman autopilot -t example.com --session bounty-q1 --profile normal

# Generate professional report
talisman report generate bounty-q1 --format html,markdown
```

---

## Command Reference

### Reconnaissance
```bash
# Subdomain enumeration -- passive and active
talisman recon subdomain -t example.com -s bounty-q1 --bruteforce

# Deep DNS analysis and zone transfer attempt
talisman recon dns -t example.com --zone-transfer

# Technology fingerprinting and WAF detection
talisman recon tech -t https://example.com

# Web crawler -- JS endpoint extraction
talisman recon crawl -t https://example.com --depth 4 --js-parse

# OSINT -- emails, S3 buckets, GitHub dorks
talisman recon osint -t example.com --github-token $GITHUB_TOKEN
```

### Vulnerability Scanning
```bash
# Run all scanners
talisman scan all -t https://example.com -s bounty-q1

# Individual scanners
talisman scan xss   -t "https://example.com/search?q=FUZZ" --waf-bypass
talisman scan sqli  -t "https://example.com/item?id=1"
talisman scan ssrf  -t https://example.com --oast oastify.com
talisman scan cmdi  -t https://example.com --oast oastify.com
talisman scan ssti  -t "https://example.com/greet?name=FUZZ"
talisman scan lfi   -t "https://example.com/page?file=FUZZ"
talisman scan xxe   -t https://example.com/upload
talisman scan smuggle -t https://example.com
talisman scan cors  -t https://example.com
talisman scan headers -t https://example.com
talisman scan cache -t https://example.com
talisman scan idor  -t "https://example.com/api/users/123"
talisman scan auth  -t https://example.com
talisman scan redirect -t "https://example.com/go?url=FUZZ"
talisman scan proto -t https://example.com
```

### WAF Bypass
```bash
# Detect WAF vendor
talisman waf detect -t https://example.com

# Find real origin behind Cloudflare
talisman waf origin -t example.com --shodan-key $SHODAN_KEY

# Generate vendor-specific bypass payloads
talisman waf bypass -t https://example.com --waf Cloudflare --type xss
```

### WordPress
```bash
talisman cms wordpress -t https://wordpress-site.com --full --oast oastify.com
```

### API Security
```bash
# GraphQL audit -- introspection, injection, batching
talisman api graphql -t https://api.example.com --auth "Bearer TOKEN"

# JWT attacks -- alg confusion, none, kid, brute force
talisman api jwt -t https://api.example.com --token "eyJhbGci..." --endpoint https://api.example.com/admin
```

### Cloud Security
```bash
# AWS S3 and CloudFront audit
talisman cloud aws -t example.com --s3 --cf-bypass

# Secret scanning
talisman cloud secrets -t https://example.com
```

### Misconfiguration
```bash
talisman misconfig spring     -t https://api.example.com
talisman misconfig kubernetes -t k8s-cluster.example.com --api-port 6443
talisman misconfig database   -t example.com
talisman misconfig server     -t https://example.com
```

### Active Directory
```bash
# Full AD enumeration
talisman ad recon -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 --user testuser --password Pass123

# Kerberoasting and AS-REP roasting
talisman ad kerberos -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 --user testuser --password Pass123

# SMB audit -- shares, signing, null session, GPP credentials
talisman ad smb -t 192.168.1.10 --user testuser --password Pass123 --domain corp.local
```

### Fuzzing
```bash
talisman fuzz paths -t https://example.com --wordlist wordlists/raft-large.txt --extensions php,asp,aspx,bak,txt --threads 50
```

### Chain Orchestrator
```bash
# List all chains
talisman chain list

# Run built-in chains
talisman chain run full_recon       -t example.com -s bounty-q1
talisman chain run web_vuln_scan    -t https://example.com -s bounty-q1
talisman chain run wordpress_full   -t https://wp-site.com -s bounty-q1 --oast oastify.com
talisman chain run api_audit        -t https://api.example.com -s bounty-q1
talisman chain run cloud_breach     -t example.com -s bounty-q1
talisman chain run waf_bypass_probe -t https://example.com -s bounty-q1
talisman chain run windows_ad       -t 192.168.1.10 -s ad-bounty --profile stealth

# Dry run (show what would execute)
talisman chain run full_recon -t example.com --dry-run
```

### Session Management
```bash
talisman session list
talisman session summary bounty-q1
talisman session findings bounty-q1 --severity critical,high
talisman session findings bounty-q1 --format json
```

### Reports
```bash
talisman report generate bounty-q1 --format html,markdown,json --output ./reports/
talisman report generate bounty-q1 --severity critical,high
```

### Autopilot
```bash
talisman autopilot -t example.com --session bounty-q1 --profile normal --oast oastify.com --scope scope.yaml --report
```

---

## Chain YAML Format

```yaml
name: my_custom_chain
version: "1.0"
description: "Custom assessment workflow"
tags: [web, api]
rate_profile: stealth

steps:
  - id: tech_detect
    module: recon.tech
    args:
      waf_detect: true

  - id: xss_scan
    module: scanner.xss
    depends_on: [tech_detect]
    args:
      waf_bypass: true
    on_error: continue

  - id: sqli_scan
    module: scanner.sqli
    depends_on: [tech_detect]
    parallel: true
    args:
      techniques: [error, boolean, time]
```

**Available modules:** `recon.subdomain`, `recon.dns`, `recon.tech`, `recon.crawl`, `recon.osint`, `scanner.xss`, `scanner.sqli`, `scanner.ssrf`, `scanner.cmdi`, `scanner.ssti`, `scanner.lfi`, `scanner.xxe`, `scanner.cors`, `scanner.headers`, `scanner.idor`, `scanner.smuggle`, `scanner.cache`, `scanner.auth`, `scanner.redirect`, `scanner.proto`, `scanner.nosqli`, `scanner.deserialize`, `scanner.websocket`, `waf.detector`, `waf.bypass`, `api.graphql`, `api.jwt`, `cloud.aws`, `cloud.secrets`, `misconfig.spring`, `misconfig.kubernetes`, `misconfig.database`, `misconfig.server`, `network.takeover`, `cms.wordpress`, `cms.wordpress.plugins`, `cms.wordpress.xmlrpc`, `ad.recon`, `ad.kerberos`, `ad.smb`

---

## Scanning Capabilities

TALISMAN provides 20+ vulnerability scanners covering the full OWASP Top 10 and modern attack surface:

| Category | Modules |
|---|---|
| Injection | XSS, SQLi, NoSQLi, CMDi, SSTI, LFI, XXE |
| Authentication | Auth bypass, MFA bypass, JWT attacks, OAuth audit |
| Access Control | IDOR/BOLA, CORS, Open Redirect, Mass Assignment |
| Business Logic | Price manipulation, Workflow bypass, Race conditions |
| Modern Attacks | Prototype pollution, WebSocket hijacking, Deserialization |
| Infra | Cache poisoning, Request smuggling, Log4Shell, CRLF injection |
| Cloud | AWS, GCP, Azure, Secrets scanning |
| AD | Kerberos roasting, SMB audit, ADCS, Password spray |
| API | GraphQL introspection, Swagger audit, OAuth/OIDC |

---

## Scope File Format

```yaml
include:
  - "*.example.com"
  - "example.com"
  - "192.168.1.0/24"

exclude:
  - "mail.example.com"
  - "*.prod.example.com"

restrictions:
  max_requests_per_second: 50
  avoid_writes: false
  avoid_destructive: true
  respect_robots_txt: false
```

---

## Rate Profiles

| Profile | Req/s | Delay | Concurrent | Use Case |
|---|---|---|---|---|
| `aggressive` | 200 | 0-50ms | 50 | Internal networks, low-risk targets |
| `normal` | 50 | 100-300ms | 20 | Standard bug bounty |
| `stealth` | 10 | 500ms-2s | 5 | WAF-protected, production |
| `passive` | 5 | 1s-5s | 2 | Highly sensitive or monitored |

---

## Environment Variables

```bash
export GITHUB_TOKEN=ghp_xxx          # GitHub dorking
export SHODAN_API_KEY=xxx            # Shodan enrichment
export DISCORD_WEBHOOK=https://...   # Notifications
export TALISMAN_AI_KEY=sk-ant-xxx    # AI features
```

---

## Docker Usage

```bash
# Build
docker-compose build

# Run a scan
docker run --rm -v $(pwd)/reports:/reports talisman autopilot -t example.com -s docker-session

# Interactive
docker run --rm -it -v $(pwd)/reports:/reports talisman bash
```

---

## Architecture

```
talisman/
  engine/           core: orchestrator, session, scope, rate limiter
  modules/
    recon/          subdomain, DNS, crawl, tech, OSINT
    scanner/        XSS, SQLi, NoSQLi, SSRF, CMDi, SSTI, LFI, XXE, ...
    websocket/      WebSocket hijacking and message injection
    deserialization/ Java, PHP, Python Pickle, Node.js unsafe deserialization
    nosqli/         MongoDB NoSQL injection
    fuzzer/         path fuzzer, param fuzzer
    api/            JWT, GraphQL, OAuth, Swagger
    cloud/          AWS, GCP, Azure, secrets
    waf/            detection, bypass, vendor modules
    cms/            WordPress deep audit
    misconfiguration/ Spring, K8s, databases, servers
    activedirectory/ LDAP, Kerberos, SMB, ADCS
    network/        takeover, SSL/TLS
  output/           HTML/Markdown/JSON report engine
  intelligence/     CVE correlation, scoring
  chains/           YAML workflow definitions
  utils/            HTTP client, payload engine, logger
```

---

## Legal

TALISMAN is designed for authorized security testing only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. The authors accept no liability for misuse. Always obtain proper written authorization before testing.

---

*Built for professionals, by professionals. TALISMAN v1.0.0*
