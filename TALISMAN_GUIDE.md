# 🗡️ TALISMAN — Complete User Guide
**Author: MR MARCUS TAYK** | v1.0.0 | Advanced Bug Bounty & Security Research Platform

> ⚠️ **AUTHORIZED USE ONLY** — Use exclusively on systems you own or have explicit written permission to test.

---

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Core Concepts](#2-core-concepts)
3. [Autopilot — One Command Full Scan](#3-autopilot)
4. [Reconnaissance](#4-reconnaissance)
5. [Vulnerability Scanning](#5-vulnerability-scanning)
6. [WAF Detection & Bypass](#6-waf-detection--bypass)
7. [WordPress Audit](#7-wordpress-audit)
8. [API Security](#8-api-security)
9. [Cloud Security](#9-cloud-security)
10. [Misconfiguration Scanners](#10-misconfiguration-scanners)
11. [Active Directory](#11-active-directory)
12. [Chain Orchestrator](#12-chain-orchestrator)
13. [Fuzzing](#13-fuzzing)
14. [Session Management](#14-session-management)
15. [Reports](#15-reports)
16. [Advanced Workflows](#16-advanced-workflows)
17. [Troubleshooting](#17-troubleshooting)
18. [Full Command Reference](#18-full-command-reference)

---

## 1. Installation & Setup

### Quick Install
```bash
# Clone the project
git clone https://github.com/yourhandle/talisman
cd talisman

# Create virtual environment (recommended)
python3.11 -m venv venv && source venv/bin/activate

# Install with all dependencies
pip install -e .

# First-time setup (creates ~/.talisman/ directories, checks tools)
talisman init
```

### Install Optional External Tools
TALISMAN works standalone but integrates with these for extra power:
```bash
# Go tools (ProjectDiscovery suite)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/owasp-amass/amass/v4/...@latest

# System tools
sudo apt install nmap masscan

# Active Directory modules (optional)
pip install ldap3 impacket
```

### Install Optional Python Extras
```bash
# AI-powered triage + report writing
pip install anthropic openai

# Cloud modules (AWS/GCP/Azure)
pip install boto3 google-cloud-storage azure-storage-blob

# Browser-based scanning (DOM XSS, screenshots)
pip install playwright && playwright install chromium

# PDF reports
pip install weasyprint
```

---

## 2. Core Concepts

### Sessions
Every scan stores findings in a named **session**. Sessions persist across runs — you can stop and resume.
```bash
talisman scan xss -t https://example.com -s bounty-q1   # All findings go to bounty-q1
talisman recon subdomain -t example.com -s bounty-q1    # Appends to same session
talisman session findings bounty-q1                     # View everything found
talisman report generate bounty-q1                      # Generate report
```

### Rate Profiles
Control how aggressive or stealthy your scans are:

| Profile | Speed | Concurrent | Use Case |
|---------|-------|------------|----------|
| `aggressive` | 200 req/s | 50 | Internal networks, dev targets |
| `normal` | 50 req/s | 20 | Standard bug bounty **[default]** |
| `stealth` | 10 req/s | 5 | WAF-protected, production |
| `passive` | 5 req/s | 2 | Highly monitored / sensitive |

```bash
talisman scan all -t https://example.com -p stealth
talisman scan all -t https://internal.corp.com -p aggressive
```

### Scope Files
Always define scope to avoid scanning out-of-bounds targets:
```yaml
# scope.yaml
include:
  - "*.example.com"
  - "example.com"
  - "192.168.1.0/24"
exclude:
  - "mail.example.com"
  - "*.prod.example.com"
restrictions:
  max_requests_per_second: 30
  avoid_destructive: true
```
```bash
talisman autopilot -t example.com --scope ./scope.yaml
```

### OAST (Out-of-Band Detection)
For blind vulnerabilities (SSRF, XXE, CMDi, Log4Shell) you need an OOB callback domain:
```bash
# Free: sign up at https://app.interactsh.com and get a domain
talisman scan ssrf -t https://example.com --oast xxxxxxxx.oastify.com
talisman scan cmdi -t https://example.com --oast xxxxxxxx.oastify.com
talisman scan log4shell -t https://example.com --oast xxxxxxxx.oastify.com

# Self-hosted interactsh
docker run -it projectdiscovery/interactsh-server -domain your-domain.com
```

### Proxy Integration
Route all traffic through Burp Suite for manual review:
```bash
talisman scan all -t https://example.com --proxy http://127.0.0.1:8080
talisman autopilot -t example.com --proxy http://127.0.0.1:8080 -s bounty
# All requests appear in Burp HTTP history
```

---

## 3. Autopilot

The fastest way to assess a target — runs everything automatically:

```bash
# Standard run (most common)
talisman autopilot -t example.com -s bounty-q1

# Full-power: proxy + OAST + stealth
talisman autopilot -t https://app.example.com -s bounty \
  --proxy http://127.0.0.1:8080 \
  --oast xxxxxxxx.oastify.com \
  --profile stealth

# With scope file (important for bug bounty programs)
talisman autopilot -t example.com -s bounty --scope ./scope.yaml

# Skip report auto-generation (generate manually later)
talisman autopilot -t example.com -s quick --no-report

# Aggressive scan of internal network
talisman autopilot -t 192.168.1.1 -s internal --profile aggressive

# Debug mode — see every request/error
talisman autopilot -t example.com -s debug --debug
```

**Autopilot workflow:**
1. Tech fingerprinting + WAF detection
2. Web crawling (links, forms, JS endpoints)
3. OSINT (emails, S3 buckets, GitHub dorks)
4. All vulnerability scanners in sequence
5. WordPress deep audit (if WordPress detected)
6. Secret scanning (API keys, tokens)
7. HTML + Markdown + JSON report generation

---

## 4. Reconnaissance

### Subdomain Enumeration
```bash
# Passive only (fast, no DNS noise)
talisman recon subdomain -t example.com -s bounty

# All sources + active brute force
talisman recon subdomain -t example.com -s bounty \
  --bruteforce \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  --threads 100

# Custom sources only
talisman recon subdomain -t example.com --sources crtsh,wayback

# Aggressive internal domain brute force
talisman recon subdomain -t corp.local --profile aggressive \
  --bruteforce --wordlist ./internal-words.txt
```

**Sources used:**
- `crtsh` — Certificate Transparency logs (crt.sh)
- `hackertarget` — HackerTarget API
- `wayback` — Wayback Machine CDX
- `permutation` — Smart permutations (dev-, api-, staging-, etc.)

### DNS Analysis
```bash
# Full DNS audit including zone transfer attempt
talisman recon dns -t example.com -s bounty

# Skip zone transfer
talisman recon dns -t example.com --no-zone-transfer
```
Checks: All record types, zone transfer (AXFR), SPF/DMARC/DKIM, subdomain takeover patterns.

### Technology Fingerprinting
```bash
talisman recon tech -t https://example.com -s bounty
```
Detects 35+ technologies: WordPress, Laravel, Django, Spring Boot, React, Nginx, Apache, IIS, Cloudflare, Akamai, AWS WAF, and more.

### Web Crawling
```bash
# Standard crawl
talisman recon crawl -t https://example.com -s bounty

# Deep crawl with JS parsing
talisman recon crawl -t https://example.com --depth 5 --max-pages 500

# Behind Burp proxy
talisman recon crawl -t https://example.com --proxy http://127.0.0.1:8080
```

### OSINT
```bash
# All OSINT checks
talisman recon osint -t example.com -s bounty

# With GitHub token (better rate limits + more results)
export GITHUB_TOKEN=ghp_yourtoken
talisman recon osint -t example.com -s bounty

# S3 only
talisman recon osint -t example.com --checks s3_buckets
```

### Port Scanning
```bash
talisman recon ports -t 192.168.1.1 -s internal
talisman recon ports -t 10.0.0.1 --ports 1-10000 --threads 200
talisman recon ports -t target.com --ports 80,443,8080,8443,3000,3306,5432
```

### Run All Recon
```bash
talisman recon all -t example.com -s bounty-q1
```

---

## 5. Vulnerability Scanning

### Individual Scanners

```bash
# XSS — context-aware, WAF bypass variants
talisman scan xss -t "https://example.com/search?q=FUZZ"
talisman scan xss -t https://example.com --waf-bypass    # Cloudflare/Akamai bypass payloads

# SQL Injection — error, boolean blind, time-based
talisman scan sqli -t "https://example.com/item?id=1"
talisman scan sqli -t https://example.com --waf-bypass

# SSRF — cloud metadata, internal IPs, protocols
talisman scan ssrf -t https://example.com --oast xxxxxxxx.oastify.com
talisman scan ssrf -t "https://example.com/fetch?url=FUZZ"

# Command Injection — Linux + Windows, OOB
talisman scan cmdi -t "https://example.com/ping?host=FUZZ" --oast oastify.com
talisman scan cmdi -t https://example.com --waf-bypass

# SSTI — Jinja2, Twig, Freemarker, Velocity
talisman scan ssti -t "https://example.com/greet?name=FUZZ"

# LFI / Path Traversal
talisman scan lfi -t "https://example.com/page?file=FUZZ"
talisman scan lfi -t https://example.com --waf-bypass

# XXE — file read, XInclude, OOB
talisman scan xxe -t https://example.com/upload --oast oastify.com
talisman scan xxe -t https://example.com/api/xml

# CORS misconfiguration — 9 bypass patterns
talisman scan cors -t https://api.example.com

# Security headers + CSP analysis
talisman scan headers -t https://example.com

# Web cache poisoning
talisman scan cache -t https://example.com

# IDOR / Broken Object Level Authorization
talisman scan idor -t "https://example.com/api/users/123"
talisman scan idor -t https://example.com/api

# HTTP Request Smuggling (CL.TE, TE.CL, TE.TE)
talisman scan smuggle -t https://example.com

# Open Redirect
talisman scan redirect -t "https://example.com/login?next=FUZZ"

# Prototype Pollution
talisman scan proto -t https://example.com/api

# Auth bypass + default credentials
talisman scan auth -t https://example.com
talisman scan auth -t https://admin.example.com

# Log4Shell / JNDI injection
talisman scan log4shell -t https://example.com --oast oastify.com

# Race condition / TOCTOU
talisman scan race -t https://example.com/redeem-coupon

# MFA bypass
talisman scan mfa -t https://example.com

# Business logic (price manipulation, mass assignment, workflow bypass)
talisman scan bizlogic -t https://example.com/checkout
```

### Run All Scanners
```bash
# Everything
talisman scan all -t https://example.com -s bounty

# With WAF bypass + OAST (most thorough)
talisman scan all -t https://example.com -s bounty \
  --waf-bypass --oast xxxxxxxx.oastify.com

# Stealth with Burp proxy
talisman scan all -t https://example.com -s bounty \
  --profile stealth --proxy http://127.0.0.1:8080

# Skip heavy modules
talisman scan all -t https://example.com -s bounty \
  --exclude smuggle,race,mfa
```

---

## 6. WAF Detection & Bypass

```bash
# Step 1: Detect WAF vendor and confidence
talisman waf detect -t https://example.com

# Step 2: Find real origin IP behind Cloudflare
talisman waf origin -t example.com
talisman waf origin -t example.com --shodan-key YOUR_KEY   # Better results

# Step 3: Generate vendor-specific bypass payloads
talisman waf bypass -t https://example.com --waf Cloudflare --type xss
talisman waf bypass -t https://example.com --waf Akamai --type sqli --param id
talisman waf bypass -t https://example.com --waf ModSecurity --type lfi
```

**Bypass techniques by vendor:**
- **Cloudflare**: SVG onload, animatetransform, mXSS, ontoggle, scientific notation SQLi
- **Akamai**: CSS-based XSS, SVG foreignObject, MathML, Unicode homoglyphs
- **ModSecurity**: Vertical tab whitespace, form feed, IFS substitution, comment injection
- **AWS WAF**: JSON body testing, header injection, double encoding

**Finding origin behind Cloudflare:**
- Certificate Transparency logs (historical IPs)
- MX record correlation (mail servers often unproxied)  
- Shodan indexed IPs before Cloudflare
- Favicon hash fingerprinting
- Subdomain enumeration (dev., direct., origin. often bypass CDN)

---

## 7. WordPress Audit

```bash
# Full audit (recommended)
talisman cms wordpress -t https://wordpress-site.com -s bounty

# With OAST for XML-RPC pingback SSRF
talisman cms wordpress -t https://wp-site.com -s bounty --oast oastify.com

# Through Burp
talisman cms wordpress -t https://wp-site.com --proxy http://127.0.0.1:8080

# Use the dedicated WordPress chain
talisman chain run wordpress_full -t https://wp-site.com -s bounty
```

**What gets audited:**
- **Version detection** (6 methods) + CVE correlation (8 critical CVEs)
- **25 sensitive paths**: /wp-config.php, /.git, /debug.log, /phpinfo.php, /backup.zip, etc.
- **User enumeration** (4 methods): author redirect, REST API, RSS feed, sitemap
- **Plugin audit** (15 known-vulnerable): contact-form-7, elementor, wp-file-manager, woocommerce-payments, etc.
- **XML-RPC**: system.multicall brute amplification, pingback SSRF
- **REST API**: unauthenticated access, user data leakage

---

## 8. API Security

### GraphQL
```bash
# Auto-discovers endpoint
talisman api graphql -t https://api.example.com -s bounty

# With auth token
talisman api graphql -t https://api.example.com \
  --auth "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Tests: introspection enabled, injection, alias batching (rate limit bypass),
# depth limits, unauthorized mutations, field suggestion bypass
```

### JWT Attacks
```bash
# Analyze and attack a JWT
talisman api jwt -t https://api.example.com \
  --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxx.yyy

# Test forged tokens against protected endpoint
talisman api jwt -t https://api.example.com \
  --token eyJhbGci... \
  --endpoint https://api.example.com/admin/dashboard

# Skip secret brute force
talisman api jwt -t https://api.example.com --token eyJ... --no-crack
```

**JWT attacks:**
1. Algorithm confusion (RS256 → HS256 using public key as HMAC secret)
2. `alg: none` attack (unsigned tokens) — 5 case variants
3. `kid` header injection (path traversal + SQL injection)
4. Weak HMAC secret brute force (50+ common secrets)

### OpenAPI/Swagger
```bash
# Auto-discovers spec
talisman api swagger -t https://api.example.com -s bounty

# With auth + specific spec URL
talisman api swagger -t https://api.example.com \
  --spec /api/v3/openapi.json \
  --auth "Bearer TOKEN"
```

### OAuth 2.0 / OIDC
```bash
talisman api oauth -t https://auth.example.com -s bounty
talisman api oauth -t https://example.com --client-id myapp
```
Tests: implicit flow, PKCE enforcement, redirect_uri bypass (10 variants), state CSRF.

---

## 9. Cloud Security

### AWS
```bash
# S3 bucket enumeration + CloudFront bypass
talisman cloud aws -t example.com -s bounty

# S3 only (faster)
talisman cloud aws -t example.com --s3 --no-cf
```

Checks 20+ S3 naming patterns: `{domain}`, `{domain}-assets`, `{domain}-backup`, `{domain}-dev`, etc.
Detects: publicly listable buckets, CloudFront origin bypass.

### Secret Scanning
```bash
# Scan all JS files, HTML, config files
talisman cloud secrets -t https://example.com -s bounty
```

Detects 30+ secret types: AWS keys, GitHub PATs, Stripe keys, OpenAI, Slack tokens, database URLs, private keys, `.env` files.

---

## 10. Misconfiguration Scanners

```bash
# Spring Boot Actuator (22 endpoints)
talisman misconfig spring -t https://api.example.com -s bounty
# Finds: /actuator/env (creds), /heapdump, /sessions, /jolokia, /shutdown

# Kubernetes
talisman misconfig kubernetes -t k8s.example.com -s bounty
talisman misconfig kubernetes -t 10.0.0.1 --api-port 8080

# Exposed databases (15 types)
talisman misconfig database -t 192.168.1.1 -s internal
talisman misconfig database -t target.com --checks mongodb,redis,elasticsearch

# Server (Nginx/Apache/IIS, CRLF, HTTP methods, sensitive files)
talisman misconfig server -t https://example.com -s bounty

# Nginx-specific (alias traversal, off-by-slash)
talisman misconfig nginx -t https://example.com -s bounty
```

---

## 11. Active Directory

> Requires: `pip install ldap3 impacket`

### Enumeration
```bash
# Anonymous LDAP
talisman ad recon -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10

# Authenticated (standard user — finds Kerberoastable accounts, admins, etc.)
talisman ad recon -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 \
  --user jsmith --password Password1
```

### Kerberoasting + AS-REP Roasting
```bash
talisman ad kerberos -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 \
  --user jsmith --password Password1

# Crack captured hashes
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

### SMB Audit
```bash
# Null session (anonymous)
talisman ad smb -t 192.168.1.10 -s internal

# Authenticated (finds sensitive files, GPP credentials)
talisman ad smb -t 192.168.1.10 --user jsmith --password Password1 --domain CORP
```
GPP credentials (MS14-025) are automatically decrypted using the published AES key.

### Password Spray
```bash
# Lockout-safe spray (never exceeds threshold-1 attempts)
talisman ad spray -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 \
  --users users.txt --passwords "Password1,Welcome1,Summer2024!" -s internal

# Custom delay (default 30 min between rounds)
talisman ad spray ... --delay-minutes 10 --lockout-threshold 5
```

### AD Certificate Services (ESC1-ESC8)
```bash
talisman ad adcs -t 192.168.1.10 --domain corp.local --dc-ip 192.168.1.10 \
  --user jsmith --password Password1 -s internal
```

### Full AD Chain
```bash
talisman chain run windows_ad -t 192.168.1.10 \
  --domain corp.local --dc-ip 192.168.1.10 \
  --user jsmith --password Password1 \
  -s internal --profile stealth
```

---

## 12. Chain Orchestrator

Chains are YAML workflows that run multiple modules in sequence/parallel.

### Built-in Chains
```bash
talisman chain list    # See all available chains

# Full recon (subdomain → DNS → tech → crawl → OSINT → takeover)
talisman chain run full_recon -t example.com -s bounty-q1

# All web vuln scanners
talisman chain run web_vuln_scan -t https://example.com -s bounty \
  --profile stealth --proxy http://127.0.0.1:8080

# WordPress full audit
talisman chain run wordpress_full -t https://wp-site.com -s bounty --oast oastify.com

# API audit (GraphQL + JWT + Swagger)
talisman chain run api_audit -t https://api.example.com -s bounty

# Cloud assessment (AWS + secrets + CloudFront)
talisman chain run cloud_breach -t example.com -s bounty

# WAF bypass workflow
talisman chain run waf_bypass_probe -t https://example.com -s bounty

# Preview without running
talisman chain run full_recon -t example.com --dry-run
```

### Custom Chains (YAML)
```yaml
# my_chain.yaml
name: my_custom_chain
description: "My specific assessment workflow"
rate_profile: stealth

steps:
  - id: tech
    module: recon.tech
    args:
      waf_detect: true

  - id: xss_scan
    module: scanner.xss
    depends_on: [tech]
    args:
      waf_bypass: true

  - id: sqli_scan
    module: scanner.sqli
    depends_on: [tech]
    parallel: true        # Runs at same time as other parallel steps

  - id: secrets
    module: cloud.secrets
    parallel: true
    on_error: continue    # Don't stop chain if this fails
```
```bash
talisman chain run ./my_chain.yaml -t https://example.com -s bounty
```

---

## 13. Fuzzing

### Directory/File Brute Force
```bash
# Built-in wordlist (150+ critical paths)
talisman fuzz paths -t https://example.com -s bounty

# With SecLists
talisman fuzz paths -t https://example.com \
  --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  --extensions php,asp,aspx,bak,old,sql,log,config \
  --threads 100

# Aggressive
talisman fuzz paths -t https://example.com --threads 200 -p aggressive
```

Built-in paths cover: admin panels, API endpoints, config files, `.git`, backup files, debug pages, actuator, WEB-INF, `.env`, phpinfo.

### Parameter Discovery
```bash
talisman fuzz params -t https://example.com/api/users -s bounty
talisman fuzz params -t https://example.com --methods GET,POST,PUT
```

---

## 14. Session Management

```bash
# List all sessions
talisman session list

# Summary stats
talisman session summary bounty-q1

# View findings (table format)
talisman session findings bounty-q1

# Filter by severity
talisman session findings bounty-q1 --severity critical,high

# JSON output (for scripting/piping)
talisman session findings bounty-q1 --format json
talisman session findings bounty-q1 --format json | jq '.[] | .title'
talisman session findings bounty-q1 --format json | jq '.[] | select(.severity=="critical")'

# Add notes
talisman session note bounty-q1 "Login uses JWT HS256 — test alg confusion next"
talisman session note bounty-q1 "Admin panel at /console — check default creds"

# Delete a session
talisman session delete bounty-q1 --confirm
```

---

## 15. Reports

```bash
# Generate all formats (HTML + Markdown + JSON)
talisman report generate bounty-q1

# HTML only, critical + high findings
talisman report generate bounty-q1 --format html --severity critical,high

# Custom output directory
talisman report generate bounty-q1 --output ~/Desktop/reports/

# Generate and open in browser immediately
talisman report generate bounty-q1 --format html --open

# Just JSON for processing
talisman report generate bounty-q1 --format json
```

**Report formats:**
- **HTML** — Self-contained dark-theme report with severity chart, syntax-highlighted HTTP requests, full finding details
- **Markdown** — HackerOne/Bugcrowd-ready format with CVSS scores, reproduction steps, PoC, remediation
- **JSON** — Machine-readable full data dump for custom tooling

---

## 16. Advanced Workflows

### Complete Bug Bounty Assessment
```bash
# Phase 1: Full recon
talisman chain run full_recon -t example.com -s bounty-q1

# Phase 2: Check recon results
talisman session findings bounty-q1 --severity high,critical

# Phase 3: Targeted vuln scan on discovered targets
talisman scan all -t https://api.example.com -s bounty-q1 \
  --oast xxxxxxxx.oastify.com --proxy http://127.0.0.1:8080

# Phase 4: WordPress audit (if found)
talisman chain run wordpress_full -t https://wp.example.com -s bounty-q1

# Phase 5: Generate report
talisman report generate bounty-q1 --format html,markdown --severity critical,high
```

### Internal Network Pentest
```bash
# Network discovery + port scan
talisman recon ports -t 10.0.0.0/24 --ports 1-65535 -s internal

# Web app scanning on discovered services
talisman scan all -t http://10.0.0.5:8080 -s internal -p aggressive

# Database exposure check
talisman misconfig database -t 10.0.0.10 -s internal

# Kubernetes cluster
talisman misconfig kubernetes -t 10.0.0.20 -s internal

# Active Directory
talisman chain run windows_ad -t 10.0.0.1 --domain corp.local --dc-ip 10.0.0.1 \
  --user jsmith --password Password1 -s internal -p stealth
```

### Cloudflare-Protected Target
```bash
# Step 1: Find origin IP
talisman waf origin -t example.com --shodan-key YOUR_KEY

# Step 2: Scan origin directly (bypasses WAF)
talisman scan all -t http://ORIGIN_IP -s bounty \
  --proxy http://127.0.0.1:8080  # Add Host: example.com in Burp match/replace

# Step 3: Test through Cloudflare with bypass payloads
talisman waf bypass -t https://example.com --waf Cloudflare --type xss
talisman scan xss -t https://example.com --waf-bypass -s bounty
```

### API-First Target
```bash
# Discover everything
talisman api swagger -t https://api.example.com -s api-bounty

# Test GraphQL
talisman api graphql -t https://api.example.com -s api-bounty \
  --auth "Bearer $(cat ./token.txt)"

# JWT attacks
talisman api jwt -t https://api.example.com -s api-bounty \
  --token $(cat ./jwt.txt) \
  --endpoint https://api.example.com/admin

# Full API chain
talisman chain run api_audit -t https://api.example.com -s api-bounty
```

---

## 17. Troubleshooting

### `OperationalError: near "references": syntax error`
Fixed in the current version. This was caused by `references` being a reserved SQLite keyword. Upgrade to the latest version:
```bash
pip install -e . --force-reinstall
```

### `No such option: --profile`
Use `-p` instead of `--profile` for short form, or `--profile` (two dashes):
```bash
talisman autopilot -t example.com -p stealth   # ✅ short form
talisman autopilot -t example.com --profile stealth  # ✅ long form
```

### SSL Certificate Errors
```bash
# TALISMAN disables SSL verification by default for security testing
# If you need to trust a custom CA:
export SSL_CERT_FILE=/path/to/ca-bundle.crt
```

### Import Errors on Optional Modules
AD modules require: `pip install ldap3 impacket`
Cloud modules require: `pip install boto3 google-cloud-storage azure-storage-blob`
AI features require: `pip install anthropic openai`

### Slow Performance
```bash
# Use aggressive profile for internal/dev targets
talisman scan all -t https://example.com -p aggressive

# Reduce threads if hitting rate limits
talisman recon subdomain -t example.com --threads 20

# Skip heavy modules
talisman scan all -t https://example.com --exclude smuggle,race
```

### No Findings on WAF-Protected Target
```bash
# Step 1: Find the real origin IP
talisman waf origin -t example.com

# Step 2: Enable WAF bypass mode
talisman scan all -t https://example.com --waf-bypass

# Step 3: Use stealth profile
talisman scan all -t https://example.com -p stealth

# Step 4: Test through Burp manually for confirmation
talisman scan all -t https://example.com --proxy http://127.0.0.1:8080
```

---

## 18. Full Command Reference

```
talisman init                              First-time setup
talisman version                           Show version + author

talisman autopilot [OPTIONS]               Full automated assessment
  -t, --target TEXT    (required)
  -s, --session TEXT   [default: default]
  -p, --profile TEXT   [aggressive|normal|stealth|passive]
  --proxy TEXT
  --scope PATH
  --oast TEXT
  --report / --no-report
  --wordpress / --no-wordpress
  --secrets / --no-secrets
  --debug

talisman recon subdomain -t DOMAIN [OPTIONS]
talisman recon dns -t DOMAIN [OPTIONS]
talisman recon tech -t URL [OPTIONS]
talisman recon crawl -t URL [OPTIONS]
talisman recon osint -t DOMAIN [OPTIONS]
talisman recon ports -t HOST [OPTIONS]
talisman recon all -t DOMAIN [OPTIONS]

talisman scan xss -t URL [OPTIONS]
talisman scan sqli -t URL [OPTIONS]
talisman scan ssrf -t URL [--oast DOMAIN] [OPTIONS]
talisman scan cmdi -t URL [--oast DOMAIN] [OPTIONS]
talisman scan ssti -t URL [OPTIONS]
talisman scan lfi -t URL [OPTIONS]
talisman scan xxe -t URL [--oast DOMAIN] [OPTIONS]
talisman scan cors -t URL [OPTIONS]
talisman scan headers -t URL [OPTIONS]
talisman scan cache -t URL [OPTIONS]
talisman scan idor -t URL [OPTIONS]
talisman scan smuggle -t URL [OPTIONS]
talisman scan redirect -t URL [OPTIONS]
talisman scan proto -t URL [OPTIONS]
talisman scan auth -t URL [OPTIONS]
talisman scan log4shell -t URL --oast DOMAIN [OPTIONS]
talisman scan race -t URL [OPTIONS]
talisman scan mfa -t URL [OPTIONS]
talisman scan bizlogic -t URL [OPTIONS]
talisman scan all -t URL [--exclude NAMES] [OPTIONS]

talisman waf detect -t URL [OPTIONS]
talisman waf origin -t DOMAIN [--shodan-key KEY]
talisman waf bypass -t URL --waf VENDOR --type VULNTYPE [OPTIONS]

talisman fuzz paths -t URL [--wordlist PATH] [OPTIONS]
talisman fuzz params -t URL [OPTIONS]

talisman api graphql -t URL [--auth HEADER] [OPTIONS]
talisman api jwt -t URL --token JWT [--endpoint URL] [OPTIONS]
talisman api swagger -t URL [--spec URL] [OPTIONS]
talisman api oauth -t URL [--client-id ID] [OPTIONS]

talisman cloud aws -t DOMAIN [OPTIONS]
talisman cloud secrets -t URL [OPTIONS]

talisman misconfig spring -t URL [OPTIONS]
talisman misconfig kubernetes -t HOST [OPTIONS]
talisman misconfig database -t HOST [--checks LIST] [OPTIONS]
talisman misconfig server -t URL [OPTIONS]
talisman misconfig nginx -t URL [OPTIONS]

talisman cms wordpress -t URL [--oast DOMAIN] [OPTIONS]

talisman ad recon -t HOST --domain DOMAIN --dc-ip IP [OPTIONS]
talisman ad kerberos -t HOST --domain DOMAIN --dc-ip IP [OPTIONS]
talisman ad smb -t HOST [--user USER] [--password PASS] [OPTIONS]
talisman ad spray -t HOST --domain DOMAIN --dc-ip IP --users FILE [OPTIONS]
talisman ad adcs -t HOST --domain DOMAIN --dc-ip IP [OPTIONS]

talisman chain list
talisman chain show CHAIN_NAME
talisman chain run CHAIN_NAME -t TARGET [OPTIONS]

talisman session list
talisman session summary SESSION_NAME
talisman session findings SESSION_NAME [--severity LIST] [--format table|json]
talisman session note SESSION_NAME "NOTE TEXT"
talisman session delete SESSION_NAME --confirm

talisman report generate SESSION_NAME [--format html,markdown,json] [OPTIONS]

talisman takeover -t DOMAIN [--subdomains FILE] [OPTIONS]

talisman intel cve TECHNOLOGY [--version VER]
talisman intel score VULN_TYPE
```

---

*TALISMAN v1.0.0 — Built by MR MARCUS TAYK*  
*For authorized security testing only.*
